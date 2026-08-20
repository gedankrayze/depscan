use super::*;

#[tokio::test]
async fn stale_registry_metadata_revalidates_with_etag_and_refreshes_on_304() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metadata"))
        .and(header("if-none-match", "\"revision-1\""))
        .respond_with(ResponseTemplate::new(304))
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    cache
        .put(
            "registry",
            "etag-304",
            &json!({"revision": 1}),
            Some("\"revision-1\"".to_owned()),
        )
        .unwrap();
    age_cache_entry(&cache, "registry", "etag-304", Duration::hours(7));
    let before = read_cache_entry(&cache, "registry", "etag-304").stored_at;
    let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());

    let value = client
        .metadata(
            "etag-304",
            &format!("{}/metadata", server.uri()),
            HeaderMap::new(),
        )
        .await
        .unwrap();

    assert_eq!(value, json!({"revision": 1}));
    let refreshed = read_cache_entry(&cache, "registry", "etag-304");
    assert!(refreshed.stored_at > before);
    assert_eq!(refreshed.etag.as_deref(), Some("\"revision-1\""));
    assert_eq!(refreshed.value, value);
    server.verify().await;
}

#[tokio::test]
async fn future_registry_metadata_revalidates_before_reuse() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metadata"))
        .and(header("if-none-match", "\"revision-future\""))
        .respond_with(ResponseTemplate::new(304))
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    cache
        .put(
            "registry",
            "future-etag",
            &json!({"revision": 1}),
            Some("\"revision-future\"".to_owned()),
        )
        .unwrap();
    let future = Utc::now() + Duration::days(1);
    set_cache_entry_timestamp(&cache, "registry", "future-etag", future);
    let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());

    let value = client
        .metadata(
            "future-etag",
            &format!("{}/metadata", server.uri()),
            HeaderMap::new(),
        )
        .await
        .unwrap();

    assert_eq!(value, json!({"revision": 1}));
    let refreshed = read_cache_entry(&cache, "registry", "future-etag");
    assert!(refreshed.stored_at < future);
    assert!(refreshed.stored_at <= Utc::now());
    assert_eq!(refreshed.etag.as_deref(), Some("\"revision-future\""));
    server.verify().await;
}

#[tokio::test]
async fn late_registry_304_cannot_overwrite_a_concurrent_changed_response() {
    let server = MockServer::start().await;
    let slow_received = Arc::new(tokio::sync::Notify::new());
    let slow_responder_received = slow_received.clone();
    Mock::given(method("GET"))
        .and(path("/slow-not-modified"))
        .and(header("if-none-match", "\"revision-1\""))
        .respond_with(move |_: &wiremock::Request| {
            slow_responder_received.notify_one();
            ResponseTemplate::new(304).set_delay(std::time::Duration::from_millis(200))
        })
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/fast-modified"))
        .and(header("if-none-match", "\"revision-1\""))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"revision-2\"")
                .set_body_json(json!({"revision": 2})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    cache
        .put(
            "registry",
            "revalidation-race",
            &json!({"revision": 1}),
            Some("\"revision-1\"".to_owned()),
        )
        .unwrap();
    age_cache_entry(&cache, "registry", "revalidation-race", Duration::hours(7));
    let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());
    let slow_client = client.clone();
    let slow_url = format!("{}/slow-not-modified", server.uri());
    let slow_started = slow_received.notified();
    let slow = tokio::spawn(async move {
        slow_client
            .metadata("revalidation-race", &slow_url, HeaderMap::new())
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), slow_started)
        .await
        .expect("slow revalidation request was not received");

    let fast = client
        .metadata(
            "revalidation-race",
            &format!("{}/fast-modified", server.uri()),
            HeaderMap::new(),
        )
        .await
        .unwrap();
    let slow = slow.await.unwrap().unwrap();

    assert_eq!(fast, json!({"revision": 2}));
    assert_eq!(slow, fast);
    let cached = read_cache_entry(&cache, "registry", "revalidation-race");
    assert_eq!(cached.value, fast);
    assert_eq!(cached.etag.as_deref(), Some("\"revision-2\""));
    server.verify().await;
}

#[tokio::test]
async fn cache_bypass_still_prevents_out_of_order_publication() {
    let server = MockServer::start().await;
    let slow_received = Arc::new(tokio::sync::Notify::new());
    let slow_responder_received = slow_received.clone();
    let slow_calls = Arc::new(AtomicUsize::new(0));
    let responder_calls = slow_calls.clone();
    Mock::given(method("GET"))
        .and(path("/slow-refresh"))
        .respond_with(move |_: &wiremock::Request| {
            if responder_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                slow_responder_received.notify_one();
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"revision-1\"")
                    .set_body_json(json!({"revision": 1}))
                    .set_delay(std::time::Duration::from_millis(200))
            } else {
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"revision-2\"")
                    .set_body_json(json!({"revision": 2}))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/fast-refresh"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"revision-2\"")
                .set_body_json(json!({"revision": 2})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy {
            read: false,
            max_age: None,
        },
    };
    cache
        .put(
            "registry",
            "bypass-race",
            &json!({"revision": 0}),
            Some("\"revision-0\"".to_owned()),
        )
        .unwrap();
    let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());
    let slow_client = client.clone();
    let slow_url = format!("{}/slow-refresh", server.uri());
    let slow_started = slow_received.notified();
    let slow = tokio::spawn(async move {
        slow_client
            .metadata("bypass-race", &slow_url, HeaderMap::new())
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), slow_started)
        .await
        .expect("slow bypass request was not received");

    let fast = client
        .metadata(
            "bypass-race",
            &format!("{}/fast-refresh", server.uri()),
            HeaderMap::new(),
        )
        .await
        .unwrap();
    let slow = slow.await.unwrap().unwrap();

    assert_eq!(fast, json!({"revision": 2}));
    assert_eq!(slow, fast);
    assert_eq!(slow_calls.load(Ordering::SeqCst), 2);
    let cached = read_cache_entry(&cache, "registry", "bypass-race");
    assert_eq!(cached.value, fast);
    assert_eq!(cached.etag.as_deref(), Some("\"revision-2\""));
    for request in server.received_requests().await.unwrap() {
        assert!(request.headers.get("if-none-match").is_none());
    }
    server.verify().await;
}

#[tokio::test]
async fn changed_registry_etag_replaces_the_cached_body_atomically() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metadata"))
        .and(header("if-none-match", "\"revision-1\""))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"revision-2\"")
                .set_body_json(json!({"revision": 2})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    cache
        .put(
            "registry",
            "etag-changed",
            &json!({"revision": 1}),
            Some("\"revision-1\"".to_owned()),
        )
        .unwrap();
    age_cache_entry(&cache, "registry", "etag-changed", Duration::hours(7));
    let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());

    let value = client
        .metadata(
            "etag-changed",
            &format!("{}/metadata", server.uri()),
            HeaderMap::new(),
        )
        .await
        .unwrap();

    assert_eq!(value, json!({"revision": 2}));
    let cached = read_cache_entry(&cache, "registry", "etag-changed");
    assert_eq!(cached.value, value);
    assert_eq!(cached.etag.as_deref(), Some("\"revision-2\""));
    server.verify().await;
}

#[tokio::test]
async fn missing_registry_etag_forces_an_unconditional_refresh() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"revision": 2})))
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    cache
        .put("registry", "missing-etag", &json!({"revision": 1}), None)
        .unwrap();
    age_cache_entry(&cache, "registry", "missing-etag", Duration::hours(7));
    let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());

    let value = client
        .metadata(
            "missing-etag",
            &format!("{}/metadata", server.uri()),
            HeaderMap::new(),
        )
        .await
        .unwrap();

    assert_eq!(value, json!({"revision": 2}));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].headers.get("if-none-match").is_none());
    let cached = read_cache_entry(&cache, "registry", "missing-etag");
    assert_eq!(cached.value, value);
    assert!(cached.etag.is_none());
    server.verify().await;
}

#[tokio::test]
async fn failed_registry_revalidation_preserves_the_stale_cache_entry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metadata"))
        .and(header("if-none-match", "\"revision-1\""))
        .respond_with(ResponseTemplate::new(400))
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    cache
        .put(
            "registry",
            "failed-revalidation",
            &json!({"revision": 1}),
            Some("\"revision-1\"".to_owned()),
        )
        .unwrap();
    age_cache_entry(
        &cache,
        "registry",
        "failed-revalidation",
        Duration::hours(7),
    );
    let before = read_cache_entry(&cache, "registry", "failed-revalidation");
    let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());

    let error = client
        .metadata(
            "failed-revalidation",
            &format!("{}/metadata", server.uri()),
            HeaderMap::new(),
        )
        .await
        .unwrap_err();

    assert!(error.to_string().contains("HTTP 400"));
    let after = read_cache_entry(&cache, "registry", "failed-revalidation");
    assert_eq!(after.stored_at, before.stored_at);
    assert_eq!(after.etag, before.etag);
    assert_eq!(after.value, before.value);
    server.verify().await;
}
