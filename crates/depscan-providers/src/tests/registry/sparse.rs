use super::*;

#[tokio::test]
async fn accepts_complete_sparse_ndjson_and_reuses_the_validated_cache() {
    let server = MockServer::start().await;
    let body = concat!(
        "\n",
        "{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":true}\r\n",
        "\n",
        "{\"name\":\"fixture\",\"vers\":\"2.0.0\",\"yanked\":false}\n",
    );
    Mock::given(method("GET"))
        .and(path("/fi/xt/fixture"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/plain"))
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    let cache_file = cache.filename("registry", "crates:fixture");
    let client =
        RegistryClient::with_crates_index_base_url(HttpClient::new().unwrap(), cache, server.uri());
    let package = crates_package("fixture");

    for _ in 0..2 {
        let latest = client.latest(&package).await.unwrap();
        assert_eq!(latest.latest.latest_stable, "2.0.0");
        assert!(latest.latest.yanked);
    }

    let stored: Value = serde_json::from_str(&fs::read_to_string(&cache_file).unwrap()).unwrap();
    assert_eq!(
        stored
            .pointer("/value/schema_version")
            .and_then(Value::as_u64),
        Some(u64::from(CRATES_IO_INDEX_CACHE_SCHEMA_VERSION))
    );
    assert_eq!(
        stored
            .pointer("/value/entries")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    server.verify().await;
}

#[tokio::test]
async fn stale_sparse_index_revalidates_with_etag_and_refreshes_on_304() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fi/xt/fixture"))
        .and(header("if-none-match", "\"sparse-1\""))
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
            "crates:fixture",
            &json!({
                "schema_version": CRATES_IO_INDEX_CACHE_SCHEMA_VERSION,
                "entries": [
                    {"name": "fixture", "vers": "1.0.0", "yanked": true},
                    {"name": "fixture", "vers": "2.0.0", "yanked": false}
                ]
            }),
            Some("\"sparse-1\"".to_owned()),
        )
        .unwrap();
    age_cache_entry(&cache, "registry", "crates:fixture", Duration::hours(7));
    let before = read_cache_entry(&cache, "registry", "crates:fixture").stored_at;
    let client = RegistryClient::with_crates_index_base_url(
        HttpClient::new().unwrap(),
        cache.clone(),
        server.uri(),
    );

    let latest = client.latest(&crates_package("fixture")).await.unwrap();

    assert_eq!(latest.latest.latest_stable, "2.0.0");
    assert!(latest.latest.yanked);
    let refreshed = read_cache_entry(&cache, "registry", "crates:fixture");
    assert!(refreshed.stored_at > before);
    assert_eq!(refreshed.etag.as_deref(), Some("\"sparse-1\""));
    assert_eq!(
        refreshed
            .value
            .pointer("/entries/1/vers")
            .and_then(Value::as_str),
        Some("2.0.0")
    );
    server.verify().await;
}

#[tokio::test]
async fn future_sparse_index_revalidates_before_reuse() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/fi/xt/fixture"))
        .and(header("if-none-match", "\"sparse-future\""))
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
            "crates:fixture",
            &json!({
                "schema_version": CRATES_IO_INDEX_CACHE_SCHEMA_VERSION,
                "entries": [
                    {"name": "fixture", "vers": "1.0.0", "yanked": false},
                    {"name": "fixture", "vers": "2.0.0", "yanked": false}
                ]
            }),
            Some("\"sparse-future\"".to_owned()),
        )
        .unwrap();
    let future = Utc::now() + Duration::days(1);
    set_cache_entry_timestamp(&cache, "registry", "crates:fixture", future);
    let client = RegistryClient::with_crates_index_base_url(
        HttpClient::new().unwrap(),
        cache.clone(),
        server.uri(),
    );

    let latest = client.latest(&crates_package("fixture")).await.unwrap();

    assert_eq!(latest.latest.latest_stable, "2.0.0");
    let refreshed = read_cache_entry(&cache, "registry", "crates:fixture");
    assert!(refreshed.stored_at < future);
    assert!(refreshed.stored_at <= Utc::now());
    assert_eq!(refreshed.etag.as_deref(), Some("\"sparse-future\""));
    server.verify().await;
}

#[tokio::test]
async fn late_sparse_304_cannot_overwrite_a_concurrent_changed_index() {
    let server = MockServer::start().await;
    let slow_received = Arc::new(tokio::sync::Notify::new());
    let slow_responder_received = slow_received.clone();
    Mock::given(method("GET"))
        .and(path("/slow/fi/xt/fixture"))
        .and(header("if-none-match", "\"sparse-1\""))
        .respond_with(move |_: &wiremock::Request| {
            slow_responder_received.notify_one();
            ResponseTemplate::new(304).set_delay(std::time::Duration::from_millis(200))
        })
        .expect(1)
        .mount(&server)
        .await;
    let changed_body = concat!(
        "{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
        "{\"name\":\"fixture\",\"vers\":\"2.0.0\",\"yanked\":false}\n",
    );
    Mock::given(method("GET"))
        .and(path("/fast/fi/xt/fixture"))
        .and(header("if-none-match", "\"sparse-1\""))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"sparse-2\"")
                .set_body_raw(changed_body, "text/plain"),
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
            "crates:fixture",
            &json!({
                "schema_version": CRATES_IO_INDEX_CACHE_SCHEMA_VERSION,
                "entries": [
                    {"name": "fixture", "vers": "1.0.0", "yanked": false}
                ]
            }),
            Some("\"sparse-1\"".to_owned()),
        )
        .unwrap();
    age_cache_entry(&cache, "registry", "crates:fixture", Duration::hours(7));
    let slow_client = RegistryClient::with_crates_index_base_url(
        HttpClient::new().unwrap(),
        cache.clone(),
        format!("{}/slow", server.uri()),
    );
    let fast_client = RegistryClient::with_crates_index_base_url(
        HttpClient::new().unwrap(),
        cache.clone(),
        format!("{}/fast", server.uri()),
    );
    let package = crates_package("fixture");
    let slow_package = package.clone();
    let slow_started = slow_received.notified();
    let slow = tokio::spawn(async move { slow_client.latest(&slow_package).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), slow_started)
        .await
        .expect("slow sparse-index request was not received");

    let fast = fast_client.latest(&package).await.unwrap();
    let slow = slow.await.unwrap().unwrap();

    assert_eq!(fast.latest.latest_stable, "2.0.0");
    assert_eq!(slow.latest.latest_stable, "2.0.0");
    let cached = read_cache_entry(&cache, "registry", "crates:fixture");
    assert_eq!(cached.etag.as_deref(), Some("\"sparse-2\""));
    assert_eq!(
        cached
            .value
            .pointer("/entries/1/vers")
            .and_then(Value::as_str),
        Some("2.0.0")
    );
    server.verify().await;
}
