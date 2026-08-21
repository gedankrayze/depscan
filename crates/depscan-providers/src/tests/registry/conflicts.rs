use super::*;

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
async fn conflicting_fresh_winner_is_adopted_without_a_second_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metadata"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"revision": 2}))
                .set_delay(std::time::Duration::from_millis(500)),
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
        .put("registry", "conflict-budget", &json!({"revision": 1}), None)
        .unwrap();
    age_cache_entry(&cache, "registry", "conflict-budget", Duration::hours(7));
    let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());

    // While the single fetch is in flight, a concurrent writer publishes a fresh winner. The
    // resulting commit conflict must be resolved locally by adopting the winner, never by a
    // second network request.
    let url = format!("{}/metadata", server.uri());
    let lookup = client.metadata("conflict-budget", &url, HeaderMap::new());
    let winner = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        cache
            .put("registry", "conflict-budget", &json!({"revision": 3}), None)
            .unwrap();
    };
    let (value, ()) = tokio::join!(lookup, winner);

    assert_eq!(value.unwrap(), json!({"revision": 3}));
    server.verify().await;
}
