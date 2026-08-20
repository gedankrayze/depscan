use super::*;

#[test]
fn retry_status_classification_is_exact() {
    for code in 100..=599 {
        let status = StatusCode::from_u16(code).unwrap();
        assert_eq!(
            retryable_status(status),
            code == 429 || (500..=599).contains(&code),
            "unexpected retry classification for HTTP {code}"
        );
    }
}

#[test]
fn production_network_budgets_match_the_documented_contract() {
    let http = HttpClient::new().unwrap();
    assert_eq!(http.request_timeout, StdDuration::from_secs(10));
    assert_eq!(http.retry_settings.attempts, 4);
    assert_eq!(
        http.retry_settings.backoff_base,
        StdDuration::from_millis(200)
    );
    assert_eq!(http.retry_settings.max_delay, StdDuration::from_secs(30));

    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    let osv = OsvClient::new(http.clone(), cache.clone());
    assert_eq!(osv.concurrency.available_permits(), 16);
    let registries = RegistryClient::new(http, cache);
    assert_eq!(registries.limits[&Ecosystem::Npm].available_permits(), 16);
    assert_eq!(registries.limits[&Ecosystem::PyPI].available_permits(), 16);
    assert_eq!(registries.limits[&Ecosystem::NuGet].available_permits(), 16);
    assert_eq!(
        registries.limits[&Ecosystem::CratesIo].available_permits(),
        8
    );
}

#[test]
fn retry_after_supports_delta_seconds_and_all_http_date_forms() {
    let now = SystemTime::UNIX_EPOCH + StdDuration::from_secs(1_800_000_000);
    let cap = StdDuration::from_secs(30);

    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, HeaderValue::from_static("999999"));
    assert_eq!(retry_after_delay(&headers, now, cap), Some(cap));

    for date in [
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
        "Sun, 06 Nov 1994 08:49:37 GMT",
    ] {
        let parsed = httpdate::parse_http_date(date).unwrap();
        headers.insert(RETRY_AFTER, HeaderValue::from_str(date).unwrap());
        assert_eq!(
            retry_after_delay(&headers, parsed - StdDuration::from_secs(7), cap),
            Some(StdDuration::from_secs(7))
        );
    }

    headers.insert(
        RETRY_AFTER,
        HeaderValue::from_str(&httpdate::fmt_http_date(now - StdDuration::from_secs(1))).unwrap(),
    );
    assert_eq!(
        retry_after_delay(&headers, now, cap),
        Some(StdDuration::ZERO)
    );
    headers.insert(RETRY_AFTER, HeaderValue::from_static("not-a-date"));
    assert_eq!(retry_after_delay(&headers, now, cap), None);
}

#[tokio::test]
async fn json_uses_one_attempt_plus_three_retries_without_a_final_sleep() {
    let responses = (0..HTTP_ATTEMPTS)
        .map(|_| RawResponse::fixed(500, Vec::new()))
        .collect();
    let (base_url, requests, server) = spawn_raw_server(responses).await;
    let runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
    let client = test_http_client(runtime.clone(), StdDuration::from_secs(1));

    let error = client
        .get_json(&format!("{base_url}/metadata"), HeaderMap::new())
        .await
        .unwrap_err();
    server.await.unwrap();

    assert_eq!(requests.load(Ordering::SeqCst), HTTP_ATTEMPTS);
    assert_eq!(
        runtime.sleeps(),
        vec![
            StdDuration::from_millis(200),
            StdDuration::from_millis(400),
            StdDuration::from_millis(800),
        ]
    );
    assert_eq!(
        runtime.jitter_bounds(),
        vec![
            StdDuration::from_millis(50),
            StdDuration::from_millis(100),
            StdDuration::from_millis(200),
        ]
    );
    assert!(error.to_string().contains("HTTP 500"));
    assert!(error.to_string().contains("attempt 4/4"));
}

#[tokio::test]
async fn bounded_byte_stream_uses_one_attempt_plus_three_retries() {
    let responses = (0..HTTP_ATTEMPTS)
        .map(|_| RawResponse {
            status: 429,
            retry_after: Some("0".to_owned()),
            body: RawResponseBody::Fixed(Vec::new()),
        })
        .collect();
    let (base_url, requests, server) = spawn_raw_server(responses).await;
    let runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
    let client = test_http_client(runtime.clone(), StdDuration::from_secs(1));

    let error = client
        .get_bytes_limited_revalidated(&format!("{base_url}/bytes"), 1024, HeaderMap::new())
        .await
        .unwrap_err();
    server.await.unwrap();

    assert_eq!(requests.load(Ordering::SeqCst), HTTP_ATTEMPTS);
    assert_eq!(runtime.sleeps(), vec![StdDuration::ZERO; HTTP_MAX_RETRIES]);
    assert!(runtime.jitter_bounds().is_empty());
    assert!(error.to_string().contains("HTTP 429"));
    assert!(error.to_string().contains("attempt 4/4"));
}

#[tokio::test]
async fn bounded_json_rejects_a_body_larger_than_its_decompressed_limit() {
    let body = serde_json::to_vec(&json!({"padding": "x".repeat(128)})).unwrap();
    let (base_url, requests, server) = spawn_raw_server(vec![RawResponse::fixed(200, body)]).await;
    let runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
    let client = test_http_client(runtime, StdDuration::from_secs(1));

    let error = client
        .get_json_limited_revalidated(&format!("{base_url}/metadata"), 64, HeaderMap::new())
        .await
        .unwrap_err();
    server.await.unwrap();

    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert!(
        error
            .to_string()
            .contains("response exceeds the 64-byte limit")
    );
}

#[tokio::test]
async fn retry_after_delta_and_http_date_use_the_injected_clock_and_sleeper() {
    let now = SystemTime::UNIX_EPOCH + StdDuration::from_secs(1_800_000_000);
    let responses = vec![
        RawResponse {
            status: 429,
            retry_after: Some("999999".to_owned()),
            body: RawResponseBody::Fixed(Vec::new()),
        },
        RawResponse {
            status: 503,
            retry_after: Some(httpdate::fmt_http_date(now + StdDuration::from_secs(7))),
            body: RawResponseBody::Fixed(Vec::new()),
        },
        RawResponse::fixed(200, br#"{"ok":true}"#.to_vec()),
    ];
    let (base_url, requests, server) = spawn_raw_server(responses).await;
    let runtime = Arc::new(RecordingRetryRuntime::new(now));
    let client = test_http_client(runtime.clone(), StdDuration::from_secs(1));

    let (value, _) = client
        .get_json(&format!("{base_url}/metadata"), HeaderMap::new())
        .await
        .unwrap();
    server.await.unwrap();

    assert_eq!(value, json!({"ok": true}));
    assert_eq!(requests.load(Ordering::SeqCst), 3);
    assert_eq!(
        runtime.sleeps(),
        vec![StdDuration::from_secs(30), StdDuration::from_secs(7)]
    );
    assert!(runtime.jitter_bounds().is_empty());
}

#[tokio::test]
async fn non_retryable_status_is_immediate_and_redacts_request_secrets() {
    let secret_body = b"super-secret-response".to_vec();
    let (base_url, requests, server) =
        spawn_raw_server(vec![RawResponse::fixed(400, secret_body)]).await;
    let authenticated_url = base_url.replacen("http://", "http://alice:password@", 1);
    let runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
    let client = test_http_client(runtime.clone(), StdDuration::from_secs(1));

    let error = client
        .get_json(
            &format!("{authenticated_url}/metadata?token=query-secret"),
            HeaderMap::new(),
        )
        .await
        .unwrap_err();
    server.await.unwrap();

    let message = error.to_string();
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert!(runtime.sleeps().is_empty());
    assert!(message.contains("HTTP 400"));
    for secret in ["alice", "password", "query-secret", "super-secret-response"] {
        assert!(
            !message.contains(secret),
            "error leaked {secret:?}: {message}"
        );
    }
}

#[tokio::test]
async fn unavailable_endpoint_retries_with_platform_semantic_transport_detail() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable = listener.local_addr().unwrap();
    drop(listener);
    let connect_runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
    let connect_client = test_http_client(connect_runtime.clone(), StdDuration::from_millis(50));
    let url = format!("http://alice:connect-secret@{unavailable}/metadata?token=query-secret");

    let connect_error = connect_client
        .get_json(&url, HeaderMap::new())
        .await
        .unwrap_err();
    let ProviderError::Network(message) = connect_error else {
        panic!("retryable transport failure did not return a network error")
    };
    assert_eq!(
        connect_runtime.sleeps(),
        vec![
            StdDuration::from_millis(200),
            StdDuration::from_millis(400),
            StdDuration::from_millis(800),
        ]
    );
    assert!(
        message.contains("connection failed") || message.contains("request timed out"),
        "retryable transport detail was not normalized: {message}"
    );
    assert!(message.contains("attempt 4/4"));
    assert!(message.starts_with(&request_context(&reqwest::Method::GET, &url)));
    for secret in ["alice", "connect-secret", "query-secret"] {
        assert!(
            !message.contains(secret),
            "error leaked {secret:?}: {message}"
        );
    }
}

#[tokio::test]
async fn request_timeout_retries_every_attempt() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/slow"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(StdDuration::from_millis(100))
                .set_body_json(json!({"ok": true})),
        )
        .expect(HTTP_ATTEMPTS as u64)
        .mount(&server)
        .await;
    let timeout_runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
    let timeout_client = test_http_client(timeout_runtime.clone(), StdDuration::from_millis(10));
    let timeout_error = timeout_client
        .get_json(&format!("{}/slow", server.uri()), HeaderMap::new())
        .await
        .unwrap_err();
    assert_eq!(
        timeout_runtime.sleeps(),
        vec![
            StdDuration::from_millis(200),
            StdDuration::from_millis(400),
            StdDuration::from_millis(800),
        ]
    );
    assert!(timeout_error.to_string().contains("timed out"));
    assert!(timeout_error.to_string().contains("attempt 4/4"));
    server.verify().await;
}

#[tokio::test]
async fn request_builder_failure_is_immediate_and_redacted() {
    let builder_runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
    let builder_client = test_http_client(builder_runtime.clone(), StdDuration::from_secs(1));
    let builder_error = builder_client
        .get_json("://builder-secret", HeaderMap::new())
        .await
        .unwrap_err();
    assert!(builder_runtime.sleeps().is_empty());
    assert!(builder_error.to_string().contains("attempt 1/4"));
    assert!(!builder_error.to_string().contains("builder-secret"));
}
