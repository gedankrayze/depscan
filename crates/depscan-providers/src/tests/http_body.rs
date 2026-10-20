use super::*;

#[tokio::test]
async fn json_gzip_limit_applies_after_decompression() {
    // gzip({"padding": "x" * 128}): 37 encoded bytes, 142 decoded bytes.
    let compressed = vec![
        31, 139, 8, 0, 0, 0, 0, 0, 0, 19, 171, 86, 42, 72, 76, 73, 201, 204, 75, 87, 178, 82, 170,
        24, 96, 160, 84, 11, 0, 224, 199, 23, 139, 142, 0, 0, 0,
    ];
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Encoding", "gzip")
                .set_body_bytes(compressed),
        )
        .expect(1)
        .mount(&server)
        .await;
    let mut client = HttpClient::new().unwrap();
    client.max_json_bytes = 64;
    let error = client
        .get_json(&server.uri(), HeaderMap::new())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("response exceeds the 64-byte limit")
    );
    server.verify().await;
}

#[tokio::test]
async fn json_get_and_post_reject_oversized_bodies_without_retrying() {
    for method in [reqwest::Method::GET, reqwest::Method::POST] {
        let body = serde_json::to_vec(&json!({"padding": "secret".repeat(32)})).unwrap();
        let (base_url, requests, server) =
            spawn_raw_server(vec![RawResponse::fixed(200, body)]).await;
        let runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
        let mut client = test_http_client(runtime.clone(), StdDuration::from_secs(1));
        client.max_json_bytes = 64;
        let error = client
            .request_json(
                method,
                &format!("{base_url}/metadata?token=private"),
                None,
                HeaderMap::new(),
            )
            .await
            .unwrap_err();
        server.await.unwrap();
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert!(runtime.sleeps().is_empty());
        assert!(
            error
                .to_string()
                .contains("response exceeds the 64-byte limit")
        );
        assert!(!error.to_string().contains("secret"));
        assert!(!error.to_string().contains("private"));
    }
}

#[tokio::test]
async fn json_chunked_body_is_bounded_without_content_length() {
    let response = RawResponse {
        status: 200,
        retry_after: None,
        body: RawResponseBody::Chunked {
            body: serde_json::to_vec(&json!({"padding": "x".repeat(128)})).unwrap(),
            chunk_size: 16,
            delay: StdDuration::ZERO,
            pause_after_chunks: None,
            paused: None,
            resume: None,
        },
    };
    let (base_url, requests, server) = spawn_raw_server(vec![response]).await;
    let mut client = HttpClient::new().unwrap();
    client.max_json_bytes = 64;
    let error = client
        .get_json(&base_url, HeaderMap::new())
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
async fn json_accepts_exact_limit_and_reports_interrupted_body() {
    let body = serde_json::to_vec(&json!({"ok": true})).unwrap();
    let (base_url, requests, server) =
        spawn_raw_server(vec![RawResponse::fixed(200, body.clone())]).await;
    let runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
    let mut client = test_http_client(runtime.clone(), StdDuration::from_secs(1));
    client.max_json_bytes = body.len();
    let (value, _) = client.get_json(&base_url, HeaderMap::new()).await.unwrap();
    server.await.unwrap();
    assert_eq!(value, json!({"ok": true}));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert!(runtime.sleeps().is_empty());

    let (base_url, _, server) = spawn_raw_server(vec![RawResponse::truncated(body, 4)]).await;
    let error = client
        .get_json(&base_url, HeaderMap::new())
        .await
        .unwrap_err();
    server.await.unwrap();
    assert!(matches!(error, ProviderError::Network(_)));
    assert!(runtime.sleeps().is_empty());
}
