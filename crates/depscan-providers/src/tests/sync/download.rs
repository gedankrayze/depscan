use super::*;

#[tokio::test]
async fn streamed_dump_memory_is_bounded_by_chunk_size_not_archive_size() {
    let chunk_bytes = 64 * 1024;
    let small_peak = peak_live_stream_bytes(4 * 1024 * 1024, chunk_bytes).await;
    let large_peak = peak_live_stream_bytes(128 * 1024 * 1024, chunk_bytes).await;

    assert_eq!(small_peak, chunk_bytes);
    assert_eq!(large_peak, chunk_bytes);
}

#[tokio::test]
async fn sync_streams_a_slow_large_dump_before_atomic_replacement() {
    let previous = dump_archive_bytes(32);
    let replacement = dump_archive_bytes(4 * 1024 * 1024);
    let paused = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let response = RawResponse {
        status: 200,
        retry_after: None,
        body: RawResponseBody::Chunked {
            body: replacement.clone(),
            chunk_size: 64 * 1024,
            delay: StdDuration::from_millis(3),
            pause_after_chunks: Some(8),
            paused: Some(paused.clone()),
            resume: Some(resume.clone()),
        },
    };
    let (base_url, requests, server) = spawn_raw_server(vec![response]).await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_dir.path());
    let previous_marker = "2000-01-01T00:00:00Z";
    seed_sync_files(&cache, &previous, previous_marker);
    let client =
        HttpClient::with_timeouts(StdDuration::from_secs(30), StdDuration::from_secs(30)).unwrap();
    let observed_chunk_bytes = Arc::new(AtomicUsize::new(0));
    let (stream_progress, mut streamed_bytes) = tokio::sync::watch::channel(0u64);
    let mut config = test_sync_config(base_url);
    config.transfer_timeout = StdDuration::from_secs(30);
    config.hooks.observed_max_chunk_bytes = Some(observed_chunk_bytes.clone());
    config.hooks.stream_progress = Some(stream_progress);
    let sync_cache = cache.clone();
    let sync = tokio::spawn(async move {
        sync_osv_dumps_with_config(&client, &sync_cache, &[Ecosystem::Npm], &config).await
    });

    tokio::time::timeout(StdDuration::from_secs(10), async {
        paused.notified().await;
        streamed_bytes
            .wait_for(|bytes| *bytes > 0)
            .await
            .expect("stream progress sender closed before the first write");
        let (archive_path, marker_path) = sync_paths(&cache);
        assert_eq!(fs::read(&archive_path).unwrap(), previous);
        assert_eq!(fs::read_to_string(&marker_path).unwrap(), previous_marker);
        let partial_size = *streamed_bytes.borrow_and_update();
        assert!(partial_size > 0);
        assert!(partial_size < replacement.len() as u64);
        assert!(
            fs::read_dir(cache.root().join("offline"))
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry.file_name().to_string_lossy().ends_with(".zip.tmp")),
            "the client write did not target the held temporary file"
        );

        resume.notify_one();
        let paths = sync.await.unwrap().unwrap();
        server.await.unwrap();
        assert_eq!(paths, vec![archive_path.clone()]);
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert!(observed_chunk_bytes.load(Ordering::SeqCst) > 0);
        assert!(observed_chunk_bytes.load(Ordering::SeqCst) < replacement.len());
        assert_eq!(fs::read(&archive_path).unwrap(), replacement);
        assert_ne!(fs::read_to_string(marker_path).unwrap(), previous_marker);
        assert_no_sync_temps(&cache);
    })
    .await
    .expect("slow stream did not complete the server/client/write/publication sequence");
}

#[tokio::test]
async fn sync_retries_an_interrupted_body_from_an_empty_temp_file() {
    let previous = dump_archive_bytes(32);
    let replacement = dump_archive_bytes(256 * 1024);
    let responses = vec![
        RawResponse::truncated(replacement.clone(), replacement.len() / 2),
        RawResponse::fixed(200, replacement.clone()),
    ];
    let (base_url, requests, server) = spawn_raw_server(responses).await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_dir.path());
    seed_sync_files(&cache, &previous, "2000-01-01T00:00:00Z");
    let client =
        HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1)).unwrap();
    let config = test_sync_config(base_url);

    sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
        .await
        .unwrap();
    server.await.unwrap();

    let (archive_path, _) = sync_paths(&cache);
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    assert_eq!(fs::read(archive_path).unwrap(), replacement);
    assert_no_sync_temps(&cache);
}

#[tokio::test]
async fn sync_retries_429_and_5xx_with_both_retry_after_forms() {
    let replacement = dump_archive_bytes(1024);
    let now = SystemTime::UNIX_EPOCH + StdDuration::from_secs(1_800_000_000);
    let responses = vec![
        RawResponse {
            status: 429,
            retry_after: Some("999999".to_owned()),
            body: RawResponseBody::Fixed(Vec::new()),
        },
        RawResponse::fixed(500, Vec::new()),
        RawResponse {
            status: 503,
            retry_after: Some(httpdate::fmt_http_date(now + StdDuration::from_secs(20))),
            body: RawResponseBody::Fixed(Vec::new()),
        },
        RawResponse::fixed(200, replacement.clone()),
    ];
    let (base_url, requests, server) = spawn_raw_server(responses).await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_dir.path());
    let runtime = Arc::new(RecordingRetryRuntime::new(now));
    let client = test_http_client(runtime.clone(), StdDuration::from_secs(1));
    let config = test_sync_config(base_url);

    sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
        .await
        .unwrap();
    server.await.unwrap();

    assert_eq!(requests.load(Ordering::SeqCst), HTTP_ATTEMPTS);
    assert_eq!(
        runtime.sleeps(),
        vec![
            StdDuration::from_millis(5),
            StdDuration::from_millis(2),
            StdDuration::from_millis(5),
        ]
    );
    assert_eq!(fs::read(sync_paths(&cache).0).unwrap(), replacement);
    assert_no_sync_temps(&cache);
}
