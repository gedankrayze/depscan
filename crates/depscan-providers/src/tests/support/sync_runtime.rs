use super::*;

#[cfg(any(unix, windows))]
pub(crate) async fn assert_sync_boundary_is_capability_confined(
    boundary: OsvSyncBoundary,
    response: Vec<u8>,
) {
    let expected_response = response.clone();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/npm/all.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(response))
        .mount(&server)
        .await;
    let cache_root = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_root.path());
    let previous = dump_archive_bytes(32);
    let previous_marker = "2000-01-01T00:00:00Z";
    seed_sync_files(&cache, &previous, previous_marker);
    let external = tempfile::tempdir().unwrap();
    seed_external_sync_namespace(external.path());
    let offline = cache.root().join("offline");
    let moved = cache.root().join("offline.ds047-held");
    let swap = Arc::new(Mutex::new(NamespaceSwap::NotAttempted));
    let hook_swap = swap.clone();
    let external_path = external.path().to_path_buf();
    let mut config = test_sync_config(server.uri());
    config.boundary_hook = Some(Arc::new(move |observed| {
        if observed == boundary {
            let mut outcome = hook_swap.lock().unwrap();
            if matches!(*outcome, NamespaceSwap::NotAttempted) {
                *outcome = attempt_namespace_swap(&offline, &moved, &external_path);
            }
        }
    }));
    let client =
        HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1)).unwrap();

    let result = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config).await;
    let outcome = std::mem::replace(&mut *swap.lock().unwrap(), NamespaceSwap::NotAttempted);
    let swapped = restore_namespace_swap(outcome);

    if swapped {
        assert!(
            matches!(&result, Err(ProviderError::Cache(_))),
            "a successful swap at {boundary:?} must fail capability revalidation: {result:?}"
        );
    } else if boundary == OsvSyncBoundary::BeforeHandledErrorCleanup {
        assert!(
            matches!(
                &result,
                Err(ProviderError::InvalidResponse(message))
                    if message.starts_with("OSV dump for npm is invalid: ")
            ),
            "a denied Windows swap at {boundary:?} must preserve the invalid dump result: {result:?}"
        );
    } else {
        result
            .as_ref()
            .expect("a denied Windows swap must preserve a valid sync");
    }

    if swapped || boundary == OsvSyncBoundary::BeforeHandledErrorCleanup {
        assert_eq!(fs::read(sync_paths(&cache).0).unwrap(), previous);
        assert_eq!(
            fs::read_to_string(sync_paths(&cache).1).unwrap(),
            previous_marker
        );
    } else {
        assert_eq!(fs::read(sync_paths(&cache).0).unwrap(), expected_response);
        assert_ne!(
            fs::read_to_string(sync_paths(&cache).1).unwrap(),
            previous_marker
        );
    }
    assert_no_sync_temps(&cache);
    assert_external_sync_namespace_unchanged(external.path());
}

pub(crate) fn test_sync_config(base_url: String) -> OsvSyncConfig {
    let mut config = OsvSyncConfig::new(OsvSyncOptions {
        transfer_timeout: StdDuration::from_secs(5),
    })
    .unwrap();
    config.base_url = base_url;
    config.max_download_bytes = 32 * 1024 * 1024;
    config.max_entry_bytes = 16 * 1024 * 1024;
    config.max_uncompressed_bytes = 64 * 1024 * 1024;
    config.max_entries = 100;
    config.backoff_base = StdDuration::from_millis(1);
    config.max_retry_delay = StdDuration::from_millis(5);
    config
}

pub(crate) struct TrackedChunk {
    bytes: Vec<u8>,
    live_bytes: Arc<AtomicUsize>,
}

impl TrackedChunk {
    pub(crate) fn new(size: usize, live_bytes: Arc<AtomicUsize>, peak_bytes: &AtomicUsize) -> Self {
        let live = live_bytes.fetch_add(size, Ordering::SeqCst) + size;
        peak_bytes.fetch_max(live, Ordering::SeqCst);
        Self {
            bytes: vec![b'x'; size],
            live_bytes,
        }
    }
}

impl AsRef<[u8]> for TrackedChunk {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for TrackedChunk {
    fn drop(&mut self) {
        self.live_bytes
            .fetch_sub(self.bytes.len(), Ordering::SeqCst);
    }
}

pub(crate) async fn peak_live_stream_bytes(total_bytes: usize, chunk_bytes: usize) -> usize {
    assert_eq!(total_bytes % chunk_bytes, 0);
    let live_bytes = Arc::new(AtomicUsize::new(0));
    let peak_bytes = Arc::new(AtomicUsize::new(0));
    let chunks = stream::iter((0..total_bytes / chunk_bytes).map({
        let live_bytes = live_bytes.clone();
        let peak_bytes = peak_bytes.clone();
        move |_| {
            Ok::<_, std::io::Error>(TrackedChunk::new(
                chunk_bytes,
                live_bytes.clone(),
                &peak_bytes,
            ))
        }
    }));
    let mut destination = tokio::io::sink();
    let mut config = test_sync_config("http://unused.test".to_owned());
    config.max_download_bytes = total_bytes as u64;
    let downloaded = stream_osv_dump_body(
        chunks,
        &mut destination,
        "http://unused.test/dump.zip",
        &config,
    )
    .await
    .unwrap();
    assert_eq!(downloaded, total_bytes as u64);
    assert_eq!(live_bytes.load(Ordering::SeqCst), 0);
    peak_bytes.load(Ordering::SeqCst)
}
