use super::*;

#[tokio::test]
async fn ecosystem_sync_lock_serializes_competing_writers() {
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_dir.path());
    let (_, first_lock) = acquire_osv_sync_lock(cache.root(), "npm").unwrap();
    let started = Arc::new(Notify::new());
    let waiter_started = started.clone();
    let root = cache.root().to_path_buf();
    let mut waiter = tokio::task::spawn_blocking(move || {
        waiter_started.notify_one();
        acquire_osv_sync_lock(&root, "npm")
    });

    started.notified().await;
    assert!(
        tokio::time::timeout(StdDuration::from_millis(50), &mut waiter)
            .await
            .is_err(),
        "a competing same-ecosystem sync acquired the lock early"
    );
    fs2::FileExt::unlock(&first_lock).unwrap();
    let (_, second_lock) = waiter.await.unwrap().unwrap();
    fs2::FileExt::unlock(&second_lock).unwrap();
}

#[tokio::test]
async fn sync_removes_only_owned_abandoned_temporary_files() {
    let replacement = dump_archive_bytes(1024);
    let (base_url, requests, server) =
        spawn_raw_server(vec![RawResponse::fixed(200, replacement)]).await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_dir.path());
    let offline = cache.root().join("offline");
    fs::create_dir(&offline).unwrap();
    for name in [
        ".npm-old.zip.tmp",
        ".npm-old.synced-at.tmp",
        ".npm-old.zip.rollback.tmp",
        ".npm-old.zip.tmp.keep",
        ".npmx-old.zip.tmp",
        ".pypi-old.zip.tmp",
        "unrelated.tmp",
    ] {
        fs::write(offline.join(name), b"stale fixture").unwrap();
    }
    let client =
        HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1)).unwrap();
    let config = test_sync_config(base_url);

    sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
        .await
        .unwrap();
    server.await.unwrap();

    assert_eq!(requests.load(Ordering::SeqCst), 1);
    for name in [
        ".npm-old.zip.tmp",
        ".npm-old.synced-at.tmp",
        ".npm-old.zip.rollback.tmp",
    ] {
        assert!(!offline.join(name).exists(), "{name} was not reclaimed");
    }
    for name in [
        ".npm-old.zip.tmp.keep",
        ".npmx-old.zip.tmp",
        ".pypi-old.zip.tmp",
        "unrelated.tmp",
    ] {
        assert!(offline.join(name).is_file(), "{name} was removed");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn sync_refuses_a_symlinked_offline_namespace_without_external_writes() {
    use std::os::unix::fs::symlink;

    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_dir.path());
    let external = tempfile::tempdir().unwrap();
    let important = external.path().join("important.txt");
    fs::write(&important, b"preserve").unwrap();
    symlink(external.path(), cache.root().join("offline")).unwrap();
    let client = HttpClient::new().unwrap();
    let config = test_sync_config("http://127.0.0.1:9".to_owned());

    let error = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
        .await
        .unwrap_err();

    assert!(matches!(error, ProviderError::Cache(_)));
    assert_eq!(fs::read(important).unwrap(), b"preserve");
    assert!(!external.path().join("npm.zip").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn sync_refuses_a_cache_root_swapped_to_a_symlink() {
    use std::os::unix::fs::symlink;

    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_dir.path());
    let original = cache.root().to_path_buf();
    let moved = original.with_extension("owned-before-swap");
    let external = tempfile::tempdir().unwrap();
    let important = external.path().join("important.txt");
    fs::write(&important, b"preserve").unwrap();
    fs::rename(&original, &moved).unwrap();
    symlink(external.path(), &original).unwrap();
    let client = HttpClient::new().unwrap();
    let config = test_sync_config("http://127.0.0.1:9".to_owned());

    let result = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config).await;
    fs::remove_file(&original).unwrap();
    fs::rename(&moved, &original).unwrap();

    assert!(matches!(result, Err(ProviderError::Cache(_))));
    assert_eq!(fs::read(important).unwrap(), b"preserve");
    assert!(!external.path().join("npm.zip").exists());
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn capability_relative_sync_confines_every_publication_and_cleanup_boundary() {
    let valid = dump_archive_bytes(1024);
    for boundary in [
        OsvSyncBoundary::AfterTemporaryCreation,
        OsvSyncBoundary::BeforeValidation,
        OsvSyncBoundary::BeforeRollbackStaging,
        OsvSyncBoundary::BeforeArchivePublication,
        OsvSyncBoundary::BeforeMarkerPublication,
    ] {
        assert_sync_boundary_is_capability_confined(boundary, valid.clone()).await;
    }
    assert_sync_boundary_is_capability_confined(
        OsvSyncBoundary::BeforeHandledErrorCleanup,
        b"not a zip archive".to_vec(),
    )
    .await;
}

#[cfg(any(unix, windows))]
#[tokio::test]
async fn capability_relative_sync_confines_a_cache_root_swap() {
    let replacement = dump_archive_bytes(1024);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/npm/all.zip"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(replacement.clone()))
        .mount(&server)
        .await;
    let cache_root = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_root.path());
    let previous = dump_archive_bytes(32);
    seed_sync_files(&cache, &previous, "2000-01-01T00:00:00Z");
    let external = tempfile::tempdir().unwrap();
    seed_external_sync_namespace(external.path());
    let original = cache.root().to_path_buf();
    let moved = original.parent().unwrap().join(format!(
        "{}.ds047-held",
        original.file_name().unwrap().to_string_lossy()
    ));
    let swap = Arc::new(Mutex::new(NamespaceSwap::NotAttempted));
    let hook_swap = swap.clone();
    let external_path = external.path().to_path_buf();
    let mut config = test_sync_config(server.uri());
    config.hooks.boundary_hook = Some(Arc::new(move |boundary| {
        if boundary == OsvSyncBoundary::AfterTemporaryCreation {
            let mut outcome = hook_swap.lock().unwrap();
            if matches!(*outcome, NamespaceSwap::NotAttempted) {
                *outcome = attempt_namespace_swap(&original, &moved, &external_path);
            }
        }
    }));
    let client =
        HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1)).unwrap();

    let result = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config).await;
    let outcome = std::mem::replace(&mut *swap.lock().unwrap(), NamespaceSwap::NotAttempted);
    let swapped = restore_namespace_swap(outcome);

    if swapped {
        assert!(matches!(result, Err(ProviderError::Cache(_))));
        assert_eq!(fs::read(sync_paths(&cache).0).unwrap(), previous);
        assert_no_sync_temps(&cache);
    } else {
        result.expect("a denied Windows root swap must preserve a valid sync");
        assert_eq!(fs::read(sync_paths(&cache).0).unwrap(), replacement);
        assert_no_sync_temps(&cache);
    }
    assert_external_sync_namespace_unchanged(external.path());
}
