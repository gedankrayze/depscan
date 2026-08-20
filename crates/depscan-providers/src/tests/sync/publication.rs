use super::*;

#[tokio::test]
async fn failed_interrupted_transfers_preserve_known_good_files_and_clean_temps() {
    let previous = dump_archive_bytes(32);
    let replacement = dump_archive_bytes(64 * 1024);
    let responses = (0..OSV_DUMP_ATTEMPTS)
        .map(|_| RawResponse::truncated(replacement.clone(), replacement.len() / 3))
        .collect();
    let (base_url, requests, server) = spawn_raw_server(responses).await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_dir.path());
    let previous_marker = "2000-01-01T00:00:00Z";
    seed_sync_files(&cache, &previous, previous_marker);
    let client =
        HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1)).unwrap();
    let config = test_sync_config(base_url);

    let error = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
        .await
        .unwrap_err();
    server.await.unwrap();

    assert!(matches!(error, ProviderError::Network(_)));
    assert_eq!(requests.load(Ordering::SeqCst), OSV_DUMP_ATTEMPTS);
    let (archive_path, marker_path) = sync_paths(&cache);
    assert_eq!(fs::read(archive_path).unwrap(), previous);
    assert_eq!(fs::read_to_string(marker_path).unwrap(), previous_marker);
    assert_no_sync_temps(&cache);
}

#[tokio::test]
async fn corrupt_zip_preserves_known_good_files_and_is_not_retried() {
    let previous = dump_archive_bytes(32);
    let corrupt = b"this is not a zip archive".to_vec();
    let (base_url, requests, server) =
        spawn_raw_server(vec![RawResponse::fixed(200, corrupt)]).await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_dir.path());
    let previous_marker = "2000-01-01T00:00:00Z";
    seed_sync_files(&cache, &previous, previous_marker);
    let client =
        HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1)).unwrap();
    let config = test_sync_config(base_url);

    let error = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
        .await
        .unwrap_err();
    server.await.unwrap();

    assert!(matches!(error, ProviderError::InvalidResponse(_)));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    let (archive_path, marker_path) = sync_paths(&cache);
    assert_eq!(fs::read(archive_path).unwrap(), previous);
    assert_eq!(fs::read_to_string(marker_path).unwrap(), previous_marker);
    assert_no_sync_temps(&cache);
}

#[tokio::test]
async fn syntactically_valid_non_osv_json_preserves_known_good_files() {
    let previous = dump_archive_bytes(32);
    let invalid = archive_with_entry("TEST-1.json", b"{}");
    let (base_url, requests, server) =
        spawn_raw_server(vec![RawResponse::fixed(200, invalid)]).await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_dir.path());
    let previous_marker = "2000-01-01T00:00:00Z";
    seed_sync_files(&cache, &previous, previous_marker);
    let client =
        HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1)).unwrap();
    let config = test_sync_config(base_url);

    let error = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
        .await
        .unwrap_err();
    server.await.unwrap();

    assert!(matches!(error, ProviderError::InvalidResponse(_)));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    let (archive_path, marker_path) = sync_paths(&cache);
    assert_eq!(fs::read(archive_path).unwrap(), previous);
    assert_eq!(fs::read_to_string(marker_path).unwrap(), previous_marker);
    assert_no_sync_temps(&cache);
}

#[tokio::test]
async fn rollback_staging_failure_leaves_the_previous_pair_untouched() {
    let previous = dump_archive_bytes(32);
    let replacement = dump_archive_bytes(1024);
    let (base_url, requests, server) =
        spawn_raw_server(vec![RawResponse::fixed(200, replacement)]).await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_dir.path());
    let previous_marker = "2000-01-01T00:00:00Z";
    seed_sync_files(&cache, &previous, previous_marker);
    let client =
        HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1)).unwrap();
    let mut config = test_sync_config(base_url);
    config.force_rollback_staging_error = true;

    let error = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
        .await
        .unwrap_err();
    server.await.unwrap();

    assert!(matches!(error, ProviderError::Cache(_)));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    let (archive_path, marker_path) = sync_paths(&cache);
    assert_eq!(fs::read(archive_path).unwrap(), previous);
    assert_eq!(fs::read_to_string(marker_path).unwrap(), previous_marker);
    assert_no_sync_temps(&cache);
}

#[tokio::test]
async fn invalid_marker_target_is_rejected_before_download_or_replacement() {
    let previous = dump_archive_bytes(32);
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_dir.path());
    seed_sync_files(&cache, &previous, "2000-01-01T00:00:00Z");
    let (archive_path, marker_path) = sync_paths(&cache);
    fs::remove_file(&marker_path).unwrap();
    fs::create_dir(&marker_path).unwrap();
    let client =
        HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1)).unwrap();
    let config = test_sync_config("http://127.0.0.1:9".to_owned());

    let error = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
        .await
        .unwrap_err();

    assert!(matches!(error, ProviderError::Cache(_)));
    assert_eq!(fs::read(archive_path).unwrap(), previous);
    assert!(marker_path.is_dir());
    assert_no_sync_temps(&cache);
}

#[test]
fn staged_backup_restores_a_replaced_archive_without_copying_after_failure() {
    let cache_root = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_root.path());
    let directory = OfflineDirectory::open(cache.root()).unwrap();
    let archive_name = OsStr::new("npm.zip");
    let archive = directory.display_path(archive_name);
    let previous = dump_archive_bytes(32);
    fs::write(&archive, &previous).unwrap();
    let backup = stage_previous_archive(&directory, archive_name, ".npm-")
        .unwrap()
        .unwrap();

    let mut replacement = CapabilityTempFile::new(&directory, ".npm-", ".zip.tmp").unwrap();
    replacement.write_all(&dump_archive_bytes(1024)).unwrap();
    replacement.as_file().sync_all().unwrap();
    replacement
        .persist(archive_name)
        .map_err(|error| error.source)
        .unwrap();
    restore_previous_archive(&directory, Some(backup), archive_name).unwrap();

    assert_eq!(fs::read(archive).unwrap(), previous);
}

#[test]
fn failed_restore_retains_the_last_recovery_copy() {
    let cache_root = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_root.path());
    let directory = OfflineDirectory::open(cache.root()).unwrap();
    let archive_name = OsStr::new("npm.zip");
    let archive = directory.display_path(archive_name);
    let previous = dump_archive_bytes(32);
    fs::write(&archive, &previous).unwrap();
    let backup = stage_previous_archive(&directory, archive_name, ".npm-")
        .unwrap()
        .unwrap();
    fs::remove_file(&archive).unwrap();
    fs::create_dir(&archive).unwrap();

    let error = restore_previous_archive(&directory, Some(backup), archive_name).unwrap_err();
    let recovery_files = fs::read_dir(&directory.path)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .ends_with(".zip.rollback.tmp")
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();

    assert!(error.to_string().contains("rollback copy retained at"));
    assert_eq!(recovery_files.len(), 1);
    assert_eq!(fs::read(&recovery_files[0]).unwrap(), previous);
    assert!(archive.is_dir());
}

#[test]
fn marker_publication_failure_exercises_pair_rollback() {
    let cache_root = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_root.path());
    let directory = OfflineDirectory::open(cache.root()).unwrap();
    let archive_name = OsStr::new("npm.zip");
    let marker_name = OsStr::new("npm.synced-at");
    let archive = directory.display_path(archive_name);
    let marker = directory.display_path(marker_name);
    let previous_archive = dump_archive_bytes(32);
    let previous_marker = b"2000-01-01T00:00:00Z";
    fs::write(&archive, &previous_archive).unwrap();
    fs::write(&marker, previous_marker).unwrap();
    let backup = stage_previous_archive(&directory, archive_name, ".npm-").unwrap();

    let mut archive_temp = CapabilityTempFile::new(&directory, ".npm-", ".zip.tmp").unwrap();
    archive_temp.write_all(&dump_archive_bytes(1024)).unwrap();
    archive_temp.as_file().sync_all().unwrap();
    let mut marker_temp = CapabilityTempFile::new(&directory, ".npm-", ".synced-at.tmp").unwrap();
    marker_temp.write_all(b"2026-08-19T00:00:00Z").unwrap();
    marker_temp.as_file().sync_all().unwrap();
    let marker_blocker = directory.path.join("marker-blocker");
    fs::create_dir(&marker_blocker).unwrap();

    let error = publish_osv_pair_with(
        &directory,
        archive_temp,
        marker_temp,
        OsvPairNames {
            archive: archive_name,
            marker: marker_name,
        },
        backup,
        || Ok(()),
        |temporary, _| persist_capability_temp(temporary, OsStr::new("marker-blocker")),
    )
    .unwrap_err();

    assert!(error.to_string().contains("restored previous archive"));
    assert_eq!(fs::read(&archive).unwrap(), previous_archive);
    assert_eq!(fs::read(&marker).unwrap(), previous_marker);
    let temporary = fs::read_dir(&directory.path)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    assert!(
        temporary.is_empty(),
        "temporary files remain: {temporary:?}"
    );
}

#[tokio::test]
async fn configurable_transfer_deadline_preserves_known_good_files() {
    let previous = dump_archive_bytes(32);
    let replacement = dump_archive_bytes(512 * 1024);
    let responses = (0..2)
        .map(|_| RawResponse {
            status: 200,
            retry_after: None,
            body: RawResponseBody::Chunked {
                body: replacement.clone(),
                chunk_size: 32 * 1024,
                delay: StdDuration::from_millis(20),
                pause_after_chunks: None,
                paused: None,
                resume: None,
            },
        })
        .collect();
    let (base_url, requests, server) = spawn_raw_server(responses).await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_dir.path());
    let previous_marker = "2000-01-01T00:00:00Z";
    seed_sync_files(&cache, &previous, previous_marker);
    let client =
        HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1)).unwrap();
    let mut config = test_sync_config(base_url);
    config.transfer_timeout = StdDuration::from_millis(45);
    config.attempts = 2;

    let error = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
        .await
        .unwrap_err();
    server.await.unwrap();

    assert!(matches!(error, ProviderError::Network(_)));
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    let (archive_path, marker_path) = sync_paths(&cache);
    assert_eq!(fs::read(archive_path).unwrap(), previous);
    assert_eq!(fs::read_to_string(marker_path).unwrap(), previous_marker);
    assert_no_sync_temps(&cache);
}

#[test]
fn dump_validation_requires_complete_bounded_osv_documents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dump.zip");
    let config = test_sync_config("http://unused.test".to_owned());
    let valid = br#"{"id":"TEST-1","modified":"2026-08-19T00:00:00Z","details":"forward-compatible","affected":[]}"#;

    fs::write(&path, archive_with_entry("TEST-1.json", valid)).unwrap();
    validate_osv_dump(&path, Ecosystem::Npm, &config).unwrap();

    for (name, contents) in [
        ("README.txt", b"not JSON".as_slice()),
        ("TEST-1.json", b"{}".as_slice()),
        ("TEST-1.json", b"null".as_slice()),
        ("TEST-1.json", b"[]".as_slice()),
        (
            "TEST-1.json",
            br#"{"id":"TEST-1","modified":"not-a-timestamp"}"#.as_slice(),
        ),
        (
            "TEST-1.json",
            br#"{"id":"UNKNOWN","modified":"2026-08-19T00:00:00Z"}"#.as_slice(),
        ),
        ("TEST-1.json", br#"{"id":"TEST-1""#.as_slice()),
    ] {
        fs::write(&path, archive_with_entry(name, contents)).unwrap();
        assert!(
            matches!(
                validate_osv_dump(&path, Ecosystem::Npm, &config),
                Err(ProviderError::InvalidResponse(_))
            ),
            "accepted invalid entry {name:?}: {}",
            String::from_utf8_lossy(contents)
        );
    }

    fs::write(&path, archive_with_entry("OTHER-1.json", valid)).unwrap();
    assert!(matches!(
        validate_osv_dump(&path, Ecosystem::Npm, &config),
        Err(ProviderError::InvalidResponse(_))
    ));

    let mut limited = config;
    limited.max_entry_bytes = valid.len() as u64 - 1;
    fs::write(&path, archive_with_entry("TEST-1.json", valid)).unwrap();
    assert!(matches!(
        validate_osv_dump(&path, Ecosystem::Npm, &limited),
        Err(ProviderError::InvalidResponse(_))
    ));

    let mut forged = archive_with_entry("TEST-1.json", valid);
    let central_header = forged
        .windows(4)
        .rposition(|window| window == b"PK\x01\x02")
        .unwrap();
    let forged_declared_size = u32::try_from(valid.len() - 2).unwrap();
    forged[central_header + 24..central_header + 28]
        .copy_from_slice(&forged_declared_size.to_le_bytes());
    fs::write(&path, forged).unwrap();
    limited.max_entry_bytes = valid.len() as u64 - 1;
    let error = validate_osv_dump(&path, Ecosystem::Npm, &limited).unwrap_err();
    assert!(
        error.to_string().contains("actual uncompressed"),
        "unexpected forged-size error: {error}"
    );
}
