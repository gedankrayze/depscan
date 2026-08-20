use super::*;

#[cfg(any(unix, windows))]
#[test]
fn capability_relative_lock_and_abandoned_cleanup_ignore_replacement_namespace() {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Boundary {
        Lock,
        Cleanup,
    }

    for boundary in [Boundary::Lock, Boundary::Cleanup] {
        let cache_root = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_root.path());
        let offline = cache.root().join("offline");
        fs::create_dir(&offline).unwrap();
        fs::write(offline.join(".npm-victim.zip.tmp"), b"owned stale temp").unwrap();
        let moved = cache.root().join("offline.ds047-held");
        let external = tempfile::tempdir().unwrap();
        seed_external_sync_namespace(external.path());
        let swap = Arc::new(Mutex::new(NamespaceSwap::NotAttempted));
        let attempt = {
            let swap = swap.clone();
            let offline = offline.clone();
            let moved = moved.clone();
            let external = external.path().to_path_buf();
            Arc::new(move || {
                let mut outcome = swap.lock().unwrap();
                if matches!(*outcome, NamespaceSwap::NotAttempted) {
                    *outcome = attempt_namespace_swap(&offline, &moved, &external);
                }
            })
        };
        let before_lock = attempt.clone();
        let before_cleanup = attempt.clone();

        let result = acquire_osv_sync_lock_with(
            cache.root(),
            "npm",
            move || {
                if boundary == Boundary::Lock {
                    before_lock();
                }
            },
            move || {
                if boundary == Boundary::Cleanup {
                    before_cleanup();
                }
            },
        );
        let outcome = std::mem::replace(&mut *swap.lock().unwrap(), NamespaceSwap::NotAttempted);
        let swapped = restore_namespace_swap(outcome);

        if swapped {
            assert!(matches!(result, Err(ProviderError::Cache(_))));
        } else {
            let (_, lock) =
                result.expect("a denied Windows namespace swap must preserve lock acquisition");
            fs2::FileExt::unlock(&lock).unwrap();
        }
        if boundary == Boundary::Cleanup {
            assert!(
                !offline.join(".npm-victim.zip.tmp").exists(),
                "cleanup did not act through the held directory capability"
            );
        }
        assert_external_sync_namespace_unchanged(external.path());
    }
}

#[cfg(any(unix, windows))]
#[test]
fn capability_acquisition_revalidates_before_creating_the_offline_child() {
    let cache_root = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_root.path());
    let original = cache.root().to_path_buf();
    let moved = original.parent().unwrap().join(format!(
        "{}.ds047-acquire-held",
        original.file_name().unwrap().to_string_lossy()
    ));
    let external = tempfile::tempdir().unwrap();
    let swap = Arc::new(Mutex::new(NamespaceSwap::NotAttempted));
    let hook_swap = swap.clone();
    let hook_original = original.clone();
    let external_path = external.path().to_path_buf();

    let result = OfflineDirectory::open_with(&original, move || {
        *hook_swap.lock().unwrap() = attempt_namespace_swap(&hook_original, &moved, &external_path);
    });
    let outcome = std::mem::replace(&mut *swap.lock().unwrap(), NamespaceSwap::NotAttempted);
    let swapped = restore_namespace_swap(outcome);

    if swapped {
        assert!(matches!(result, Err(ProviderError::Cache(_))));
    } else {
        result.expect("a denied Windows root swap must preserve capability acquisition");
        assert!(original.join("offline").is_dir());
    }
    assert!(
        fs::read_dir(external.path()).unwrap().next().is_none(),
        "capability acquisition wrote into the replacement cache root"
    );
}

#[cfg(any(unix, windows))]
#[test]
fn cache_sentinel_regular_replacement_is_denied_or_detected() {
    let cache_root = tempfile::tempdir().unwrap();
    let cache = cache_for_sync(cache_root.path());
    let sentinel = cache.root().join(CACHE_SENTINEL_FILE);
    let moved = cache.root().join(".depscan-cache.original.json");
    let replacement = cache.root().join(".depscan-cache.replacement.json");
    let original_bytes = fs::read(&sentinel).unwrap();
    fs::write(&replacement, &original_bytes).unwrap();
    let root = CapDir::open_ambient_dir(cache.root(), ambient_authority()).unwrap();
    let mut outcome = None;

    let result = validate_capability_sentinel_with(&root, cache.root(), || {
        outcome = Some(attempt_regular_file_swap(&sentinel, &moved, &replacement));
    });
    let swapped = restore_file_namespace_swap(outcome.expect("replacement was attempted"));

    if swapped {
        assert!(matches!(result, Err(ProviderError::Cache(_))));
    } else {
        result.expect("denied replacement keeps the owned cache usable");
    }
    assert_eq!(fs::read(sentinel).unwrap(), original_bytes);
}

#[cfg(any(unix, windows))]
#[test]
fn capability_relative_offline_reads_reject_root_child_and_final_name_swaps() {
    let package = Package::new(
        Ecosystem::Npm,
        "read-capability",
        "1.0.0",
        PathBuf::from("package-lock.json"),
    );
    let document = serde_json::to_vec(&json!({
        "id": "TEST-READ-CAPABILITY",
        "modified": TEST_OSV_MODIFIED,
        "summary": "the original held archive contains this advisory",
        "affected": [{
            "package": {
                "ecosystem": "npm",
                "name": "read-capability"
            },
            "versions": ["1.0.0"]
        }]
    }))
    .unwrap();
    let vulnerable_archive = archive_with_entry("TEST-READ-CAPABILITY.json", &document);
    let empty_archive = archive_with_entries(&[], zip::CompressionMethod::Stored);
    let now = test_timestamp("2026-08-19T12:00:00Z");

    for (kind, target) in [OfflineReadSwapKind::Symlink, OfflineReadSwapKind::Regular]
        .into_iter()
        .flat_map(|kind| {
            [
                OfflineReadSwapTarget::Root,
                OfflineReadSwapTarget::OfflineDirectory,
                OfflineReadSwapTarget::Archive,
                OfflineReadSwapTarget::Marker,
            ]
            .into_iter()
            .map(move |target| (kind, target))
        })
    {
        let cache_root = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_root.path());
        seed_sync_files(&cache, &vulnerable_archive, TEST_OSV_MODIFIED);
        let provider = OsvOffline::new(cache.clone());
        let baseline = provider
            .query_blocking_at(std::slice::from_ref(&package), now)
            .unwrap();
        assert_eq!(
            baseline[&package.key()].len(),
            1,
            "original archive was not a vulnerable baseline for {target:?}"
        );

        let external = tempfile::tempdir().unwrap();
        seed_external_offline_read_cache(external.path(), &empty_archive, TEST_OSV_MODIFIED);
        let boundary = match target {
            OfflineReadSwapTarget::Archive => OsvOfflineReadBoundary::BeforeArchive,
            OfflineReadSwapTarget::Root
            | OfflineReadSwapTarget::OfflineDirectory
            | OfflineReadSwapTarget::Marker => OsvOfflineReadBoundary::BeforeMarker,
        };
        let swap = Arc::new(Mutex::new(None));
        let hook_swap = swap.clone();
        let hook_cache = cache.clone();
        let external_root = external.path().to_path_buf();

        let result = provider.query_blocking_at_with_hook(
            std::slice::from_ref(&package),
            now,
            move |observed| {
                if observed == boundary {
                    let mut outcome = hook_swap.lock().unwrap();
                    if outcome.is_none() {
                        *outcome = Some(attempt_offline_read_swap(
                            kind,
                            target,
                            &hook_cache,
                            &external_root,
                        ));
                    }
                }
            },
        );
        let outcome = swap
            .lock()
            .unwrap()
            .take()
            .expect("offline read did not reach the requested swap boundary");
        let swapped = restore_offline_read_swap(outcome);

        if swapped {
            assert!(
                matches!(result, Err(ProviderError::Offline(_))),
                "successful {kind:?} {target:?} swap did not fail the offline scan closed: {result:?}"
            );
        } else {
            let output = result.expect("a denied Windows swap must leave the scan usable");
            assert_eq!(
                output[&package.key()].len(),
                1,
                "denied {kind:?} {target:?} swap produced a false-clean result"
            );
        }
        let (archive_path, marker_path) = sync_paths(&cache);
        assert_eq!(fs::read(archive_path).unwrap(), vulnerable_archive);
        assert_eq!(fs::read(marker_path).unwrap(), TEST_OSV_MODIFIED.as_bytes());
        assert_eq!(
            fs::read(external.path().join("offline/npm.zip")).unwrap(),
            empty_archive,
            "external empty archive changed during {kind:?} {target:?} swap"
        );
        assert_eq!(
            fs::read(external.path().join("offline/npm.synced-at")).unwrap(),
            TEST_OSV_MODIFIED.as_bytes(),
            "external marker changed during {kind:?} {target:?} swap"
        );
    }
}
