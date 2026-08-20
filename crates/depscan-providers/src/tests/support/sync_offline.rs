use super::*;

#[cfg(any(unix, windows))]
pub(crate) fn seed_external_offline_read_cache(root: &Path, archive: &[u8], marker: &str) {
    fs::write(
        root.join(CACHE_SENTINEL_FILE),
        serde_json::to_vec(&expected_cache_sentinel()).unwrap(),
    )
    .unwrap();
    let offline = root.join("offline");
    fs::create_dir(&offline).unwrap();
    fs::write(offline.join("npm.zip"), archive).unwrap();
    fs::write(offline.join("npm.synced-at"), marker).unwrap();
}

#[cfg(any(unix, windows))]
pub(crate) fn attempt_offline_read_swap(
    kind: OfflineReadSwapKind,
    target: OfflineReadSwapTarget,
    cache: &Cache,
    external_root: &Path,
) -> OfflineReadSwap {
    let offline = cache.root().join("offline");
    let external_offline = external_root.join("offline");
    if matches!(kind, OfflineReadSwapKind::Regular) {
        let (original, moved, replacement) = match target {
            OfflineReadSwapTarget::Root => {
                let original = cache.root().to_path_buf();
                let moved = original.parent().unwrap().join(format!(
                    "{}.ds064-read-held",
                    original.file_name().unwrap().to_string_lossy()
                ));
                (original, moved, external_root.to_path_buf())
            }
            OfflineReadSwapTarget::OfflineDirectory => (
                offline.clone(),
                cache.root().join("offline.ds064-read-held"),
                external_offline.clone(),
            ),
            OfflineReadSwapTarget::Archive => (
                offline.join("npm.zip"),
                offline.join("npm.zip.ds064-read-held"),
                external_offline.join("npm.zip"),
            ),
            OfflineReadSwapTarget::Marker => (
                offline.join("npm.synced-at"),
                offline.join("npm.synced-at.ds064-read-held"),
                external_offline.join("npm.synced-at"),
            ),
        };
        return OfflineReadSwap::Regular(attempt_regular_namespace_swap(
            &original,
            &moved,
            &replacement,
        ));
    }

    match target {
        OfflineReadSwapTarget::Root => {
            let original = cache.root();
            let moved = original.parent().unwrap().join(format!(
                "{}.ds047-read-held",
                original.file_name().unwrap().to_string_lossy()
            ));
            OfflineReadSwap::Directory(attempt_namespace_swap(original, &moved, external_root))
        }
        OfflineReadSwapTarget::OfflineDirectory => {
            let moved = cache.root().join("offline.ds047-read-held");
            OfflineReadSwap::Directory(attempt_namespace_swap(&offline, &moved, &external_offline))
        }
        OfflineReadSwapTarget::Archive => {
            let original = offline.join("npm.zip");
            let moved = offline.join("npm.zip.ds047-read-held");
            OfflineReadSwap::File(attempt_file_namespace_swap(
                &original,
                &moved,
                &external_offline.join("npm.zip"),
            ))
        }
        OfflineReadSwapTarget::Marker => {
            let original = offline.join("npm.synced-at");
            let moved = offline.join("npm.synced-at.ds047-read-held");
            OfflineReadSwap::File(attempt_file_namespace_swap(
                &original,
                &moved,
                &external_offline.join("npm.synced-at"),
            ))
        }
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn restore_offline_read_swap(outcome: OfflineReadSwap) -> bool {
    match outcome {
        OfflineReadSwap::Directory(outcome) => restore_namespace_swap(outcome),
        OfflineReadSwap::File(outcome) => restore_file_namespace_swap(outcome),
        OfflineReadSwap::Regular(outcome) => restore_regular_namespace_swap(outcome),
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn seed_external_sync_namespace(directory: &Path) {
    fs::create_dir_all(directory).unwrap();
    for (name, contents) in [
        ("npm.zip", b"external archive".as_slice()),
        ("npm.synced-at", b"external marker".as_slice()),
        (".npm.sync.lock", b"external lock".as_slice()),
        (".npm-victim.zip.tmp", b"external temp".as_slice()),
        (
            ".npm-victim.zip.rollback.tmp",
            b"external rollback".as_slice(),
        ),
    ] {
        fs::write(directory.join(name), contents).unwrap();
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn assert_external_sync_namespace_unchanged(directory: &Path) {
    let expected = BTreeMap::from([
        (
            ".npm-victim.zip.rollback.tmp",
            b"external rollback".as_slice(),
        ),
        (".npm-victim.zip.tmp", b"external temp".as_slice()),
        (".npm.sync.lock", b"external lock".as_slice()),
        ("npm.synced-at", b"external marker".as_slice()),
        ("npm.zip", b"external archive".as_slice()),
    ]);
    let actual = fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            let bytes = fs::read(entry.path()).unwrap();
            (name, bytes)
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(actual.len(), expected.len(), "external namespace changed");
    for (name, contents) in expected {
        assert_eq!(
            actual.get(name).map(Vec::as_slice),
            Some(contents),
            "external file {name:?} changed"
        );
    }
}
