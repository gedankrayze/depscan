use super::*;

#[test]
fn common_cache_freshness_rejects_future_timestamps_and_honors_boundaries() {
    fn entry(stored_at: DateTime<Utc>) -> CacheEntry {
        CacheEntry {
            stored_at,
            etag: None,
            value: Value::Null,
        }
    }

    let now = test_timestamp("2026-08-19T12:00:00Z");
    let ttl = Duration::hours(1);
    let cache = Cache {
        root: PathBuf::new(),
        policy: CachePolicy::default(),
    };

    assert!(cache.lookup_from_entry_at(entry(now), ttl, now).fresh);
    assert!(cache.lookup_from_entry_at(entry(now - ttl), ttl, now).fresh);
    assert!(
        !cache
            .lookup_from_entry_at(entry(now - ttl - Duration::nanoseconds(1)), ttl, now)
            .fresh
    );
    assert!(
        !cache
            .lookup_from_entry_at(entry(now + Duration::nanoseconds(1)), ttl, now)
            .fresh
    );

    let max_age = Duration::minutes(30);
    let strict = Cache {
        root: PathBuf::new(),
        policy: CachePolicy {
            read: true,
            max_age: Some(max_age),
        },
    };
    assert!(
        strict
            .lookup_from_entry_at(entry(now - max_age), ttl, now)
            .fresh
    );
    assert!(
        !strict
            .lookup_from_entry_at(entry(now - max_age - Duration::nanoseconds(1)), ttl, now,)
            .fresh
    );
    assert!(
        !strict
            .lookup_from_entry_at(entry(now + Duration::nanoseconds(1)), ttl, now)
            .fresh
    );
}

#[test]
fn future_concurrent_winner_remains_a_non_reusable_cas_generation() {
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    let ttl = Duration::hours(1);
    cache
        .put("registry", "future-conflict", &json!({"revision": 1}), None)
        .unwrap();
    let expected = cache
        .snapshot("registry", "future-conflict", ttl)
        .expect("initial cache generation");
    cache
        .put("registry", "future-conflict", &json!({"revision": 2}), None)
        .unwrap();
    set_cache_entry_timestamp(
        &cache,
        "registry",
        "future-conflict",
        Utc::now() + Duration::days(1),
    );

    let conflict = cache
        .put_if_unchanged(
            "registry",
            "future-conflict",
            Some(&expected),
            &json!({"revision": 3}),
            None,
            ttl,
        )
        .unwrap();

    let CacheCommit::Conflict(Some(current)) = conflict else {
        panic!("concurrent future entry must remain the raw conflict generation");
    };
    assert!(!current.fresh);
    assert_eq!(current.value, json!({"revision": 2}));
    assert_eq!(
        read_cache_entry(&cache, "registry", "future-conflict").value,
        current.value
    );
}

#[test]
fn owned_cache_clear_removes_only_known_cache_contents() {
    let temp = tempfile::tempdir().unwrap();
    let requested = temp.path().join("owned-cache");
    let cache = Cache::from_root(requested, CachePolicy::default()).unwrap();
    cache
        .put("registry", "fixture", &json!({"ok": true}), None)
        .unwrap();
    cache.put("osv/query", "fixture", &json!([]), None).unwrap();
    fs::create_dir_all(cache.root().join("offline")).unwrap();
    fs::write(cache.root().join("offline/npm.zip"), b"fixture").unwrap();
    fs::write(cache.root().join("unrelated.txt"), b"preserve me").unwrap();

    cache.clear().unwrap();

    for directory in CACHE_CONTENT_DIRECTORIES {
        assert!(!cache.root().join(directory).exists());
    }
    assert!(cache.root().join(CACHE_SENTINEL_FILE).is_file());
    assert_eq!(
        fs::read(cache.root().join("unrelated.txt")).unwrap(),
        b"preserve me"
    );
    cache.clear().unwrap();
}

#[test]
fn cache_initialization_rejects_empty_broad_and_nonowned_paths() {
    let empty = Cache::from_root(PathBuf::new(), CachePolicy::default()).unwrap_err();
    assert!(empty.to_string().contains("empty cache directory"));

    let current = fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
    let filesystem_root = current.ancestors().last().unwrap();
    let broad =
        Cache::from_root(filesystem_root.to_path_buf(), CachePolicy::default()).unwrap_err();
    assert!(broad.to_string().contains("filesystem roots"));
    assert!(
        validate_cache_scope_with(&current, &current, None)
            .unwrap_err()
            .to_string()
            .contains("current workspace")
    );

    let temp = tempfile::tempdir().unwrap();
    let fake_home = fs::canonicalize(temp.path()).unwrap();
    assert!(
        validate_cache_scope_with(&fake_home, &current, Some(fake_home.as_path()),)
            .unwrap_err()
            .to_string()
            .contains("home directory")
    );
    let nonowned = temp.path().join("nonowned");
    fs::create_dir(&nonowned).unwrap();
    let unrelated = nonowned.join("important.txt");
    fs::write(&unrelated, b"do not delete").unwrap();

    let error = Cache::from_root(nonowned.clone(), CachePolicy::default()).unwrap_err();

    assert!(error.to_string().contains("non-empty"));
    assert_eq!(fs::read(&unrelated).unwrap(), b"do not delete");
    assert!(!nonowned.join(CACHE_SENTINEL_FILE).exists());
}

#[test]
fn cache_initialization_canonicalizes_safe_path_aliases() {
    let temp = tempfile::tempdir().unwrap();
    let alias_component = temp.path().join("alias");
    fs::create_dir(&alias_component).unwrap();
    let requested = alias_component.join("..").join("cache");

    let cache = Cache::from_root(requested, CachePolicy::default()).unwrap();

    assert_eq!(
        cache.root(),
        fs::canonicalize(temp.path().join("cache")).unwrap()
    );
    assert!(cache.root().join(CACHE_SENTINEL_FILE).is_file());
}

#[test]
fn exact_default_cache_layout_can_be_migrated_to_the_ownership_sentinel() {
    let temp = tempfile::tempdir().unwrap();
    let legacy = temp.path().join("legacy-default-cache");
    fs::create_dir_all(legacy.join("osv/query")).unwrap();
    fs::create_dir(legacy.join("registry")).unwrap();
    fs::write(legacy.join("osv/query/fixture.json"), b"{}").unwrap();

    let migrated = initialize_cache_root(&legacy, true).unwrap();

    assert!(migrated.join(CACHE_SENTINEL_FILE).is_file());
    assert!(migrated.join("osv/query/fixture.json").is_file());

    let unrelated = temp.path().join("unrelated-default-cache");
    fs::create_dir(&unrelated).unwrap();
    fs::write(unrelated.join("important.txt"), b"preserve").unwrap();
    let error = initialize_cache_root(&unrelated, true).unwrap_err();
    assert!(error.to_string().contains("non-empty"));
    assert_eq!(
        fs::read(unrelated.join("important.txt")).unwrap(),
        b"preserve"
    );
    assert!(!unrelated.join(CACHE_SENTINEL_FILE).exists());
}

#[test]
fn missing_or_invalid_cache_sentinel_refuses_clear_without_deleting_data() {
    let temp = tempfile::tempdir().unwrap();
    let cache = Cache::from_root(temp.path().join("owned-cache"), CachePolicy::default()).unwrap();
    cache
        .put("registry", "fixture", &json!({"preserve": true}), None)
        .unwrap();
    let registry = cache.root().join("registry");
    fs::remove_file(cache.root().join(CACHE_SENTINEL_FILE)).unwrap();

    let missing = cache.clear().unwrap_err();

    assert!(missing.to_string().contains("missing ownership sentinel"));
    assert!(registry.is_dir());
    fs::write(
        cache.root().join(CACHE_SENTINEL_FILE),
        br#"{"schema_version":2,"owner":"depscan"}"#,
    )
    .unwrap();
    let invalid = cache.clear().unwrap_err();
    assert!(invalid.to_string().contains("unsupported owner or schema"));
    assert!(registry.is_dir());
}

#[cfg(unix)]
#[test]
fn symlink_swaps_and_symlinked_cache_content_are_refused_without_deletion() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let requested = temp.path().join("owned-cache");
    let cache = Cache::from_root(requested.clone(), CachePolicy::default()).unwrap();
    cache
        .put("registry", "fixture", &json!({"preserve": true}), None)
        .unwrap();
    let backup = temp.path().join("owned-cache-backup");
    fs::rename(cache.root(), &backup).unwrap();
    let replacement = Cache::from_root(
        temp.path().join("replacement-cache"),
        CachePolicy::default(),
    )
    .unwrap();
    replacement
        .put("registry", "victim", &json!({"important": true}), None)
        .unwrap();
    symlink(replacement.root(), &requested).unwrap();

    let swapped = cache.clear().unwrap_err();

    assert!(swapped.to_string().contains("replaced or is not real"));
    assert!(replacement.root().join("registry").is_dir());

    let content_cache =
        Cache::from_root(temp.path().join("content-cache"), CachePolicy::default()).unwrap();
    fs::create_dir(content_cache.root().join("offline")).unwrap();
    fs::write(content_cache.root().join("offline/preserve.zip"), b"keep").unwrap();
    let external = temp.path().join("external-registry");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("important.txt"), b"keep").unwrap();
    symlink(&external, content_cache.root().join("registry")).unwrap();

    let content_swap = content_cache.clear().unwrap_err();

    assert!(content_swap.to_string().contains("not a real directory"));
    assert!(content_cache.root().join("offline/preserve.zip").is_file());
    assert!(external.join("important.txt").is_file());
}
