use super::*;

#[test]
fn offline_dump_age_handles_fresh_stale_missing_malformed_and_future_markers() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::from_root(directory.path().join("cache"), CachePolicy::default()).unwrap();
    let archive = cache.root().join("offline/npm.zip");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(&archive, b"archive fixture").unwrap();
    let marker = archive.with_extension("synced-at");
    let now = test_timestamp("2026-08-19T12:00:00Z");
    let provider = OsvOffline::new(cache.clone());

    fs::write(&marker, "2026-08-18T12:00:00Z").unwrap();
    assert_eq!(
        provider
            .validate_dump_age_at(&archive, Ecosystem::Npm, now)
            .unwrap(),
        OsvDumpAge::Current
    );

    fs::write(&marker, "2026-08-11T11:59:59Z").unwrap();
    assert!(matches!(
        provider
            .validate_dump_age_at(&archive, Ecosystem::Npm, now)
            .unwrap(),
        OsvDumpAge::Warn { age, .. } if age == Duration::seconds(8 * 24 * 60 * 60 + 1)
    ));

    let strict = OsvOffline::new(Cache {
        root: cache.root.clone(),
        policy: CachePolicy {
            read: true,
            max_age: Some(Duration::days(7)),
        },
    });
    let stale = strict
        .validate_dump_age_at(&archive, Ecosystem::Npm, now)
        .unwrap_err();
    assert!(stale.to_string().contains("exceeds --max-cache-age"));

    fs::remove_file(&marker).unwrap();
    let missing = provider
        .validate_dump_age_at(&archive, Ecosystem::Npm, now)
        .unwrap_err();
    assert!(missing.to_string().contains("missing OSV dump timestamp"));

    fs::write(&marker, "not-a-timestamp").unwrap();
    let malformed = provider
        .validate_dump_age_at(&archive, Ecosystem::Npm, now)
        .unwrap_err();
    assert!(malformed.to_string().contains("invalid OSV dump timestamp"));

    fs::write(&marker, "2026-08-19T12:00:01Z").unwrap();
    let future = provider
        .validate_dump_age_at(&archive, Ecosystem::Npm, now)
        .unwrap_err();
    assert!(future.to_string().contains("is in the future"));
}

#[test]
fn offline_dump_rejects_malformed_utf8_schema_and_truncated_entries_with_context() {
    let limits = OsvDumpLimits::production();
    let cases = [
        (
            "malformed JSON",
            archive_with_entry("TEST-MALFORMED.json", br#"{not-json}"#),
            "valid UTF-8 JSON",
        ),
        (
            "truncated JSON entry",
            archive_with_entry("TEST-TRUNCATED.json", br#"{"id":"TEST-TRUNCATED""#),
            "valid UTF-8 JSON",
        ),
        (
            "invalid UTF-8",
            archive_with_entry("TEST-UTF8.json", &[0xff, 0xfe, 0xfd]),
            "valid UTF-8 JSON",
        ),
        (
            "schema-invalid object",
            archive_with_entry("TEST-SCHEMA.json", br#"{}"#),
            "not an OSV document",
        ),
        (
            "missing affected",
            archive_with_entry(
                "TEST-MISSING-AFFECTED.json",
                br#"{"id":"TEST-MISSING-AFFECTED","modified":"2026-08-19T00:00:00Z"}"#,
            ),
            "affected must be a present array",
        ),
        (
            "malformed package identity",
            archive_with_entry(
                "TEST-MALFORMED-IDENTITY.json",
                br#"{"id":"TEST-MALFORMED-IDENTITY","modified":"2026-08-19T00:00:00Z","affected":[{"package":{"ecosystem":"npm"},"versions":["1.0.0"]}]}"#,
            ),
            "package.name must be a string",
        ),
        (
            "null withdrawn",
            archive_with_entry(
                "TEST-NULL-WITHDRAWN.json",
                br#"{"id":"TEST-NULL-WITHDRAWN","modified":"2026-08-19T00:00:00Z","withdrawn":null,"affected":[]}"#,
            ),
            "withdrawn must be an RFC 3339 string",
        ),
        (
            "trailing data",
            archive_with_entry(
                "TEST-TRAILING.json",
                br#"{"id":"TEST-TRAILING","modified":"2026-08-19T00:00:00Z"} trailing"#,
            ),
            "valid UTF-8 JSON",
        ),
    ];

    for (case, archive, expected) in cases {
        let error = scan_offline_archive(&archive, limits).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("npm.zip"), "{case}: {message}");
        assert!(message.contains("entry \"TEST-"), "{case}: {message}");
        assert!(message.contains(expected), "{case}: {message}");
    }

    let valid = valid_offline_document("TEST-TRUNCATED-ZIP", "fixture");
    let mut truncated_zip = archive_with_entry("TEST-TRUNCATED-ZIP.json", &valid);
    truncated_zip.truncate(truncated_zip.len() - 10);
    let error = scan_offline_archive(&truncated_zip, limits).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("npm.zip"), "{message}");
    assert!(message.contains("bad ZIP"), "{message}");
}

#[test]
fn offline_dump_enforces_entry_aggregate_count_and_actual_decompression_limits() {
    let bomb = valid_offline_document("TEST-BOMB", &"x".repeat(8 * 1024));
    let bomb_archive = archive_with_entries(
        &[("TEST-BOMB.json", bomb.as_slice())],
        zip::CompressionMethod::Deflated,
    );
    let mut limits = OsvDumpLimits::production();
    limits.max_entry_bytes = 1024;
    let error = scan_offline_archive(&bomb_archive, limits).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("npm.zip"), "{message}");
    assert!(message.contains("TEST-BOMB.json"), "{message}");
    assert!(message.contains("declared uncompressed"), "{message}");

    let first = valid_offline_document("TEST-AGGREGATE-1", "first");
    let second = valid_offline_document("TEST-AGGREGATE-2", "second");
    let aggregate = archive_with_entries(
        &[
            ("TEST-AGGREGATE-1.json", first.as_slice()),
            ("TEST-AGGREGATE-2.json", second.as_slice()),
        ],
        zip::CompressionMethod::Stored,
    );
    limits = OsvDumpLimits::production();
    limits.max_uncompressed_bytes = first.len() as u64 + second.len() as u64 - 1;
    let error = scan_offline_archive(&aggregate, limits).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("declared uncompressed size"), "{message}");
    assert!(message.contains("TEST-AGGREGATE-2.json"), "{message}");

    limits = OsvDumpLimits::production();
    limits.max_entries = 1;
    let error = scan_offline_archive(&aggregate, limits).unwrap_err();
    assert!(error.to_string().contains("entry count exceeds 1"));

    limits = OsvDumpLimits::production();
    limits.max_compressed_bytes = aggregate.len() as u64 - 1;
    let error = scan_offline_archive(&aggregate, limits).unwrap_err();
    assert!(error.to_string().contains("compressed size exceeds"));

    let actual = valid_offline_document("TEST-ACTUAL", "forged declared size");
    let mut forged = archive_with_entry("TEST-ACTUAL.json", &actual);
    let central_header = forged
        .windows(4)
        .rposition(|window| window == b"PK\x01\x02")
        .unwrap();
    let forged_declared_size = u32::try_from(actual.len() - 2).unwrap();
    forged[central_header + 24..central_header + 28]
        .copy_from_slice(&forged_declared_size.to_le_bytes());
    limits = OsvDumpLimits::production();
    limits.max_entry_bytes = actual.len() as u64 - 1;
    let error = scan_offline_archive(&forged, limits).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("TEST-ACTUAL.json"), "{message}");
    assert!(message.contains("actual uncompressed"), "{message}");
}

#[test]
fn offline_dump_accepts_a_valid_empty_ecosystem_archive() {
    let archive = archive_with_entries(&[], zip::CompressionMethod::Stored);
    let result = scan_offline_archive(&archive, OsvDumpLimits::production()).unwrap();
    assert_eq!(result.len(), 1);
    assert!(result.values().all(Vec::is_empty));
}

#[test]
fn offline_registry_reuses_valid_cached_metadata_for_every_ecosystem() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::from_root(directory.path().join("cache"), CachePolicy::default()).unwrap();
    let provider = RegistryOffline::new(cache.clone());
    let now = test_timestamp("2026-08-19T12:00:00Z");
    let stored_at = now - Duration::hours(1);
    let fixtures = [
        (
            Package::new(
                Ecosystem::Npm,
                "npm-demo",
                "1.0.0",
                PathBuf::from("package-lock.json"),
            ),
            json!({"dist-tags": {"latest": "2.0.0"}}),
        ),
        (
            Package::new(
                Ecosystem::PyPI,
                "pypi-demo",
                "1.0.0",
                PathBuf::from("uv.lock"),
            ),
            json!({"releases": {
                "1.0.0": [{"yanked": false}],
                "2.0.0": [{"yanked": false}]
            }}),
        ),
        (
            Package::new(
                Ecosystem::NuGet,
                "NuGet.Demo",
                "1.0.0",
                PathBuf::from("packages.lock.json"),
            ),
            json!({"versions": ["1.0.0", "2.0.0"]}),
        ),
        (
            Package::new(
                Ecosystem::CratesIo,
                "crate-demo",
                "1.0.0",
                PathBuf::from("Cargo.lock"),
            ),
            json!({
                "schema_version": CRATES_IO_INDEX_CACHE_SCHEMA_VERSION,
                "entries": [
                    {"name": "crate-demo", "vers": "1.0.0", "yanked": false},
                    {"name": "crate-demo", "vers": "2.0.0", "yanked": false}
                ]
            }),
        ),
    ];

    for (package, value) in fixtures {
        write_cache_entry(
            &cache,
            "registry",
            &RegistryOffline::cache_key(&package),
            &CacheEntry {
                stored_at,
                etag: None,
                value,
            },
        );
        let latest = provider.latest_at(&package, now).unwrap();
        assert_eq!(latest.latest_stable, "2.0.0");
        assert_eq!(latest.staleness, depscan_core::Staleness::Major);
    }
}

#[test]
fn offline_registry_reports_cache_age_and_integrity_failures_without_network() {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::from_root(directory.path().join("cache"), CachePolicy::default()).unwrap();
    let now = test_timestamp("2026-08-19T12:00:00Z");
    let package = Package::new(
        Ecosystem::Npm,
        "offline-demo",
        "1.0.0",
        PathBuf::from("package-lock.json"),
    );
    let key = RegistryOffline::cache_key(&package);
    let value = json!({"dist-tags": {"latest": "2.0.0"}});

    write_cache_entry(
        &cache,
        "registry",
        &key,
        &CacheEntry {
            stored_at: now - Duration::days(2),
            etag: None,
            value: value.clone(),
        },
    );
    let default_provider = RegistryOffline::new(cache.clone());
    let stale = default_provider.latest_at(&package, now).unwrap_err();
    assert!(stale.to_string().contains("cached entry is stale"));

    let tolerant_provider = RegistryOffline::new(Cache {
        root: cache.root.clone(),
        policy: CachePolicy {
            read: true,
            max_age: Some(Duration::days(7)),
        },
    });
    assert_eq!(
        tolerant_provider
            .latest_at(&package, now)
            .unwrap()
            .latest_stable,
        "2.0.0"
    );

    let missing_package = Package::new(
        Ecosystem::Npm,
        "missing-demo",
        "1.0.0",
        PathBuf::from("package-lock.json"),
    );
    let missing = default_provider
        .latest_at(&missing_package, now)
        .unwrap_err();
    assert!(missing.to_string().contains("no cached entry exists"));

    let path = cache.filename("registry", &key);
    fs::write(&path, b"not JSON").unwrap();
    let corrupt = default_provider.latest_at(&package, now).unwrap_err();
    assert!(corrupt.to_string().contains("cached entry is corrupt"));

    write_cache_entry(
        &cache,
        "registry",
        &key,
        &CacheEntry {
            stored_at: now + Duration::seconds(1),
            etag: None,
            value,
        },
    );
    let future = default_provider.latest_at(&package, now).unwrap_err();
    assert!(future.to_string().contains("timestamp is in the future"));

    let disabled = RegistryOffline::new(Cache {
        root: cache.root.clone(),
        policy: CachePolicy {
            read: false,
            max_age: None,
        },
    })
    .latest_at(&package, now)
    .unwrap_err();
    assert!(disabled.to_string().contains("disabled by --no-cache"));
}
