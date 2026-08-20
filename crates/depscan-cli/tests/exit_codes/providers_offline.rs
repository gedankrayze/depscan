use super::support::*;

#[test]
fn malformed_offline_advisory_cannot_produce_a_clean_report() {
    let project = TestProject::rust("malformed-offline-advisory");
    seed_malformed_cargo_dump(&project.cache);

    let output = project.run(&[
        "scan",
        "--offline",
        "--format",
        "json",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 30);
    assert_diagnostic_only_on_stderr(&output, "provider hard failure");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("crates_io.zip"), "{stderr}");
    assert!(stderr.contains("RUSTSEC-MALFORMED.json"), "{stderr}");
    assert!(stderr.contains("valid UTF-8 JSON"), "{stderr}");
}

#[test]
fn malformed_offline_osv_security_fields_cannot_produce_a_clean_report() {
    let cases = [
        (
            "missing-affected",
            "RUSTSEC-MISSING-AFFECTED.json",
            br#"{"id":"RUSTSEC-MISSING-AFFECTED","modified":"2026-08-19T00:00:00Z"}"#.as_slice(),
            "affected must be a present array",
        ),
        (
            "malformed-package",
            "RUSTSEC-MALFORMED-PACKAGE.json",
            br#"{"id":"RUSTSEC-MALFORMED-PACKAGE","modified":"2026-08-19T00:00:00Z","affected":[{"package":{"ecosystem":"crates.io"},"versions":["1.0.0"]}]}"#.as_slice(),
            "package.name must be a string",
        ),
        (
            "null-withdrawn",
            "RUSTSEC-NULL-WITHDRAWN.json",
            br#"{"id":"RUSTSEC-NULL-WITHDRAWN","modified":"2026-08-19T00:00:00Z","withdrawn":null,"affected":[]}"#.as_slice(),
            "withdrawn must be an RFC 3339 string",
        ),
        (
            "boolean-withdrawn",
            "RUSTSEC-BOOLEAN-WITHDRAWN.json",
            br#"{"id":"RUSTSEC-BOOLEAN-WITHDRAWN","modified":"2026-08-19T00:00:00Z","withdrawn":false,"affected":[]}"#.as_slice(),
            "withdrawn must be an RFC 3339 string",
        ),
    ];

    for (case, entry, contents, expected) in cases {
        let project = TestProject::rust(&format!("offline-osv-{case}"));
        seed_cargo_dump_entry(&project.cache, entry, contents);

        let output = project.run(&[
            "scan",
            "--offline",
            "--format",
            "json",
            project.directory.path().to_str().expect("UTF-8 path"),
        ]);

        assert_exit(&output, 30);
        assert_diagnostic_only_on_stderr(&output, "provider hard failure");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected),
            "{case}: expected {expected:?}, got {stderr}"
        );
    }
}

#[test]
fn offline_scan_uses_registry_cache_with_network_explicitly_denied() {
    let project = TestProject::rust("offline-registry-network-deny");
    project.seed_clean("2.0.0");
    project.seed_empty_offline_dump();

    let output = command(&project.cache)
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env_remove("NO_PROXY")
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            project.directory.path().to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run offline depscan with network denied");

    assert_exit(&output, 0);
    assert!(output.stderr.is_empty());
    let report = json_report(&output);
    let result = &report_packages(&report)[0];
    assert_eq!(
        result
            .pointer("/latest/latest_stable")
            .and_then(serde_json::Value::as_str),
        Some("2.0.0")
    );
    assert_eq!(
        result
            .pointer("/latest/staleness")
            .and_then(serde_json::Value::as_str),
        Some("major")
    );
    assert_eq!(
        result
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
}

#[test]
fn offline_registry_stale_and_missing_entries_are_unknown_with_reasons() {
    let stale = TestProject::rust("offline-registry-stale");
    stale.seed_clean("2.0.0");
    stale.seed_empty_offline_dump();
    stale.set_cache_timestamp(
        "registry",
        REGISTRY_DIGEST,
        Utc::now() - chrono::Duration::days(2),
    );

    let stale_output = stale.run(&[
        "scan",
        "--offline",
        "--format",
        "json",
        stale.directory.path().to_str().expect("UTF-8 path"),
    ]);
    assert_exit(&stale_output, 0);
    let stale_report = json_report(&stale_output);
    let stale_result = &report_packages(&stale_report)[0];
    assert_eq!(
        stale_result
            .pointer("/latest/staleness")
            .and_then(serde_json::Value::as_str),
        Some("unknown")
    );
    assert!(
        stale_result
            .pointer("/errors/0/message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|message| message.contains("cached entry is stale"))
    );

    let tolerated = stale.run(&[
        "scan",
        "--offline",
        "--max-cache-age",
        "7d",
        "--format",
        "json",
        stale.directory.path().to_str().expect("UTF-8 path"),
    ]);
    assert_exit(&tolerated, 0);
    let tolerated_report = json_report(&tolerated);
    assert_eq!(
        report_packages(&tolerated_report)[0]
            .pointer("/latest/latest_stable")
            .and_then(serde_json::Value::as_str),
        Some("2.0.0")
    );

    let missing = TestProject::rust("offline-registry-missing");
    missing.seed_empty_offline_dump();
    let missing_output = missing.run(&[
        "scan",
        "--offline",
        "--format",
        "json",
        missing.directory.path().to_str().expect("UTF-8 path"),
    ]);
    assert_exit(&missing_output, 0);
    let missing_report = json_report(&missing_output);
    let missing_result = &report_packages(&missing_report)[0];
    assert_eq!(
        missing_result
            .pointer("/latest/staleness")
            .and_then(serde_json::Value::as_str),
        Some("unknown")
    );
    assert!(
        missing_result
            .pointer("/errors/0/message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|message| message.contains("no cached entry exists"))
    );
}

#[test]
fn offline_dump_warns_after_seven_days_and_max_age_rejects_it() {
    let project = TestProject::rust("offline-dump-age");
    project.seed_clean("1.0.0");
    project.seed_empty_offline_dump();
    let marker = project.cache.join("offline/crates_io.synced-at");
    fs::write(
        &marker,
        (Utc::now() - chrono::Duration::days(8)).to_rfc3339(),
    )
    .expect("age offline marker");

    let warning = project.run(&[
        "scan",
        "--offline",
        "--format",
        "json",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);
    assert_exit(&warning, 0);
    assert!(
        String::from_utf8_lossy(&warning.stderr)
            .contains("older than the default seven-day warning age")
    );

    let rejected = project.run(&[
        "scan",
        "--offline",
        "--max-cache-age",
        "7d",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);
    assert_exit(&rejected, 30);
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(stderr.contains("exceeds --max-cache-age"));
    assert!(stderr.contains("depscan sync"));
}
