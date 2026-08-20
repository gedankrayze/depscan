use super::support::*;

#[test]
fn unsupported_project_exits_twenty() {
    let directory = TestDirectory::new("unsupported");

    let output = command(&directory.path().join("cache"))
        .args(["scan", directory.path().to_str().expect("UTF-8 path")])
        .output()
        .expect("run depscan");

    assert_exit(&output, 20);
    assert_diagnostic_only_on_stderr(&output, "no supported project detected");
}

#[test]
fn provider_hard_failure_exits_thirty() {
    let project = TestProject::rust("provider-failure");

    let output = project.run(&[
        "scan",
        "--offline",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 30);
    assert_diagnostic_only_on_stderr(&output, "provider hard failure");
}

#[test]
fn online_osv_total_outage_exits_thirty() {
    let project = TestProject::rust("online-provider-outage");

    let output = command(&project.cache)
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env_remove("NO_PROXY")
        .args([
            "scan",
            "--format",
            "json",
            project.directory.path().to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run depscan with OSV unreachable");

    assert_exit(&output, 30);
    assert_diagnostic_only_on_stderr(&output, "provider hard failure");
}

#[test]
fn future_empty_osv_query_cache_cannot_turn_a_total_outage_clean() {
    let project = TestProject::rust("future-empty-query-total-outage");
    project.seed_clean("1.0.0");
    project.set_cache_timestamp(
        "osv/query",
        QUERY_DIGEST,
        Utc::now() + chrono::Duration::days(1),
    );

    let output = command(&project.cache)
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env_remove("NO_PROXY")
        .args([
            "scan",
            "--max-cache-age",
            "1s",
            "--format",
            "json",
            project.directory.path().to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run depscan with a future-dated empty OSV query cache entry");

    assert_exit(&output, 30);
    assert_diagnostic_only_on_stderr(&output, "provider hard failure");
}

#[test]
fn future_empty_osv_query_failure_is_soft_beside_a_trustworthy_cached_result() {
    let project = TestProject::rust("future-empty-query-partial-outage");
    project.seed_clean("1.0.0");
    project.set_cache_timestamp(
        "osv/query",
        QUERY_DIGEST,
        Utc::now() + chrono::Duration::days(1),
    );
    project.add_rust_package("trusted-cache");
    project.seed_empty_osv_query("trusted-cache");

    let output = command(&project.cache)
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env_remove("NO_PROXY")
        .args([
            "scan",
            "--format",
            "json",
            project.directory.path().to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run depscan with future and trustworthy OSV query cache entries");

    assert_exit(&output, 0);
    let report = json_report(&output);
    let packages = report_packages(&report);
    let future = packages
        .iter()
        .find(|result| {
            result
                .pointer("/package/name")
                .and_then(serde_json::Value::as_str)
                == Some("demo")
        })
        .expect("future-dated package result");
    assert!(
        future
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|errors| errors.iter().any(|error| {
                error.get("provider").and_then(serde_json::Value::as_str) == Some("osv")
                    && error
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|message| message.contains("query failed"))
            }))
    );
    let trustworthy = packages
        .iter()
        .find(|result| {
            result
                .pointer("/package/name")
                .and_then(serde_json::Value::as_str)
                == Some("trusted-cache")
        })
        .expect("trustworthy cached package result");
    assert_eq!(
        trustworthy
            .get("vulns")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert!(
        trustworthy
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|errors| errors.iter().all(|error| {
                error.get("provider").and_then(serde_json::Value::as_str) != Some("osv")
            }))
    );
}

#[test]
fn online_osv_partial_outage_is_visible_without_a_false_clean_cache_entry() {
    let project = TestProject::rust("online-provider-partial-outage");
    project.seed_clean("1.0.0");
    project.add_rust_package("partial-outage");
    let failed_query_digest = sha256_hex(b"crates.io:partial-outage:1.0.0");

    let output = command(&project.cache)
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env_remove("NO_PROXY")
        .args([
            "scan",
            "--format",
            "json",
            project.directory.path().to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run depscan with one cached OSV query");

    assert_exit(&output, 0);
    let report = json_report(&output);
    let result = report_packages(&report)
        .iter()
        .find(|result| {
            result
                .pointer("/package/name")
                .and_then(serde_json::Value::as_str)
                == Some("partial-outage")
        })
        .expect("partial package result");
    assert!(
        result
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|errors| errors.iter().any(|error| {
                error.get("provider").and_then(serde_json::Value::as_str) == Some("osv")
                    && error
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|message| message.contains("query failed"))
            }))
    );
    assert!(
        !project
            .cache
            .join("osv/query")
            .join(format!("{failed_query_digest}.json"))
            .exists(),
        "a failed query must not be cached as an empty result"
    );
}

#[test]
fn malformed_cached_osv_document_is_a_hard_failure_when_no_result_is_usable() {
    let project = TestProject::rust("malformed-cached-osv-hard");
    project.seed_clean("1.0.0");
    let advisory = "RUSTSEC-MALFORMED-CACHED";
    project.seed_osv_revision("demo", advisory);
    project.seed_osv_document(
        advisory,
        r#"{
            "id":"RUSTSEC-MALFORMED-CACHED",
            "modified":"2026-08-19T00:00:00Z",
            "withdrawn":null,
            "affected":[{
                "package":{"ecosystem":"crates.io","name":"demo"},
                "versions":["1.0.0"]
            }]
        }"#,
    );

    let output = command(&project.cache)
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env_remove("NO_PROXY")
        .args([
            "scan",
            "--format",
            "json",
            project.directory.path().to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run depscan with one malformed cached OSV document");

    assert_exit(&output, 30);
    assert_diagnostic_only_on_stderr(&output, "provider hard failure");
}

#[test]
fn malformed_cached_osv_document_is_soft_beside_a_trustworthy_package() {
    let project = TestProject::rust("malformed-cached-osv-soft");
    project.seed_clean("1.0.0");
    project.add_rust_package("malformed-cached");
    let advisory = "RUSTSEC-MALFORMED-CACHED-SOFT";
    project.seed_osv_revision("malformed-cached", advisory);
    project.seed_osv_document(
        advisory,
        r#"{
            "id":"RUSTSEC-MALFORMED-CACHED-SOFT",
            "modified":"2026-08-19T00:00:00Z",
            "withdrawn":false,
            "affected":[{
                "package":{"ecosystem":"crates.io","name":"malformed-cached"},
                "versions":["1.0.0"]
            }]
        }"#,
    );

    let output = command(&project.cache)
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env_remove("NO_PROXY")
        .args([
            "scan",
            "--format",
            "json",
            project.directory.path().to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run depscan with mixed cached OSV results");

    assert_exit(&output, 0);
    let report = json_report(&output);
    let malformed = report_packages(&report)
        .iter()
        .find(|result| {
            result
                .pointer("/package/name")
                .and_then(serde_json::Value::as_str)
                == Some("malformed-cached")
        })
        .expect("malformed cached package result");
    assert!(
        malformed
            .get("vulns")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty)
    );
    assert!(
        malformed
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|errors| errors.iter().any(|error| {
                error.get("provider").and_then(serde_json::Value::as_str) == Some("osv")
                    && error
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|message| message.contains("hydration failed"))
            }))
    );
}

#[test]
fn poetry_metadata_and_nonregistry_packages_do_not_require_provider_state() {
    let directory = TestDirectory::new("poetry-nonregistry-provider-skip");
    let project = directory.path().join("project");
    let cache = directory.path().join("cache");
    fs::create_dir(&project).expect("create Poetry project");
    fs::create_dir(&cache).expect("create empty cache");
    fs::write(
        cache.join(".depscan-cache.json"),
        r#"{"schema_version":1,"owner":"depscan"}"#,
    )
    .expect("write cache ownership sentinel");
    fs::write(
        project.join("pyproject.toml"),
        r#"[tool.poetry.dependencies]
python = "^3.12"
git-dep = { git = "https://github.com/example/git-dep.git", rev = "abc123" }
private-dep = { version = "^1", source = "private" }

[[tool.poetry.source]]
name = "private"
url = "https://packages.example.invalid/simple/"
priority = "explicit"
"#,
    )
    .expect("write Poetry manifest");

    let output = command(&cache)
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            project.to_str().expect("UTF-8 project path"),
        ])
        .output()
        .expect("run provider-free Poetry scan");

    assert_exit(&output, 0);
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = json_report(&output);
    assert_eq!(
        report_package_names(&report),
        BTreeSet::from(["git-dep", "private-dep"])
    );
    assert!(
        report_packages(&report).iter().all(|result| {
            result.get("latest").is_some_and(serde_json::Value::is_null)
                && result
                    .get("vulns")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(Vec::is_empty)
                && result
                    .get("errors")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(Vec::is_empty)
        }),
        "{}",
        serde_json::to_string_pretty(&report).unwrap()
    );
}
