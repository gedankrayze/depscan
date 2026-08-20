use super::*;

#[test]
fn offline_ecosystem_output_matrix() {
    for case in ECOSYSTEMS {
        let directory = tempfile::tempdir().expect("create E2E temp directory");
        let cache = directory.path().join("cache");
        initialize_cache(&cache);
        seed_empty_dump(&cache, case.dump_name);
        let fixture_root = fixture(*case);
        let before = fixture_snapshot(&fixture_root);

        let json = run_offline(&cache, *case, "json");
        assert_clean(&json, &format!("{} JSON E2E", case.fixture));
        assert_json_contract(*case, &parse_json_report(&json));

        let table = run_offline(&cache, *case, "table");
        assert_clean(&table, &format!("{} table E2E", case.fixture));
        let table = String::from_utf8(table.stdout).expect("UTF-8 table report");
        assert!(table.starts_with("depscan: "));
        assert!(table.contains(&format!("\n{} (", case.display_name)));

        let markdown = run_offline(&cache, *case, "markdown");
        assert_clean(&markdown, &format!("{} Markdown E2E", case.fixture));
        let markdown = String::from_utf8(markdown.stdout).expect("UTF-8 Markdown report");
        assert!(markdown.starts_with("# depscan report"));
        assert!(markdown.contains("## Summary"));
        assert!(markdown.contains("## Soft failures"));
        assert!(markdown.contains(&format!("| Packages | {} |", case.packages.len())));

        let summary = run_offline(&cache, *case, "summary");
        assert_clean(&summary, &format!("{} summary E2E", case.fixture));
        let summary = String::from_utf8(summary.stdout).expect("UTF-8 summary report");
        assert!(summary.starts_with(&format!(
            "depscan: {} packages | 0 vulns",
            case.packages.len()
        )));

        let sarif = run_offline(&cache, *case, "sarif");
        assert_clean(&sarif, &format!("{} SARIF E2E", case.fixture));
        let sarif = parse_json_report(&sarif);
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "depscan");
        assert!(
            sarif["runs"][0]["results"]
                .as_array()
                .is_some_and(|results| !results.is_empty()),
            "offline registry gaps must remain visible in SARIF"
        );
        assert_eq!(
            fixture_snapshot(&fixture_root),
            before,
            "{} scans changed project files",
            case.fixture
        );
    }
}

#[test]
fn offline_workspace_self_scan() {
    let directory = tempfile::tempdir().expect("create self-scan temp directory");
    let cache = directory.path().join("cache");
    initialize_cache(&cache);
    seed_empty_dump(&cache, "crates_io");

    let output = command(&cache)
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            "--ecosystem",
            "cargo",
        ])
        .arg(workspace_root())
        .output()
        .expect("run offline workspace self-scan");
    assert_clean(&output, "workspace self-scan");
    let report = parse_json_report(&output);
    let results = result_map(&report);
    for package in ["depscan-cli", "depscan-core", "depscan-parsers", "serde"] {
        assert!(results.contains_key(package), "self-scan omitted {package}");
    }
    assert!(
        results
            .values()
            .all(|result| result["package"]["ecosystem"] == "cratesio")
    );
}

#[test]
#[ignore = "opt in with DEPSCAN_RUN_LIVE=1; calls public OSV and registry APIs"]
fn live_provider_matrix_for_every_ecosystem() {
    assert_eq!(
        std::env::var("DEPSCAN_RUN_LIVE").as_deref(),
        Ok("1"),
        "set DEPSCAN_RUN_LIVE=1 to acknowledge public API access"
    );

    for case in ECOSYSTEMS {
        let directory = tempfile::tempdir().expect("create live test directory");
        let cache = directory.path().join("cache");
        initialize_cache(&cache);
        let output = Command::new(env!("CARGO_BIN_EXE_depscan"))
            .env("DEPSCAN_CACHE_DIR", &cache)
            .env("NO_COLOR", "1")
            .args([
                "scan",
                "--no-cache",
                "--format",
                "json",
                "--ecosystem",
                case.cli_name,
            ])
            .arg(fixture(*case))
            .output()
            .expect("run live depscan fixture");
        assert!(
            matches!(output.status.code(), Some(0 | 1)),
            "{} live scan failed\nstdout:\n{}\nstderr:\n{}",
            case.fixture,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report = parse_json_report(&output);
        let results = result_map(&report);
        for expected in case.packages {
            let result = results
                .get(expected.name)
                .unwrap_or_else(|| panic!("live report omitted {}", expected.name));
            if result["package"]["enrichable"] == true {
                assert!(
                    result["latest"].is_object(),
                    "{} live registry lookup did not complete: {}",
                    expected.name,
                    result["errors"]
                );
                assert_eq!(result["errors"], serde_json::json!([]));
            }
        }
        let vulnerability_count = results
            .values()
            .map(|result| result["vulns"].as_array().map_or(0, Vec::len))
            .sum::<usize>();
        eprintln!(
            "live {} evidence: {} packages, {} vulnerability records, registry enrichment complete",
            case.display_name,
            results.len(),
            vulnerability_count
        );
    }
}
