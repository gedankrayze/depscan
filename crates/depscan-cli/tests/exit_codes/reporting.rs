use super::support::*;

#[test]
fn clean_scan_exits_zero_and_writes_report_to_stdout() {
    let project = TestProject::rust("clean");
    project.seed_clean("1.0.0");

    let output = project.run(&[
        "scan",
        "--format",
        "json",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 0);
    assert_report_only_on_stdout(&output);
}

#[test]
fn source_date_epoch_makes_repeated_json_scans_byte_identical() {
    let project = TestProject::rust("reproducible-json");
    project.seed_clean("1.0.0");
    let arguments = [
        "scan",
        "--format",
        "json",
        project.directory.path().to_str().expect("UTF-8 path"),
    ];

    let first = project.run_reproducible("1700000000", &arguments);
    let second = project.run_reproducible("1700000000", &arguments);

    assert_exit(&first, 0);
    assert_exit(&second, 0);
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stderr, second.stderr);
    assert!(
        String::from_utf8_lossy(&first.stdout)
            .contains("\"generated_at\": \"2023-11-14T22:13:20Z\"")
    );
}

#[test]
fn invalid_source_date_epoch_exits_ten_before_provider_access() {
    let project = TestProject::rust("invalid-source-date-epoch");

    let output = project.run_reproducible(
        "not-a-timestamp",
        &[
            "scan",
            "--offline",
            project.directory.path().to_str().expect("UTF-8 path"),
        ],
    );

    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "SOURCE_DATE_EPOCH");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("provider hard failure"));
}

#[test]
fn vulnerability_threshold_exits_one_and_writes_report_to_stdout() {
    let project = TestProject::rust("vulnerable");
    project.seed_clean("1.0.0");
    project.seed_vulnerability();

    let output = project.run(&[
        "scan",
        "--format",
        "json",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 1);
    assert_report_only_on_stdout(&output);
}

#[test]
fn active_cli_and_config_suppressions_preserve_full_audit_metadata() {
    let project = TestProject::rust("active-suppression-audit");
    project.seed_clean("1.0.0");
    project.seed_vulnerability_with_aliases(&["CVE-2099-0001"]);
    let config = project.directory.path().join("policy.toml");
    fs::write(
        &config,
        r#"[[ignore]]
id = "CVE-2099-0001"
reason = "accepted until the next release"
expires = 2099-01-01
"#,
    )
    .expect("write suppression policy");

    let output = project.run_reproducible(
        "1700000000",
        &[
            "scan",
            "--format",
            "json",
            "--ignore",
            "RUSTSEC-TEST",
            "--ignore",
            "RUSTSEC-TEST",
            "--config",
            config.to_str().expect("UTF-8 path"),
            project.directory.path().to_str().expect("UTF-8 path"),
        ],
    );

    assert_exit(&output, 0);
    assert!(output.stderr.is_empty());
    let report = json_report(&output);
    assert_eq!(
        report.pointer("/schema_version").and_then(|v| v.as_u64()),
        Some(4)
    );
    assert_eq!(
        report
            .pointer("/results/0/vulns")
            .and_then(|value| value.as_array())
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        report
            .pointer("/results/0/suppressed/0/vulnerability/id")
            .and_then(|value| value.as_str()),
        Some("RUSTSEC-TEST")
    );
    assert_eq!(
        report
            .pointer("/results/0/suppressed/0/active")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    let matches = report
        .pointer("/results/0/suppressed/0/matches")
        .and_then(|value| value.as_array())
        .expect("suppression matches");
    assert_eq!(
        matches.len(),
        2,
        "duplicate CLI rules must be canonicalized"
    );
    assert!(matches.iter().any(|matched| {
        matched
            .pointer("/matched_id")
            .and_then(|value| value.as_str())
            == Some("RUSTSEC-TEST")
            && matched.pointer("/source").and_then(|value| value.as_str()) == Some("cli")
    }));
    assert!(matches.iter().any(|matched| {
        matched
            .pointer("/matched_id")
            .and_then(|value| value.as_str())
            == Some("CVE-2099-0001")
            && matched.pointer("/source").and_then(|value| value.as_str()) == Some("config")
            && matched.pointer("/reason").and_then(|value| value.as_str())
                == Some("accepted until the next release")
            && matched.pointer("/expires").and_then(|value| value.as_str()) == Some("2099-01-01")
    }));
}

#[test]
fn expired_suppression_is_loud_and_does_not_change_failure_status() {
    let project = TestProject::rust("expired-suppression-audit");
    project.seed_clean("1.0.0");
    project.seed_vulnerability();
    let config = project.directory.path().join("expired-policy.toml");
    fs::write(
        &config,
        r#"[[ignore]]
id = "RUSTSEC-TEST"
reason = "temporary migration window"
expires = 2020-01-01
"#,
    )
    .expect("write expired suppression policy");

    let output = project.run_reproducible(
        "1700000000",
        &[
            "scan",
            "--format",
            "json",
            "--config",
            config.to_str().expect("UTF-8 path"),
            project.directory.path().to_str().expect("UTF-8 path"),
        ],
    );

    assert_exit(&output, 1);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("ignore has expired and will not be applied")
    );
    let report = json_report(&output);
    assert_eq!(
        report
            .pointer("/results/0/vulns/0/id")
            .and_then(|value| value.as_str()),
        Some("RUSTSEC-TEST")
    );
    assert_eq!(
        report
            .pointer("/results/0/suppressed/0/active")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        report
            .pointer("/results/0/suppressed/0/matches/0/state")
            .and_then(|value| value.as_str()),
        Some("expired")
    );
    assert_eq!(
        report
            .pointer("/results/0/suppressed/0/matches/0/reason")
            .and_then(|value| value.as_str()),
        Some("temporary migration window")
    );
}

#[test]
fn include_withdrawn_controls_rendering_counts_and_exit_in_every_format() {
    let project = TestProject::rust("withdrawn-advisory");
    project.seed_clean("1.0.0");
    project.seed_withdrawn_vulnerability();
    let root = project.directory.path().to_str().expect("UTF-8 path");
    let cases = [
        ("table", "RUSTSEC-TEST [WITHDRAWN]"),
        ("json", "\"withdrawn\": true"),
        ("sarif", "withdrawn advisory"),
        ("summary", "1 withdrawn"),
    ];

    for (format, included_marker) in cases {
        let excluded = project.run(&["scan", "--format", format, root]);
        assert_exit(&excluded, 0);
        assert!(excluded.stderr.is_empty());
        assert!(
            !String::from_utf8_lossy(&excluded.stdout).contains("RUSTSEC-TEST"),
            "{format} rendered a withdrawn advisory without --include-withdrawn: {}",
            String::from_utf8_lossy(&excluded.stdout)
        );

        let included = project.run(&["scan", "--format", format, "--include-withdrawn", root]);
        assert_exit(&included, 1);
        assert!(included.stderr.is_empty());
        assert!(
            String::from_utf8_lossy(&included.stdout).contains(included_marker),
            "{format} did not visibly label the included advisory: {}",
            String::from_utf8_lossy(&included.stdout)
        );
    }
}

#[test]
fn outdated_threshold_exits_two_and_writes_report_to_stdout() {
    let project = TestProject::rust("outdated");
    project.seed_clean("2.0.0");

    let output = project.run(&[
        "scan",
        "--format",
        "json",
        "--fail-on-outdated",
        "patch",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 2);
    assert_report_only_on_stdout(&output);
}

#[test]
fn yanked_current_is_reported_in_every_format_and_obeys_failure_policy() {
    let project = TestProject::rust("yanked-current");
    project.seed_yanked_current();
    let root = project.directory.path().to_str().expect("UTF-8 path");
    let cases = [
        ("table", "YANKED"),
        ("json", "\"yanked\": true"),
        ("sarif", "DEPSCAN-YANKED"),
        ("summary", "1 yanked"),
    ];

    for (format, expected) in cases {
        let output = project.run(&["scan", "--format", format, root]);
        assert_exit(&output, 0);
        assert!(output.stderr.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(expected),
            "{format} did not contain {expected:?}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    let failing = project.run(&[
        "scan",
        "--format",
        "json",
        "--fail-on-outdated",
        "major",
        root,
    ]);
    assert_exit(&failing, 2);
    assert_report_only_on_stdout(&failing);
}

#[test]
fn yanked_outdated_process_report_shows_both_signals_without_double_counting() {
    let project = TestProject::rust("yanked-outdated");
    project.seed_yanked_outdated();

    let output = project.run(&[
        "scan",
        "--format",
        "table",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 0);
    assert!(output.stderr.is_empty());
    let report = String::from_utf8_lossy(&output.stdout);
    assert_eq!(report.matches("YANKED").count(), 1);
    assert_eq!(report.matches("MAJOR").count(), 1);
    assert!(report.contains("1 outdated | 1 yanked"));
}

#[test]
fn vulnerability_exit_takes_precedence_over_outdated_exit() {
    let project = TestProject::rust("precedence");
    project.seed_clean("2.0.0");
    project.seed_vulnerability();

    let output = project.run(&[
        "scan",
        "--format",
        "json",
        "--fail-on-outdated",
        "patch",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 1);
    assert_report_only_on_stdout(&output);
}
