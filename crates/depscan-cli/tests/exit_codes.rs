use chrono::Utc;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::os::unix::fs::symlink as symlink_file;
#[cfg(windows)]
use std::os::windows::fs::symlink_file;

const QUERY_DIGEST: &str = "2f422c499305285ab2b6919c9f3a7749a0ae65f244b52b53b78ea8a3d83444c7";
const REGISTRY_DIGEST: &str = "73a7010ca3d255918cf210add4252cd48f0d933c881b68ea9bcf11cf8a400ac1";
const VULNERABILITY_DIGEST: &str =
    "12c66ec82798932e9795db87745d1ac1cebf373cee0ffe9cbd57b2533e2f4530";

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "depscan-cli-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove isolated test directory");
    }
}

struct TestProject {
    directory: TestDirectory,
    cache: PathBuf,
}

impl TestProject {
    fn rust(label: &str) -> Self {
        let directory = TestDirectory::new(label);
        let cache = directory.path().join("cache");
        fs::create_dir(&cache).expect("create cache directory");
        fs::write(
            cache.join(".depscan-cache.json"),
            r#"{"schema_version":1,"owner":"depscan"}"#,
        )
        .expect("write cache ownership sentinel");
        fs::write(
            directory.path().join("Cargo.lock"),
            r#"version = 3

[[package]]
name = "demo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
"#,
        )
        .expect("write Cargo.lock fixture");
        Self { directory, cache }
    }

    fn seed_clean(&self, latest: &str) {
        self.seed_cache("osv/query", QUERY_DIGEST, "[]");
        self.seed_cache(
            "registry",
            REGISTRY_DIGEST,
            &format!(
                r#"{{"schema_version":1,"entries":[{{"name":"demo","vers":"1.0.0","yanked":false}},{{"name":"demo","vers":"{latest}","yanked":false}}]}}"#
            ),
        );
    }

    fn seed_yanked_current(&self) {
        self.seed_cache("osv/query", QUERY_DIGEST, "[]");
        self.seed_cache(
            "registry",
            REGISTRY_DIGEST,
            r#"{"schema_version":1,"entries":[{"name":"demo","vers":"0.9.0","yanked":false},{"name":"demo","vers":"1.0.0","yanked":true}]}"#,
        );
    }

    fn seed_yanked_outdated(&self) {
        self.seed_cache("osv/query", QUERY_DIGEST, "[]");
        self.seed_cache(
            "registry",
            REGISTRY_DIGEST,
            r#"{"schema_version":1,"entries":[{"name":"demo","vers":"1.0.0","yanked":true},{"name":"demo","vers":"2.0.0","yanked":false}]}"#,
        );
    }

    fn seed_vulnerability(&self) {
        self.seed_vulnerability_record(false, &[]);
    }

    fn seed_vulnerability_with_aliases(&self, aliases: &[&str]) {
        self.seed_vulnerability_record(false, aliases);
    }

    fn seed_withdrawn_vulnerability(&self) {
        self.seed_vulnerability_record(true, &[]);
    }

    fn seed_vulnerability_record(&self, withdrawn: bool, aliases: &[&str]) {
        self.seed_cache(
            "osv/query",
            QUERY_DIGEST,
            r#"[{"id":"RUSTSEC-TEST","modified":"2026-08-19T00:00:00Z"}]"#,
        );
        let withdrawn_field = if withdrawn {
            r#""withdrawn":"2026-08-19T00:00:00Z","#
        } else {
            ""
        };
        let aliases = serde_json::to_string(aliases).expect("serialize aliases");
        self.seed_cache(
            "osv/vuln",
            VULNERABILITY_DIGEST,
            &format!(
                r#"{{
                "id":"RUSTSEC-TEST",
                "modified":"2026-08-19T00:00:00Z",
                {withdrawn_field}
                "summary":"process-test vulnerability",
                "aliases":{aliases},
                "severity":[{{
                    "type":"CVSS_V3",
                    "score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }}],
                "affected":[{{
                    "package":{{"ecosystem":"crates.io","name":"demo"}},
                    "ranges":[{{
                        "type":"SEMVER",
                        "events":[{{"introduced":"0"}},{{"fixed":"1.1.0"}}]
                    }}]
                }}],
                "references":[]
            }}"#
            ),
        );
    }

    fn seed_cache(&self, namespace: &str, digest: &str, value: &str) {
        let directory = self.cache.join(namespace);
        fs::create_dir_all(&directory).expect("create cache namespace");
        let entry = format!(
            r#"{{"stored_at":"{}","etag":null,"value":{value}}}"#,
            Utc::now().to_rfc3339()
        );
        fs::write(directory.join(format!("{digest}.json")), entry).expect("write cache fixture");
    }

    fn run(&self, arguments: &[&str]) -> Output {
        command(&self.cache)
            .args(arguments)
            .output()
            .expect("run depscan")
    }

    fn run_reproducible(&self, epoch: &str, arguments: &[&str]) -> Output {
        command(&self.cache)
            .env("SOURCE_DATE_EPOCH", epoch)
            .args(arguments)
            .output()
            .expect("run reproducible depscan")
    }
}

fn command(cache: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_depscan"));
    command
        .env("DEPSCAN_CACHE_DIR", cache)
        .env("NO_COLOR", "1")
        .env_remove("RUST_LOG")
        .env_remove("SOURCE_DATE_EPOCH");
    command
}

fn assert_exit(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_report_only_on_stdout(output: &Output) {
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\"schema_version\""),
        "stdout did not contain the JSON report: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn json_report(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not a JSON report: {error}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn assert_diagnostic_only_on_stderr(output: &Output, expected: &str) {
    assert!(
        output.stdout.is_empty(),
        "unexpected stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected),
        "stderr did not contain {expected:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_config_preflight_failure(output: &Output, path: &Path, expected: &str) {
    assert_exit(output, 10);
    assert_diagnostic_only_on_stderr(output, expected);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&path.to_string_lossy().into_owned()),
        "stderr did not name config path {}: {stderr}",
        path.display()
    );
    assert!(
        !stderr.contains("provider hard failure") && !stderr.contains("missing OSV dump"),
        "config validation reached provider access: {stderr}"
    );
}

#[test]
fn requirements_escape_exits_ten_before_provider_access() {
    let directory = TestDirectory::new("requirements-escape");
    let project = directory.path().join("project");
    let cache = directory.path().join("cache");
    let outside = directory.path().join("outside.txt");
    let secret = "outside-requirements-secret==9.9.9";
    fs::create_dir(&project).expect("create Python project");
    fs::write(project.join("requirements.txt"), "-r ../outside.txt\n")
        .expect("write root requirements");
    fs::write(&outside, secret).expect("write outside requirements");

    let output = command(&cache)
        .args([
            "scan",
            "--offline",
            project.to_str().expect("UTF-8 project path"),
        ])
        .output()
        .expect("run depscan");

    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "outside scan root");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requirements include chain"));
    assert!(stderr.contains("outside.txt"));
    assert!(!stderr.contains(secret));
    assert!(
        !stderr.contains("missing OSV dump") && !stderr.contains("provider"),
        "requirements validation reached provider access: {stderr}"
    );
}

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
        Some(2)
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

#[test]
fn unknown_option_exits_ten_and_writes_clap_diagnostic_to_stderr() {
    let directory = TestDirectory::new("unknown-option");

    let output = command(&directory.path().join("cache"))
        .arg("--definitely-unknown")
        .output()
        .expect("run depscan");

    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "unexpected argument");
}

#[test]
fn scan_help_documents_the_config_symlink_policy() {
    let directory = TestDirectory::new("config-help");

    let output = command(&directory.path().join("cache"))
        .args(["scan", "--help"])
        .output()
        .expect("run depscan");

    assert_exit(&output, 0);
    assert!(output.stderr.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("must be a readable regular file; symbolic links are rejected")
    );
}

#[test]
fn missing_scan_path_exits_ten() {
    let directory = TestDirectory::new("missing-path");
    let missing = directory.path().join("not-there");

    let output = command(&directory.path().join("cache"))
        .args(["scan", missing.to_str().expect("UTF-8 path")])
        .output()
        .expect("run depscan");

    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "is not a directory");
}

#[test]
fn missing_explicit_config_exits_ten() {
    let project = TestProject::rust("missing-config");
    let missing = project.directory.path().join("missing.toml");

    let output = project.run(&[
        "scan",
        "--offline",
        "--config",
        missing.to_str().expect("UTF-8 path"),
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_config_preflight_failure(&output, &missing, "does not exist");
}

#[test]
fn absent_implicit_config_is_allowed_and_verbose_origin_is_reported() {
    let project = TestProject::rust("absent-implicit-config");
    project.seed_clean("1.0.0");
    let implicit = project.directory.path().join("depscan.toml");

    let output = project.run(&[
        "scan",
        "--verbose",
        "--format",
        "json",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 0);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\"schema_version\""),
        "stdout did not contain report: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("configuration file not found; using defaults"));
    assert!(stderr.contains("origin=\"implicit-default\""));
    assert!(stderr.contains(&implicit.to_string_lossy().into_owned()));
}

#[test]
fn explicit_config_directory_exits_ten_before_provider_access() {
    let project = TestProject::rust("config-directory");
    let config = project.directory.path().join("config-directory");
    fs::create_dir(&config).expect("create config directory");

    let output = project.run(&[
        "scan",
        "--offline",
        "--config",
        config.to_str().expect("UTF-8 path"),
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_config_preflight_failure(&output, &config, "not a regular file");
}

#[test]
fn explicit_config_read_failure_exits_ten_before_provider_access() {
    let project = TestProject::rust("config-read-failure");
    let config = project.directory.path().join("unreadable.toml");
    // Invalid UTF-8 forces read_to_string to fail on every supported platform. Permission bits
    // are not portable and can be bypassed when a test runner has elevated privileges.
    fs::write(&config, [0xff, 0xfe, 0xfd]).expect("write non-UTF-8 config");

    let output = project.run(&[
        "scan",
        "--offline",
        "--config",
        config.to_str().expect("UTF-8 path"),
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_config_preflight_failure(&output, &config, "reading config");
}

#[cfg(any(unix, windows))]
#[test]
fn explicit_config_symlink_is_rejected_before_provider_access() {
    let project = TestProject::rust("config-symlink");
    let target = project.directory.path().join("real-config.toml");
    let config = project.directory.path().join("linked-config.toml");
    fs::write(&target, "fail-on = \"never\"\n").expect("write symlink target");
    if let Err(error) = symlink_file(&target, &config) {
        #[cfg(windows)]
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            // Windows requires either Developer Mode or symlink privilege. The implementation is
            // platform-independent; skip only when the host cannot construct the fixture.
            return;
        }
        panic!("create config symlink: {error}");
    }

    let output = project.run(&[
        "scan",
        "--offline",
        "--config",
        config.to_str().expect("UTF-8 path"),
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_config_preflight_failure(&output, &config, "symbolic link");
}

#[test]
fn valid_explicit_config_is_loaded_and_verbose_origin_does_not_leak_contents() {
    let project = TestProject::rust("valid-explicit-config");
    project.seed_clean("1.0.0");
    let config = project.directory.path().join("policy.toml");
    let secret_reason = "internal-policy-reason-must-not-be-logged";
    fs::write(
        &config,
        format!(
            "fail-on = \"never\"\n\n[[ignore]]\nid = \"TEST-ID\"\nreason = \"{secret_reason}\"\n"
        ),
    )
    .expect("write valid explicit config");

    let output = project.run(&[
        "scan",
        "--verbose",
        "--format",
        "json",
        "--config",
        config.to_str().expect("UTF-8 path"),
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 0);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\"schema_version\""),
        "stdout did not contain report: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("configuration loaded"));
    assert!(stderr.contains("origin=\"explicit\""));
    assert!(stderr.contains(&config.to_string_lossy().into_owned()));
    assert!(!stderr.contains(secret_reason));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret_reason));
}

#[test]
fn malformed_config_exits_ten() {
    let project = TestProject::rust("malformed-config");
    fs::write(project.directory.path().join("depscan.toml"), "fail-on = [")
        .expect("write malformed config");

    let output = project.run(&[
        "scan",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "invalid config");
}

#[test]
fn invalid_config_value_exits_ten() {
    let project = TestProject::rust("invalid-config-value");
    fs::write(
        project.directory.path().join("depscan.toml"),
        "fail-on = \"extreme\"\n",
    )
    .expect("write invalid config value");

    let output = project.run(&[
        "scan",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "invalid threshold");
}

#[test]
fn invalid_cli_value_exits_ten_before_project_detection() {
    let directory = TestDirectory::new("invalid-cli-value");

    let output = command(&directory.path().join("cache"))
        .args([
            "scan",
            "--max-cache-age",
            "tomorrow",
            directory.path().to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run depscan");

    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "duration");
}

#[test]
fn invalid_output_path_exits_ten_before_provider_access() {
    let project = TestProject::rust("invalid-output-path");
    let output = project.directory.path().join("missing").join("report.json");

    let result = project.run(&[
        "scan",
        "--output",
        output.to_str().expect("UTF-8 path"),
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&result, 10);
    assert_diagnostic_only_on_stderr(&result, "output directory");
}

#[test]
fn malformed_project_input_exits_ten() {
    let project = TestProject::rust("malformed-lockfile");
    fs::write(project.directory.path().join("Cargo.lock"), "[[package]")
        .expect("write malformed lockfile");

    let output = project.run(&[
        "scan",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "failed to parse");
}

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
fn cache_clear_preserves_the_owned_root_and_unrelated_files() {
    let project = TestProject::rust("safe-cache-clear");
    project.seed_clean("1.0.0");
    let unrelated = project.cache.join("unrelated.txt");
    fs::write(&unrelated, b"preserve me").expect("write unrelated cache-root file");

    let output = project.run(&["cache", "clear"]);

    assert_exit(&output, 0);
    assert!(String::from_utf8_lossy(&output.stdout).contains("cache cleared:"));
    assert!(project.cache.join(".depscan-cache.json").is_file());
    assert_eq!(fs::read(&unrelated).unwrap(), b"preserve me");
    assert!(!project.cache.join("osv").exists());
    assert!(!project.cache.join("registry").exists());
}
