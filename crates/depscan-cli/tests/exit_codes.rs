use chrono::Utc;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

const QUERY_DIGEST: &str = "2f422c499305285ab2b6919c9f3a7749a0ae65f244b52b53b78ea8a3d83444c7";
const REGISTRY_DIGEST: &str = "73a7010ca3d255918cf210add4252cd48f0d933c881b68ea9bcf11cf8a400ac1";
const VULNERABILITY_DIGEST: &str =
    "4db23d5d929b343edf9ffc1e02564b51eefd8392410c14f87892d246abed1289";

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
                r#"{{"lines":[{{"vers":"1.0.0","yanked":false}},{{"vers":"{latest}","yanked":false}}]}}"#
            ),
        );
    }

    fn seed_vulnerability(&self) {
        self.seed_cache("osv/query", QUERY_DIGEST, r#"["RUSTSEC-TEST"]"#);
        self.seed_cache(
            "osv/vuln",
            VULNERABILITY_DIGEST,
            r#"{
                "id":"RUSTSEC-TEST",
                "summary":"process-test vulnerability",
                "aliases":[],
                "severity":[{
                    "type":"CVSS_V3",
                    "score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }],
                "affected":[{
                    "package":{"ecosystem":"crates.io","name":"demo"},
                    "ranges":[{
                        "type":"SEMVER",
                        "events":[{"introduced":"0"},{"fixed":"1.1.0"}]
                    }]
                }],
                "references":[]
            }"#,
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
}

fn command(cache: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_depscan"));
    command
        .env("DEPSCAN_CACHE_DIR", cache)
        .env("NO_COLOR", "1")
        .env_remove("RUST_LOG");
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
        "--config",
        missing.to_str().expect("UTF-8 path"),
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "config");
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
