use chrono::Utc;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Write,
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

    fn add_rust_package(&self, name: &str) {
        let mut lockfile = fs::OpenOptions::new()
            .append(true)
            .open(self.directory.path().join("Cargo.lock"))
            .expect("open Cargo.lock fixture");
        writeln!(
            lockfile,
            r#"
[[package]]
name = "{name}"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1111111111111111111111111111111111111111111111111111111111111111""#
        )
        .expect("append Cargo.lock package");
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

    fn seed_empty_offline_dump(&self) {
        seed_empty_cargo_dump(&self.cache);
    }

    fn set_cache_timestamp(&self, namespace: &str, digest: &str, timestamp: chrono::DateTime<Utc>) {
        let path = self.cache.join(namespace).join(format!("{digest}.json"));
        let mut entry: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read cache fixture"))
                .expect("decode cache fixture");
        entry["stored_at"] = serde_json::Value::String(timestamp.to_rfc3339());
        fs::write(path, serde_json::to_vec(&entry).unwrap()).expect("update cache timestamp");
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

    fn seed_osv_revision(&self, package_name: &str, advisory_id: &str) {
        let query_digest = sha256_hex(format!("crates.io:{package_name}:1.0.0").as_bytes());
        self.seed_cache(
            "osv/query",
            &query_digest,
            &format!(r#"[{{"id":"{advisory_id}","modified":"2026-08-19T00:00:00Z"}}]"#),
        );
    }

    fn seed_osv_document(&self, advisory_id: &str, document: &str) {
        let hydration_digest = sha256_hex(format!("{advisory_id}@2026-08-19T00:00:00Z").as_bytes());
        self.seed_cache("osv/vuln", &hydration_digest, document);
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

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn assert_stdout_snapshot(output: &Output, expected_sha256: &str) {
    assert_exit(output, 0);
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        sha256_hex(&output.stdout),
        expected_sha256,
        "stdout snapshot changed:\n{}",
        String::from_utf8_lossy(&output.stdout)
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

fn python_fixture(case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../depscan-parsers/tests/fixtures/python")
        .join(case)
}

fn lock_schema_fixture(format: &str, case: &str, file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../depscan-parsers/tests/fixtures/schema-validation")
        .join(format)
        .join(case)
        .join(file)
}

fn seed_empty_pypi_dump(cache: &Path) {
    seed_empty_osv_dump(cache, "PyPI");
}

fn seed_empty_cargo_dump(cache: &Path) {
    seed_empty_osv_dump(cache, "crates_io");
}

fn seed_empty_osv_dump(cache: &Path, ecosystem: &str) {
    fs::create_dir_all(cache).expect("create cache directory");
    fs::write(
        cache.join(".depscan-cache.json"),
        r#"{"schema_version":1,"owner":"depscan"}"#,
    )
    .expect("write cache ownership sentinel");
    let offline = cache.join("offline");
    fs::create_dir_all(&offline).expect("create offline cache directory");
    zip::ZipWriter::new(
        fs::File::create(offline.join(format!("{ecosystem}.zip"))).expect("create offline dump"),
    )
    .finish()
    .expect("finish empty offline dump");
    fs::write(
        offline.join(format!("{ecosystem}.synced-at")),
        Utc::now().to_rfc3339(),
    )
    .expect("write offline dump timestamp");
}

fn seed_malformed_cargo_dump(cache: &Path) {
    seed_cargo_dump_entry(
        cache,
        "RUSTSEC-MALFORMED.json",
        br#"{"id":"RUSTSEC-MALFORMED""#,
    );
}

fn seed_cargo_dump_entry(cache: &Path, name: &str, contents: &[u8]) {
    let offline = cache.join("offline");
    fs::create_dir_all(&offline).expect("create offline cache directory");
    let mut archive = zip::ZipWriter::new(
        fs::File::create(offline.join("crates_io.zip")).expect("create offline dump"),
    );
    archive
        .start_file(name, zip::write::SimpleFileOptions::default())
        .expect("start malformed advisory entry");
    archive
        .write_all(contents)
        .expect("write offline advisory entry");
    archive.finish().expect("finish malformed offline dump");
    fs::write(offline.join("crates_io.synced-at"), Utc::now().to_rfc3339())
        .expect("write offline dump timestamp");
}

fn report_packages(report: &serde_json::Value) -> &[serde_json::Value] {
    report
        .get("results")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .expect("JSON report results")
}

fn report_package_names(report: &serde_json::Value) -> BTreeSet<&str> {
    report_packages(report)
        .iter()
        .map(|result| {
            result
                .pointer("/package/name")
                .and_then(serde_json::Value::as_str)
                .expect("reported package name")
        })
        .collect()
}

#[test]
fn python_cli_filters_use_uv_and_poetry_provenance() {
    for (case, expected_direct, expected_production) in [
        (
            "uv-current",
            [
                "custom-registry",
                "dev-direct",
                "directory-direct",
                "editable-direct",
                "git-direct",
                "optional-direct",
                "path-direct",
                "runtime-direct",
                "url-direct",
            ]
            .as_slice(),
            [
                "custom-registry",
                "directory-direct",
                "editable-direct",
                "git-direct",
                "optional-direct",
                "optional-transitive",
                "path-direct",
                "runtime-direct",
                "runtime-transitive",
                "shared-transitive",
                "url-direct",
            ]
            .as_slice(),
        ),
        (
            "poetry-current",
            [
                "custom-registry",
                "dev-direct",
                "directory-direct",
                "editable-direct",
                "file-direct",
                "git-direct",
                "optional-direct",
                "runtime-direct",
                "url-direct",
            ]
            .as_slice(),
            [
                "custom-registry",
                "directory-direct",
                "editable-direct",
                "file-direct",
                "git-direct",
                "optional-direct",
                "runtime-direct",
                "runtime-transitive",
                "shared-transitive",
                "url-direct",
            ]
            .as_slice(),
        ),
    ] {
        let directory = TestDirectory::new(&format!("python-filter-{case}"));
        let cache = directory.path().join("cache");
        seed_empty_pypi_dump(&cache);
        let fixture = python_fixture(case);

        let direct = command(&cache)
            .args([
                "scan",
                "--offline",
                "--format",
                "json",
                "--direct-only",
                fixture.to_str().expect("UTF-8 fixture path"),
            ])
            .output()
            .expect("run direct-only Python scan");
        assert_exit(&direct, 0);
        let report = json_report(&direct);
        let packages = report_packages(&report);
        assert!(packages.iter().all(|result| {
            result
                .pointer("/package/direct")
                .and_then(|value| value.as_bool())
                == Some(true)
                && result
                    .pointer("/package/direct_known")
                    .and_then(|value| value.as_bool())
                    == Some(true)
        }));
        assert_eq!(
            report_package_names(&report),
            expected_direct.iter().copied().collect()
        );

        let production = command(&cache)
            .args([
                "scan",
                "--offline",
                "--format",
                "json",
                "--no-dev",
                fixture.to_str().expect("UTF-8 fixture path"),
            ])
            .output()
            .expect("run no-dev Python scan");
        assert_exit(&production, 0);
        let report = json_report(&production);
        let packages = report_packages(&report);
        assert!(packages.iter().all(|result| {
            result
                .pointer("/package/dev")
                .and_then(|value| value.as_bool())
                == Some(false)
        }));
        assert_eq!(
            report_package_names(&report),
            expected_production.iter().copied().collect()
        );
    }
}

#[test]
fn direct_only_retains_poetry_packages_with_unknown_directness() {
    let directory = TestDirectory::new("poetry-unknown-directness");
    let project = directory.path().join("project");
    let cache = directory.path().join("cache");
    fs::create_dir(&project).expect("create Poetry project");
    fs::copy(
        python_fixture("poetry-current").join("poetry.lock"),
        project.join("poetry.lock"),
    )
    .expect("copy Poetry lockfile without its manifest");
    seed_empty_pypi_dump(&cache);

    let output = command(&cache)
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            "--direct-only",
            project.to_str().expect("UTF-8 project path"),
        ])
        .output()
        .expect("run Poetry scan with unknown directness");

    assert_exit(&output, 0);
    let report = json_report(&output);
    let packages = report_packages(&report);
    assert_eq!(packages.len(), 12);
    assert!(packages.iter().all(|result| {
        result
            .pointer("/package/direct_known")
            .and_then(|value| value.as_bool())
            == Some(false)
    }));
}

#[test]
fn pipfile_lock_cli_filters_use_manifest_directness_and_lock_scope() {
    let directory = TestDirectory::new("pipfile-lock-filters");
    let cache = directory.path().join("cache");
    seed_empty_pypi_dump(&cache);
    let fixture = python_fixture("pipenv-current");

    let direct = command(&cache)
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            "--direct-only",
            fixture.to_str().expect("UTF-8 fixture path"),
        ])
        .output()
        .expect("run direct-only Pipfile.lock scan");
    assert_exit(&direct, 0);
    let direct_report = json_report(&direct);
    assert_eq!(
        report_package_names(&direct_report),
        BTreeSet::from(["py-test", "requests", "zope-interface"])
    );
    assert!(report_packages(&direct_report).iter().all(|result| {
        result
            .pointer("/package/direct_known")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
            && result
                .pointer("/package/direct")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
    }));

    let production = command(&cache)
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            "--no-dev",
            fixture.to_str().expect("UTF-8 fixture path"),
        ])
        .output()
        .expect("run production-only Pipfile.lock scan");
    assert_exit(&production, 0);
    let production_report = json_report(&production);
    assert_eq!(
        report_package_names(&production_report),
        BTreeSet::from(["requests", "urllib3", "zope-interface"])
    );
}

#[test]
fn direct_only_retains_pipfile_lock_packages_with_unknown_directness() {
    let directory = TestDirectory::new("pipfile-lock-unknown-directness");
    let project = directory.path().join("project");
    let cache = directory.path().join("cache");
    fs::create_dir(&project).expect("create Pipenv project");
    fs::copy(
        python_fixture("pipenv-current").join("Pipfile.lock"),
        project.join("Pipfile.lock"),
    )
    .expect("copy Pipfile.lock without its manifest");
    seed_empty_pypi_dump(&cache);

    let output = command(&cache)
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            "--direct-only",
            project.to_str().expect("UTF-8 project path"),
        ])
        .output()
        .expect("run Pipfile.lock scan with unknown directness");

    assert_exit(&output, 0);
    let report = json_report(&output);
    assert_eq!(report_packages(&report).len(), 5);
    assert!(report_packages(&report).iter().all(|result| {
        result
            .pointer("/package/direct_known")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
    }));
}

#[test]
fn no_dev_retains_uv_packages_with_unknown_scope() {
    let directory = TestDirectory::new("uv-unknown-scope");
    let project = directory.path().join("project");
    let cache = directory.path().join("cache");
    fs::create_dir(&project).expect("create uv project");
    fs::write(
        project.join("uv.lock"),
        r#"version = 1
revision = 3
requires-python = ">=3.12"

[[package]]
name = "orphan"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"#,
    )
    .expect("write uv lockfile without a project root");
    seed_empty_pypi_dump(&cache);

    let output = command(&cache)
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            "--no-dev",
            project.to_str().expect("UTF-8 project path"),
        ])
        .output()
        .expect("run uv scan with unknown scope");

    assert_exit(&output, 0);
    let report = json_report(&output);
    let packages = report_packages(&report);
    assert_eq!(packages.len(), 1);
    assert_eq!(
        packages[0]
            .pointer("/package/name")
            .and_then(serde_json::Value::as_str),
        Some("orphan")
    );
    assert_eq!(
        packages[0]
            .pointer("/package/dev_known")
            .and_then(serde_json::Value::as_bool),
        Some(false)
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
fn complete_implicit_config_drives_the_default_scan_and_root_relative_output() {
    let project = TestProject::rust("complete-config");
    seed_empty_cargo_dump(&project.cache);
    fs::write(
        project.directory.path().join("Cargo.lock"),
        r#"version = 3

[[package]]
name = "demo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"

[[package]]
name = "devcrate"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"

[[package]]
name = "transitive"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
"#,
    )
    .expect("write Cargo lockfile with production, development, and transitive packages");
    fs::write(
        project.directory.path().join("Cargo.toml"),
        r#"[package]
name = "fixture"
version = "0.1.0"
edition = "2024"

[dependencies]
demo = "1"

[dev-dependencies]
devcrate = "1"
"#,
    )
    .expect("write direct Cargo manifest");
    let report_directory = project.directory.path().join("reports");
    fs::create_dir(&report_directory).expect("create report directory");
    fs::write(
        project.directory.path().join("depscan.toml"),
        r#"ecosystem = ["cargo"]
no-dev = true
direct-only = true
format = "json"
output = "reports/configured.json"
fail-on = "never"
fail-on-outdated = "never"
offline = true
no-cache = true
max-cache-age = "7d"
include-withdrawn = true
allow-tools = false
quiet = 1
verbose = 0
"#,
    )
    .expect("write complete implicit config");

    let output = project.run(&[project.directory.path().to_str().expect("UTF-8 path")]);

    assert_exit(&output, 0);
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    let report_path = report_directory.join("configured.json");
    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(&report_path).expect("read configured root-relative report"),
    )
    .expect("parse configured JSON report");
    assert_eq!(report_package_names(&report), BTreeSet::from(["demo"]));
}

#[test]
fn configured_verbose_level_is_applied_before_origin_diagnostics() {
    let project = TestProject::rust("configured-verbose");
    seed_empty_cargo_dump(&project.cache);
    fs::write(
        project.directory.path().join("depscan.toml"),
        "offline = true\nformat = \"json\"\nverbose = 1\n",
    )
    .expect("write verbose config");

    let output = project.run(&[
        "scan",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 0);
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"schema_version\""));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("configuration loaded"));
    assert!(stderr.contains("origin=\"implicit-default\""));

    let quiet = project.run(&[
        "scan",
        "--quiet",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);
    assert_exit(&quiet, 0);
    assert!(quiet.stderr.is_empty());
}

#[test]
fn configured_ecosystem_withdrawn_and_failure_policies_are_effective() {
    let ecosystem_project = TestProject::rust("configured-ecosystem");
    fs::write(
        ecosystem_project.directory.path().join("depscan.toml"),
        "ecosystem = [\"pypi\"]\n",
    )
    .expect("write ecosystem config");
    let output = ecosystem_project.run(&[
        "scan",
        ecosystem_project
            .directory
            .path()
            .to_str()
            .expect("UTF-8 path"),
    ]);
    assert_exit(&output, 20);

    let withdrawn_project = TestProject::rust("configured-withdrawn");
    withdrawn_project.seed_clean("1.0.0");
    withdrawn_project.seed_withdrawn_vulnerability();
    fs::write(
        withdrawn_project.directory.path().join("depscan.toml"),
        "format = \"json\"\ninclude-withdrawn = true\nfail-on = \"never\"\n",
    )
    .expect("write withdrawn config");
    let output = withdrawn_project.run(&[
        "scan",
        withdrawn_project
            .directory
            .path()
            .to_str()
            .expect("UTF-8 path"),
    ]);
    assert_exit(&output, 0);
    let report = json_report(&output);
    assert_eq!(
        report
            .pointer("/results/0/vulns/0/withdrawn")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );

    let outdated_project = TestProject::rust("configured-outdated-threshold");
    outdated_project.seed_clean("1.0.1");
    fs::write(
        outdated_project.directory.path().join("depscan.toml"),
        "format = \"json\"\nfail-on-outdated = \"patch\"\n",
    )
    .expect("write outdated threshold config");
    let output = outdated_project.run(&[
        "scan",
        outdated_project
            .directory
            .path()
            .to_str()
            .expect("UTF-8 path"),
    ]);
    assert_exit(&output, 2);
    let report = json_report(&output);
    assert_eq!(
        report
            .pointer("/results/0/latest/staleness")
            .and_then(serde_json::Value::as_str),
        Some("patch")
    );
}

#[test]
fn cli_groups_override_config_fieldwise() {
    let project = TestProject::rust("config-cli-precedence");
    project.seed_clean("1.0.0");
    project.seed_vulnerability();
    let configured_output = project.directory.path().join("configured.json");
    let cli_output = project.directory.path().join("cli.sarif");
    fs::write(
        project.directory.path().join("depscan.toml"),
        r#"ecosystem = ["pypi"]
format = "json"
output = "configured.json"
fail-on = "never"
quiet = 1
verbose = 0
"#,
    )
    .expect("write overridden config");

    let output = project.run(&[
        "scan",
        "--ecosystem",
        "cargo",
        "--output",
        cli_output.to_str().expect("UTF-8 output path"),
        "--fail-on",
        "high",
        "--verbose",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 1);
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("configuration loaded"));
    assert!(!configured_output.exists());
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(cli_output).expect("read CLI-selected output path"))
            .expect("parse configured JSON report");
    assert_eq!(
        report
            .get("schema_version")
            .and_then(serde_json::Value::as_u64),
        Some(4)
    );
}

#[test]
fn strict_config_schema_and_values_fail_before_provider_access() {
    let project = TestProject::rust("strict-config");
    let cases = [
        ("unknown = true\n", "unknown field"),
        ("ecosystems = [\"cargo\"]\n", "unknown field"),
        (
            "[[ignore]]\nid = \"RUSTSEC-TEST\"\nreasno = \"typo\"\n",
            "unknown field",
        ),
        ("offline = \"yes\"\n", "invalid config"),
        ("ecosystem = [\"made-up\"]\n", "invalid config value"),
        ("format = \"JSON\"\n", "invalid config value"),
        ("max-cache-age = \"tomorrow\"\n", "invalid config value"),
        ("quiet = 1\nverbose = 1\n", "cannot both"),
    ];

    for (contents, expected) in cases {
        fs::write(project.directory.path().join("depscan.toml"), contents)
            .expect("write invalid config case");
        let output = project.run(&[
            "scan",
            project.directory.path().to_str().expect("UTF-8 path"),
        ]);
        assert_exit(&output, 10);
        assert_diagnostic_only_on_stderr(&output, expected);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("provider hard failure"));
    }
}

#[test]
fn implicit_config_cannot_authorize_tools_or_escape_the_scan_root() {
    let project = TestProject::rust("implicit-config-security");
    let escaped = project
        .directory
        .path()
        .parent()
        .expect("test directory parent")
        .join(format!("depscan-escaped-{}.json", std::process::id()));
    let _ = fs::remove_file(&escaped);

    fs::write(
        project.directory.path().join("depscan.toml"),
        "allow-tools = true\n",
    )
    .expect("write implicit tool permission");
    let output = project.run(&[
        "scan",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);
    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "cannot enable allow-tools");

    fs::write(
        project.directory.path().join("depscan.toml"),
        format!(
            "format = \"json\"\noutput = \"../{}\"\n",
            escaped
                .file_name()
                .expect("escaped filename")
                .to_string_lossy()
        ),
    )
    .expect("write escaping output config");
    let output = project.run(&[
        "scan",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);
    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "escapes scan root");
    assert!(!escaped.exists());
}

#[cfg(any(unix, windows))]
#[test]
fn implicit_config_cannot_write_through_an_output_symlink() {
    let project = TestProject::rust("implicit-output-symlink");
    let target = project.directory.path().join("target.json");
    let linked = project.directory.path().join("report.json");
    fs::write(&target, "preserve me").expect("write output symlink target");
    if let Err(error) = symlink_file(&target, &linked) {
        #[cfg(windows)]
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            return;
        }
        panic!("create output symlink: {error}");
    }
    fs::write(
        project.directory.path().join("depscan.toml"),
        "format = \"json\"\noutput = \"report.json\"\n",
    )
    .expect("write implicit output config");

    let output = project.run(&[
        "scan",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "symbolic link");
    assert_eq!(
        fs::read_to_string(target).expect("read preserved target"),
        "preserve me"
    );
}

#[test]
fn explicit_config_can_authorize_tools_and_write_to_an_explicit_location() {
    let project = TestProject::rust("explicit-config-trust");
    seed_empty_cargo_dump(&project.cache);
    let trusted_config = project.directory.path().join("trusted.toml");
    let output_path = project.directory.path().join("trusted-output.json");
    fs::write(
        &trusted_config,
        format!(
            "offline = true\nformat = \"json\"\noutput = {:?}\nallow-tools = true\n",
            output_path.to_string_lossy()
        ),
    )
    .expect("write explicitly trusted config");

    let output = project.run(&[
        "scan",
        "--config",
        trusted_config.to_str().expect("UTF-8 config path"),
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 0);
    assert!(output.stdout.is_empty());
    assert!(output_path.is_file());
}

#[test]
fn malformed_scan_config_does_not_affect_non_scan_commands() {
    let project = TestProject::rust("config-command-isolation");
    fs::write(project.directory.path().join("depscan.toml"), "offline = [")
        .expect("write malformed scan config");

    let output = command(&project.cache)
        .current_dir(project.directory.path())
        .args(["cache", "path"])
        .output()
        .expect("run non-scan command beside malformed config");

    assert_exit(&output, 0);
    assert!(output.stderr.is_empty());
    assert!(String::from_utf8_lossy(&output.stdout).contains(&project.cache.to_string_lossy()[..]));

    for arguments in [&["completions", "bash"][..], &["sync", "--help"][..]] {
        let output = command(&project.cache)
            .current_dir(project.directory.path())
            .args(arguments)
            .output()
            .expect("run non-scan command beside malformed config");
        assert_exit(&output, 0);
        assert!(output.stderr.is_empty());
        assert!(!output.stdout.is_empty());
    }
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
fn unsupported_lock_schemas_exit_ten_before_provider_access() {
    for (format, file) in [
        ("npm", "package-lock.json"),
        ("bun", "bun.lock"),
        ("pnpm", "pnpm-lock.yaml"),
        ("uv", "uv.lock"),
        ("poetry", "poetry.lock"),
        ("pipfile", "Pipfile.lock"),
        ("nuget", "packages.lock.json"),
        ("cargo", "Cargo.lock"),
    ] {
        let directory = TestDirectory::new(&format!("unsupported-{format}-lock"));
        let cache = directory.path().join("cache");
        fs::copy(
            lock_schema_fixture(format, "missing-section", file),
            directory.path().join(file),
        )
        .unwrap_or_else(|error| panic!("copy {format} fixture: {error}"));

        let output = command(&cache)
            .args([
                "scan",
                directory.path().to_str().expect("UTF-8 project path"),
            ])
            .output()
            .unwrap_or_else(|error| panic!("run malformed {format} scan: {error}"));

        assert_exit(&output, 10);
        assert_diagnostic_only_on_stderr(&output, file);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("failed to parse"),
            "{format} did not report a parse failure: {stderr}"
        );
        assert!(
            !stderr.contains("provider hard failure"),
            "{format} reached provider access after an invalid lock: {stderr}"
        );
    }
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

#[test]
fn typed_cli_values_and_required_arguments_fail_during_clap_parsing() {
    let directory = TestDirectory::new("typed-cli-errors");
    let cases = vec![
        (vec!["scan", "--ecosystem", "ruby"], "possible values"),
        (
            vec!["sync", "--transfer-timeout", "1s", "--ecosystem", "ruby"],
            "possible values",
        ),
        (vec!["scan", "--format", "xml"], "possible values"),
        (vec!["scan", "--fail-on", "severe"], "possible values"),
        (
            vec!["scan", "--fail-on-outdated", "weekly"],
            "possible values",
        ),
        (
            vec!["scan", "--max-cache-age", "24"],
            "requires one of s, m, h, or d",
        ),
        (vec!["scan", "--max-cache-age", "24w"], "invalid unit"),
        (vec!["scan", "--max-cache-age=-1h"], "non-negative integer"),
        (
            vec!["scan", "--max-cache-age", "999999999999999999999999999999h"],
            "outside the supported range",
        ),
        (
            vec!["scan", "--max-cache-age", "9223372036854775807d"],
            "outside the supported range",
        ),
        (
            vec!["sync", "--transfer-timeout", "0s"],
            "must be greater than zero",
        ),
        (
            vec!["sync", "--transfer-timeout", "24"],
            "requires one of s, m, h, or d",
        ),
        (
            vec![
                "sync",
                "--transfer-timeout",
                "999999999999999999999999999999h",
            ],
            "outside the supported range",
        ),
        (vec!["completions", "tcsh"], "possible values"),
        (vec!["completions"], "required arguments"),
        (vec!["cache"], "subcommand"),
        (vec!["scan", "--quiet", "--verbose"], "cannot be used with"),
    ];

    for (arguments, expected) in cases {
        let output = command(&directory.path().join("cache"))
            .args(&arguments)
            .output()
            .expect("run invalid CLI case");
        assert_exit(&output, 10);
        assert_diagnostic_only_on_stderr(&output, expected);
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("provider hard failure"),
            "CLI validation reached a provider for {arguments:?}"
        );
    }
}

#[test]
fn ecosystem_aliases_case_and_repeatable_values_remain_compatible() {
    let empty = TestDirectory::new("ecosystem-aliases-empty");
    for value in ["node", "bun", "python", "dotnet", ".net", "NPM", "PyThOn"] {
        let output = command(&empty.path().join("cache"))
            .args([
                "scan",
                "--ecosystem",
                value,
                empty.path().to_str().expect("UTF-8 path"),
            ])
            .output()
            .expect("run ecosystem alias");
        assert_exit(&output, 20);
        assert_diagnostic_only_on_stderr(&output, "no supported project detected");
    }

    let project = TestProject::rust("cargo-ecosystem-aliases");
    project.seed_clean("1.0.0");
    let root = project.directory.path().to_str().expect("UTF-8 path");
    for value in ["cargo", "crates", "crates.io", "rust", "RUST"] {
        let output = project.run(&["scan", "--ecosystem", value, root]);
        assert_exit(&output, 0);
        assert!(output.stderr.is_empty());
    }

    let repeated = project.run(&[
        "scan",
        "--ecosystem",
        "cargo",
        "--ecosystem",
        "npm",
        "-qq",
        root,
    ]);
    assert_exit(&repeated, 0);
    assert!(repeated.stderr.is_empty());

    let missing = project.directory.path().join("missing");
    for age in ["0s", "1m", "2h", "3d"] {
        let output = project.run(&[
            "scan",
            "--max-cache-age",
            age,
            missing.to_str().expect("UTF-8 path"),
        ]);
        assert_exit(&output, 10);
        assert_diagnostic_only_on_stderr(&output, "is not a directory");
    }
    let compatible_cache_controls = project.run(&[
        "scan",
        "--offline",
        "--no-cache",
        "--max-cache-age",
        "7d",
        missing.to_str().expect("UTF-8 path"),
    ]);
    assert_exit(&compatible_cache_controls, 10);
    assert_diagnostic_only_on_stderr(&compatible_cache_controls, "is not a directory");
}

#[test]
fn output_format_inference_and_explicit_precedence_are_stable() {
    let project = TestProject::rust("format-inference");
    project.seed_clean("1.0.0");
    let root = project.directory.path().to_str().expect("UTF-8 path");

    for extension in ["json", "sarif", "txt", "log"] {
        let report = project.directory.path().join(format!("report.{extension}"));
        let output = project.run(&[
            "scan",
            "--output",
            report.to_str().expect("UTF-8 output path"),
            root,
        ]);
        assert_exit(&output, 0);
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        let contents = fs::read_to_string(&report).expect("read inferred report");
        match extension {
            "json" => {
                let value: serde_json::Value = serde_json::from_str(&contents).unwrap();
                assert!(value.get("schema_version").is_some());
            }
            "sarif" => {
                let value: serde_json::Value = serde_json::from_str(&contents).unwrap();
                assert_eq!(value.get("version").and_then(|v| v.as_str()), Some("2.1.0"));
            }
            "txt" | "log" => {
                assert!(contents.starts_with("depscan:"));
                assert_eq!(contents.lines().count(), 1);
            }
            _ => unreachable!(),
        }
    }

    let explicit_summary = project.directory.path().join("explicit.json");
    let output = project.run(&[
        "scan",
        "--format",
        "summary",
        "--output",
        explicit_summary.to_str().expect("UTF-8 output path"),
        root,
    ]);
    assert_exit(&output, 0);
    let contents = fs::read_to_string(explicit_summary).unwrap();
    assert!(contents.starts_with("depscan:"));
    assert_eq!(contents.lines().count(), 1);

    let explicit_unknown = project.directory.path().join("explicit.unknown");
    let output = project.run(&[
        "scan",
        "--format",
        "json",
        "--output",
        explicit_unknown.to_str().expect("UTF-8 output path"),
        root,
    ]);
    assert_exit(&output, 0);
    serde_json::from_slice::<serde_json::Value>(&fs::read(explicit_unknown).unwrap()).unwrap();

    let unknown = project.directory.path().join("implicit.unknown");
    let output = project.run(&[
        "scan",
        "--output",
        unknown.to_str().expect("UTF-8 output path"),
        root,
    ]);
    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "could not infer output format");
    assert!(!unknown.exists());

    let output = project.run(&["scan", root]);
    assert_exit(&output, 0);
    assert!(output.stderr.is_empty());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("depscan:"));
    assert_eq!(String::from_utf8_lossy(&output.stdout).lines().count(), 1);
}

#[test]
fn help_and_subcommand_contracts_match_byte_snapshots() {
    let directory = TestDirectory::new("help-snapshots");
    let cases = [
        (
            &["--help"][..],
            "10bc330d746d85597e467f2d4b74001007d5b5398d2ffa9ec7cf1488f3092025",
        ),
        (
            &["scan", "--help"][..],
            "04da79771018066416cff2365e532a9e3264040d88604482fb82bbc154a09553",
        ),
        (
            &["sync", "--help"][..],
            "fd120e80384cb8a4b1cd7e3452e4d46512f88791c6f5a856514e19f2cbdc5dc0",
        ),
        (
            &["cache", "--help"][..],
            "6652e14a617b9afe15c2db0394d21dde4544b92dd58f75f33bbcb0cfa75ce05f",
        ),
        (
            &["completions", "--help"][..],
            "e64f7f2ad60e86fdaab63e9c6a77ffc71069e2dd57124461bd51c09d657d4eb5",
        ),
    ];
    for (arguments, expected_sha256) in cases {
        let output = command(&directory.path().join("cache"))
            .args(arguments)
            .output()
            .expect("render help snapshot");
        assert_stdout_snapshot(&output, expected_sha256);
    }
}

#[test]
fn generated_completions_match_byte_snapshots_and_advertise_typed_values() {
    let directory = TestDirectory::new("completion-snapshots");
    for (shell, expected_sha256) in [
        (
            "bash",
            "e9e469922e7cffb61efeffe0382827ba91caa129effdd824dee5c70aa292285c",
        ),
        (
            "fish",
            "317f193fba80acbbd95765f23ca7f82c4647605b494b874b6c33474a92fc5756",
        ),
    ] {
        let output = command(&directory.path().join("cache"))
            .args(["completions", shell])
            .output()
            .expect("generate completions");
        assert_stdout_snapshot(&output, expected_sha256);
        let script = String::from_utf8_lossy(&output.stdout);
        for value in [
            "npm", "pypi", "nuget", "cargo", "table", "json", "sarif", "summary", "critical",
            "high", "medium", "low", "any", "never", "major", "minor", "patch",
        ] {
            assert!(
                script.contains(value),
                "{shell} completion omitted {value:?}"
            );
        }
        assert!(!script.contains("power-shell"));
        if shell == "bash" {
            for value in ["bash", "elvish", "fish", "powershell", "zsh"] {
                assert!(
                    script.contains(value),
                    "bash completion omitted shell {value:?}"
                );
            }
        }
    }

    let canonical = command(&directory.path().join("cache"))
        .args(["completions", "powershell"])
        .output()
        .expect("generate canonical PowerShell completion");
    let legacy = command(&directory.path().join("cache"))
        .args(["completions", "power-shell"])
        .output()
        .expect("generate legacy PowerShell completion");
    assert_exit(&canonical, 0);
    assert_exit(&legacy, 0);
    assert_eq!(canonical.stdout, legacy.stdout);
    assert!(canonical.stderr.is_empty());
    assert!(legacy.stderr.is_empty());
}

#[test]
fn help_and_version_are_successful_stdout_only_information() {
    let directory = TestDirectory::new("informational-exits");
    for arguments in [
        &["-h"][..],
        &["--help"][..],
        &["scan", "-h"][..],
        &["scan", "--help"][..],
        &["-V"][..],
        &["--version"][..],
    ] {
        let output = command(&directory.path().join("cache"))
            .args(arguments)
            .output()
            .expect("run informational option");
        assert_exit(&output, 0);
        assert!(output.stderr.is_empty());
        assert!(!output.stdout.is_empty());
    }
}
