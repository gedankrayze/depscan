use super::support::*;

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
name = "fixture"
version = "0.1.0"
dependencies = [
 "demo",
 "devcrate",
]

[[package]]
name = "demo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
dependencies = [
 "transitive",
]

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
