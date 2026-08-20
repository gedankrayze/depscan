use super::support::*;

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
    let stdout = String::from_utf8(output.stdout).expect("cache path is UTF-8");
    let mut lines = stdout.lines();
    let reported = PathBuf::from(lines.next().expect("cache path output"));
    assert!(lines.next().is_none(), "cache path output must be one line");
    assert_eq!(
        reported,
        fs::canonicalize(&project.cache).expect("canonical cache path")
    );

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
