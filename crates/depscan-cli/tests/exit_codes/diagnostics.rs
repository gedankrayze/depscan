use super::support::*;

#[test]
fn verbose_scan_reports_config_resolution_on_stderr() {
    let project = TestProject::rust("verbose-config-origin");
    project.seed_clean("1.0.0");
    project.seed_empty_offline_dump();

    let output = project.run(&[
        "scan",
        "--offline",
        "--verbose",
        "--format",
        "json",
        project.directory.path().to_str().expect("UTF-8 path"),
    ]);

    assert_exit(&output, 0);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("configuration file not found; using defaults"),
        "verbose scan must surface config resolution: {stderr}"
    );
}

#[test]
fn config_set_verbosity_applies_to_the_scan_phase() {
    let project = TestProject::rust("config-set-verbosity");
    project.seed_clean("1.0.0");
    project.seed_empty_offline_dump();
    fs::write(
        project.directory.path().join("depscan.toml"),
        "verbose = 1\n",
    )
    .expect("write project config");

    let output = command(&project.cache)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            project.directory.path().to_str().expect("UTF-8 path"),
        ])
        .output()
        .expect("run depscan with config-set verbosity");

    assert_exit(&output, 0);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("reproducible scan timestamp selected"),
        "config-set verbosity must enable scan-phase debug diagnostics: {stderr}"
    );
}
