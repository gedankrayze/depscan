use super::*;

#[test]
fn explicitly_selected_config_runs_bun_with_exact_sandboxed_invocation() {
    let fixture = Fixture::new();
    fixture.bun_project();
    fixture.install("bun", FakeBehavior::Valid(BUN_OUTPUT));
    fixture.seed_dump("npm");
    let config = fixture.directory.path().join("trusted.toml");
    fs::write(&config, "allow-tools = true\n").unwrap();

    let output = fixture.run(&[
        "scan",
        "--offline",
        "--format",
        "json",
        "--config",
        config.to_str().unwrap(),
        fixture.project.to_str().unwrap(),
    ]);

    assert_exit(&output, 0);
    assert_eq!(
        report_package_names(&output),
        BTreeSet::from(["left-pad".to_owned()])
    );
    let capture = fixture.capture();
    assert_controlled_invocation(&fixture, &["bun.lockb"], &capture);
}

#[test]
fn allow_tools_runs_dotnet_with_exact_project_and_offline_arguments() {
    let fixture = Fixture::new();
    fixture.dotnet_project();
    fixture.install("dotnet", FakeBehavior::Valid(DOTNET_OUTPUT));
    fixture.seed_dump("NuGet");

    let output = fixture.run(&[
        "scan",
        "--offline",
        "--format",
        "json",
        "--allow-tools",
        fixture.project.to_str().unwrap(),
    ]);

    assert_exit(&output, 0);
    assert_eq!(
        report_package_names(&output),
        BTreeSet::from([
            "humanizer.core".to_owned(),
            "microsoft.extensions.options".to_owned(),
        ])
    );
    let capture = fixture.capture();
    assert_controlled_invocation(
        &fixture,
        &[
            "list",
            "./Project.csproj",
            "package",
            "--include-transitive",
            "--format",
            "json",
            "--output-version",
            "1",
            "--verbosity",
            "quiet",
            "--no-restore",
        ],
        &capture,
    );
}

#[test]
fn online_dotnet_profile_does_not_disable_the_authorized_restore() {
    let fixture = Fixture::new();
    fixture.dotnet_project();
    fixture.install("dotnet", FakeBehavior::Valid(EMPTY_DOTNET_OUTPUT));

    let output = fixture.run(&["scan", "--allow-tools", fixture.project.to_str().unwrap()]);

    assert_exit(&output, 20);
    let capture = fixture.capture();
    assert_controlled_invocation(
        &fixture,
        &[
            "list",
            "./Project.csproj",
            "package",
            "--include-transitive",
            "--format",
            "json",
            "--output-version",
            "1",
            "--verbosity",
            "quiet",
        ],
        &capture,
    );
}

#[test]
fn malformed_outputs_are_actionable_for_both_tools() {
    for tool in ["bun", "dotnet"] {
        let fixture = Fixture::new();
        if tool == "bun" {
            fixture.bun_project();
        } else {
            fixture.dotnet_project();
        }
        fixture.install(tool, FakeBehavior::Malformed);
        let output = fixture.run(&["scan", "--allow-tools", fixture.project.to_str().unwrap()]);

        assert_exit(&output, 10);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("emitted malformed dependency data"),
            "{tool}: {stderr}"
        );
        assert!(fixture.capture_exists());
    }
}

#[test]
fn oversized_output_is_rejected_and_the_tool_is_stopped() {
    let fixture = Fixture::new();
    fixture.bun_project();
    fixture.install("bun", FakeBehavior::Oversized);

    let output = fixture.run(&["scan", "--allow-tools", fixture.project.to_str().unwrap()]);

    assert_exit(&output, 10);
    assert!(String::from_utf8_lossy(&output.stderr).contains("8388608-byte output limit"));
    assert!(fixture.capture_exists());
}

#[test]
fn nonzero_tool_exit_includes_bounded_actionable_stderr() {
    let fixture = Fixture::new();
    fixture.dotnet_project();
    fixture.install("dotnet", FakeBehavior::Failing);

    let output = fixture.run(&["scan", "--allow-tools", fixture.project.to_str().unwrap()]);

    assert_exit(&output, 10);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("exited with exit status: 23"), "{stderr}");
    assert!(stderr.contains("fixture restore failed"), "{stderr}");
    assert!(stderr.contains("commit packages.lock.json"), "{stderr}");
}

#[test]
fn authorized_nonzero_bun_exit_is_not_hidden_by_manifest_fallback() {
    let fixture = Fixture::new();
    fixture.bun_project();
    fixture.install("bun", FakeBehavior::Failing);

    let output = fixture.run(&["scan", "--allow-tools", fixture.project.to_str().unwrap()]);

    assert_exit(&output, 10);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("exited with exit status: 23"), "{stderr}");
    assert!(stderr.contains("fixture restore failed"), "{stderr}");
    assert!(!stderr.contains("degraded manifest-only mode"), "{stderr}");
    assert!(fixture.capture_exists());
}

#[test]
fn hanging_tool_is_killed_at_the_timeout() {
    let fixture = Fixture::new();
    fixture.bun_project();
    fixture.install("bun", FakeBehavior::Hanging);

    let started = std::time::Instant::now();
    let output = fixture.run(&["scan", "--allow-tools", fixture.project.to_str().unwrap()]);

    assert_exit(&output, 10);
    assert!(String::from_utf8_lossy(&output.stderr).contains("timed out after 10 seconds"));
    assert!(started.elapsed() < std::time::Duration::from_secs(13));
}

#[test]
fn missing_bun_executable_degrades_to_manifest_constraints() {
    let fixture = Fixture::new();
    fixture.bun_project();
    fixture.seed_dump("npm");
    fixture.seed_npm_registry("left-pad", &["1.3.0"]);
    let empty_path = env::join_paths([fixture.bin.clone()]).unwrap();

    let output = fixture.run_with_path(
        &[
            "scan",
            "--offline",
            "--format",
            "json",
            "--allow-tools",
            fixture.project.to_str().unwrap(),
        ],
        empty_path,
    );

    assert_exit(&output, 0);
    assert_eq!(
        report_package_names(&output),
        BTreeSet::from(["left-pad".to_owned()])
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("executable was not found"), "{stderr}");
    assert!(stderr.contains("degraded manifest-only mode"), "{stderr}");
    assert!(!fixture.capture_exists());
}

#[test]
fn tools_are_never_started_without_effective_authorization() {
    let bun = Fixture::new();
    bun.bun_workspace_project();
    bun.install("bun", FakeBehavior::Valid(BUN_OUTPUT));
    bun.seed_dump("npm");
    for (name, version) in [
        ("root-production", "1.0.0"),
        ("root-development", "2.0.0"),
        ("workspace-production", "3.0.0"),
        ("workspace-development", "4.0.0"),
    ] {
        bun.seed_npm_registry(name, &[version]);
    }
    let output = bun.run(&[
        "scan",
        "--offline",
        "--format",
        "json",
        bun.project.to_str().unwrap(),
    ]);
    assert_exit(&output, 0);
    assert!(!bun.capture_exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("external tool execution was not authorized"),
        "{stderr}"
    );
    assert!(stderr.contains("degraded manifest-only mode"), "{stderr}");
    let report = report(&output);
    let packages = report["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| {
            let package = &result["package"];
            (
                package["name"].as_str().unwrap(),
                (
                    package["dev"].as_bool().unwrap(),
                    package["resolved_from_range"].as_bool().unwrap(),
                    package["manifest_constraint"]["raw"].as_str().unwrap(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(packages.len(), 4);
    assert_eq!(packages["root-production"], (false, true, "^1"));
    assert_eq!(packages["root-development"], (true, true, "^2"));
    assert_eq!(packages["workspace-production"], (false, true, "^3"));
    assert_eq!(packages["workspace-development"], (true, true, "^4"));

    let dotnet = Fixture::new();
    dotnet.dotnet_project();
    dotnet.install("dotnet", FakeBehavior::Valid(DOTNET_OUTPUT));
    dotnet.seed_dump("NuGet");
    dotnet.seed_nuget_registry("Humanizer.Core", &["2.14.1"]);
    let output = dotnet.run(&[
        "scan",
        "--offline",
        "--format",
        "json",
        dotnet.project.to_str().unwrap(),
    ]);
    assert_exit(&output, 0);
    assert_eq!(
        report_package_names(&output),
        BTreeSet::from(["humanizer.core".to_owned()])
    );
    assert!(!dotnet.capture_exists());

    let implicit = Fixture::new();
    implicit.bun_project();
    implicit.install("bun", FakeBehavior::Valid(BUN_OUTPUT));
    fs::write(
        implicit.project.join("depscan.toml"),
        "allow-tools = true\n",
    )
    .unwrap();
    let output = implicit.run(&["scan", implicit.project.to_str().unwrap()]);
    assert_exit(&output, 10);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("implicit project config cannot enable allow-tools")
    );
    assert!(!implicit.capture_exists());
}

#[test]
fn bun_manifest_fallback_fails_closed_without_a_usable_manifest() {
    let missing = Fixture::new();
    missing.bun_lock_only();
    let output = missing.run(&["scan", missing.project.to_str().unwrap()]);
    assert_exit(&output, 10);
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("manifest-only fallback also failed"),
        "{stderr}"
    );
    assert!(stderr.contains("no usable colocated manifest"), "{stderr}");
    assert!(!missing.capture_exists());

    let malformed = Fixture::new();
    malformed.bun_lock_only();
    fs::write(malformed.project.join("package.json"), "not json")
        .expect("write malformed package manifest");
    let output = malformed.run(&["scan", malformed.project.to_str().unwrap()]);
    assert_exit(&output, 10);
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("manifest-only fallback also failed"),
        "{stderr}"
    );
    assert!(stderr.contains("failed to parse"), "{stderr}");
    assert!(!malformed.capture_exists());
}
