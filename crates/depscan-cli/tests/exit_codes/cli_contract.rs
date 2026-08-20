use super::support::*;

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
            "9d06a647ad5d52a3848a1beef180180f9f194a9fb0bfd3080e09d11db031b756",
        ),
        (
            &["scan", "--help"][..],
            "04da79771018066416cff2365e532a9e3264040d88604482fb82bbc154a09553",
            "e1126e87cbbeac7607240226f1b53bec1ffb23e9a63b50f0a4e59ae30eb15b36",
        ),
        (
            &["sync", "--help"][..],
            "fd120e80384cb8a4b1cd7e3452e4d46512f88791c6f5a856514e19f2cbdc5dc0",
            "66a947961b2ad4628a202fb1619fa2e80c507217c8983e67be558a8b954ee8c8",
        ),
        (
            &["cache", "--help"][..],
            "6652e14a617b9afe15c2db0394d21dde4544b92dd58f75f33bbcb0cfa75ce05f",
            "f775873438292ac5af31a5d142dc1cd2ce3714c378b8c25d7ec935a2177dc5cd",
        ),
        (
            &["completions", "--help"][..],
            "e64f7f2ad60e86fdaab63e9c6a77ffc71069e2dd57124461bd51c09d657d4eb5",
            "c7f90f5f245ebbe42844c6242d54e5b7f246d03130e70f82b4ff4fcf16efd203",
        ),
    ];
    for (arguments, unix_sha256, windows_sha256) in cases {
        let output = command(&directory.path().join("cache"))
            .args(arguments)
            .output()
            .expect("render help snapshot");
        let expected_sha256 = if cfg!(windows) {
            windows_sha256
        } else {
            unix_sha256
        };
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
