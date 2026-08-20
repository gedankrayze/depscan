use super::support::*;

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
fn malformed_npm_package_records_exit_ten_without_a_partial_report() {
    for (case, expected) in [
        ("malformed-entry", "node_modules/missing-version"),
        (
            "garbage-resolved",
            "unsupported or malformed resolved source",
        ),
        ("alias-missing-name", "alias package entry"),
    ] {
        let directory = TestDirectory::new(&format!("malformed-npm-package-record-{case}"));
        let cache = directory.path().join("cache");
        fs::copy(
            lock_schema_fixture("npm", case, "package-lock.json"),
            directory.path().join("package-lock.json"),
        )
        .expect("copy malformed npm package record fixture");

        let output = command(&cache)
            .args([
                "scan",
                directory.path().to_str().expect("UTF-8 project path"),
            ])
            .output()
            .expect("run malformed npm scan");

        assert_exit(&output, 10);
        assert_diagnostic_only_on_stderr(&output, expected);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("failed to parse"));
        assert!(!stderr.contains("provider hard failure"));
    }
}

#[test]
fn source_only_npm_coordinates_do_not_expose_url_credentials_or_tokens() {
    let directory = TestDirectory::new("npm-source-coordinate-redaction");
    let cache = directory.path().join("cache");
    fs::write(
        directory.path().join("package-lock.json"),
        r#"{
          "name":"source-coordinate-redaction",
          "version":"1.0.0",
          "lockfileVersion":3,
          "packages":{
            "":{"name":"source-coordinate-redaction","version":"1.0.0","dependencies":{"bare-version":"file:../bare","opaque-version":"file:../opaque","private-package":"https://user:password@private.example/package.tgz?token=secret#fragment","relative-protected-source":"../user:password@private.example/repository","relative-source":"../private#token=secret","scp-source":"git@private.example:owner/repo.git#token=secret","version-source":"https://other:credential@private.example/version.tgz?signature=hidden#revision"}},
            "node_modules/bare-version":{"version":"folder?token=secret/package.tgz","resolved":"file:../bare"},
            "node_modules/opaque-version":{"version":"user:password@private.example/path/package.tgz","resolved":"file:../opaque"},
            "node_modules/private-package":{"resolved":"https://user:password@private.example/package.tgz?token=secret#fragment"},
            "node_modules/relative-protected-source":{"version":"../user:password@private.example/repository"},
            "node_modules/relative-source":{"resolved":"../private#token=secret"},
            "node_modules/scp-source":{"resolved":"git@private.example:owner/repo.git#token=secret"},
            "node_modules/version-source":{"version":"https://other:credential@private.example/version.tgz?signature=hidden#revision"}
          }
        }"#,
    )
    .expect("write source-only npm lock");

    let output = command(&cache)
        .args([
            "scan",
            "--format",
            "json",
            "--fail-on",
            "never",
            "--fail-on-outdated",
            "never",
            directory.path().to_str().expect("UTF-8 project path"),
        ])
        .output()
        .expect("run source-only npm scan");

    assert_exit(&output, 0);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for secret in [
        "user",
        "password",
        "token",
        "secret",
        "fragment",
        "other",
        "credential",
        "signature",
        "hidden",
        "revision",
    ] {
        assert!(
            !combined.contains(secret),
            "source-only npm scan exposed {secret:?}: {combined}"
        );
    }
    let report = json_report(&output);
    let packages = report_packages(&report);
    assert_eq!(packages.len(), 7);
    let versions = packages
        .iter()
        .map(|result| {
            result
                .pointer("/package/version")
                .and_then(|value| value.as_str())
                .expect("reported source-only version")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        versions,
        BTreeSet::from([
            "../private",
            "[redacted-source]",
            "folder",
            "git@private.example:owner/repo.git",
            "https://private.example/package.tgz",
            "https://private.example/version.tgz",
        ])
    );
    assert!(packages.iter().all(|result| {
        result
            .pointer("/package/enrichable")
            .and_then(|value| value.as_bool())
            == Some(false)
    }));
}
