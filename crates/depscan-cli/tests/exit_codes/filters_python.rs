use super::support::*;

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
fn no_dev_retains_pnpm_packages_with_unknown_scope() {
    let directory = TestDirectory::new("pnpm-unknown-scope");
    let cache = directory.path().join("cache");
    fs::write(
        directory.path().join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    devDependencies:
      known-development:
        specifier: 1.0.0
        version: 1.0.0
packages:
  known-development@1.0.0:
    resolution: {integrity: sha512-known}
  unknown-scope@1.0.0:
    resolution: {integrity: sha512-unknown}
snapshots:
  known-development@1.0.0: {}
  unknown-scope@1.0.0: {}
"#,
    )
    .expect("write pnpm lockfile with mixed development confidence");
    seed_empty_npm_dump(&cache);

    let output = command(&cache)
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            "--no-dev",
            directory.path().to_str().expect("UTF-8 project path"),
        ])
        .output()
        .expect("run pnpm scan with unknown scope");

    assert_exit(&output, 0);
    let report = json_report(&output);
    let packages = report_packages(&report);
    assert_eq!(packages.len(), 1);
    assert_eq!(
        packages[0]
            .pointer("/package/name")
            .and_then(serde_json::Value::as_str),
        Some("unknown-scope")
    );
    assert_eq!(
        packages[0]
            .pointer("/package/dev_known")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
}
