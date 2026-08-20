use super::support::*;

#[test]
fn npm_direct_only_uses_lock_edges_and_retains_unbound_unknowns() {
    let directory = TestDirectory::new("npm-lock-directness-filter");
    let cache = directory.path().join("cache");
    fs::copy(
        npm_fixture("npm-v3-directness").join("package-lock.json"),
        directory.path().join("package-lock.json"),
    )
    .expect("copy lock-only npm directness fixture");
    seed_empty_npm_dump(&cache);

    let output = command(&cache)
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            "--direct-only",
            directory.path().to_str().expect("UTF-8 project path"),
        ])
        .output()
        .expect("run direct-only npm scan");

    assert_exit(&output, 0);
    let report = json_report(&output);
    assert_eq!(
        report_package_names(&report),
        BTreeSet::from([
            "duplicate",
            "hoisted",
            "parent",
            "root-actual",
            "root-direct",
            "shared",
            "unreferenced",
            "unreferenced-child",
            "unreferenced-parent",
            "workspace-actual",
        ])
    );
    let packages = report_packages(&report);
    assert!(
        packages.iter().all(|result| {
            let name = result
                .pointer("/package/name")
                .and_then(serde_json::Value::as_str)
                .expect("package name");
            if name.starts_with("unreferenced") {
                result
                    .pointer("/package/direct_known")
                    .and_then(serde_json::Value::as_bool)
                    == Some(false)
            } else {
                result
                    .pointer("/package/direct")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                    && result
                        .pointer("/package/direct_known")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
            }
        }),
        "direct-only must retain Direct and Unknown packages only"
    );
    assert!(
        packages.iter().all(|result| {
            !(result
                .pointer("/package/name")
                .and_then(serde_json::Value::as_str)
                == Some("duplicate")
                && result
                    .pointer("/package/version")
                    .and_then(serde_json::Value::as_str)
                    == Some("1.0.0"))
        }),
        "proven-transitive duplicate@1.0.0 must be filtered"
    );
}

#[test]
fn npm_extglob_workspace_fixture_accepts_real_link_and_rejects_forged_nonmatches() {
    let fixture = npm_fixture("npm-v3-mixed-negative-extglob").join("package-lock.json");
    let valid = TestDirectory::new("npm-extglob-workspace-valid");
    let valid_cache = valid.path().join("cache");
    fs::copy(&fixture, valid.path().join("package-lock.json"))
        .expect("copy npm 11 mixed-extglob fixture");
    seed_empty_npm_dump(&valid_cache);

    let output = command(&valid_cache)
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            valid.path().to_str().expect("UTF-8 project path"),
        ])
        .output()
        .expect("scan valid npm 11 mixed-extglob fixture");
    assert_exit(&output, 0);
    assert_eq!(
        report_package_names(&json_report(&output)),
        BTreeSet::from(["left-pad"])
    );

    let source: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture).expect("read npm 11 fixture"))
            .expect("decode npm 11 fixture");
    for (label, pattern, forged_target) in [
        (
            "excluded-negative-suffix",
            "packages/pre!(bad).js",
            "packages/prebad.js",
        ),
        (
            "standalone-star-remainder",
            "packages/!(a)@(*)",
            "packages/a",
        ),
    ] {
        let directory = TestDirectory::new(&format!("npm-extglob-forged-{label}"));
        let cache = directory.path().join("cache");
        let mut forged = source.clone();
        forged["packages"][""]["workspaces"] = serde_json::json!([pattern]);
        forged["packages"]["node_modules/@ds063/pregood"]["resolved"] =
            serde_json::Value::String(forged_target.to_owned());
        let workspace = forged["packages"]
            .as_object_mut()
            .expect("npm packages object")
            .remove("packages/pregood.js")
            .expect("real workspace descriptor");
        forged["packages"]
            .as_object_mut()
            .expect("npm packages object")
            .insert(forged_target.to_owned(), workspace);
        fs::write(
            directory.path().join("package-lock.json"),
            serde_json::to_vec_pretty(&forged).expect("encode forged npm lock"),
        )
        .expect("write structurally complete forged npm lock");

        let output = command(&cache)
            .args([
                "scan",
                directory.path().to_str().expect("UTF-8 project path"),
            ])
            .output()
            .expect("scan forged npm extglob link");
        assert_exit(&output, 10);
        assert_diagnostic_only_on_stderr(&output, "no matching workspace identity");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(forged_target));
        assert!(!stderr.contains("provider hard failure"));
    }
}

#[test]
fn cargo_filters_use_exact_locked_identities_and_retain_unknowns() {
    let directory = TestDirectory::new("cargo-exact-graph-filters");
    let cache = directory.path().join("cache");
    fs::write(
        directory.path().join("Cargo.toml"),
        r#"[package]
name = "cargo-filter-root"
version = "0.1.0"
edition = "2024"

[dependencies]
prod-parent = "1"
shared-prod = { package = "shared", version = "1" }

[dev-dependencies]
dup-dev = { package = "dup", version = "1" }
shared-dev = { package = "shared", version = "1" }

[workspace]
"#,
    )
    .expect("write Cargo manifest with duplicate-name and mixed-scope declarations");
    fs::write(
        directory.path().join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "cargo-filter-root"
version = "0.1.0"
dependencies = [
 "dup 1.0.0",
 "prod-parent",
 "shared",
]

[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
dependencies = [
 "dev-child",
]

[[package]]
name = "dev-child"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"

[[package]]
name = "dup"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2222222222222222222222222222222222222222222222222222222222222222"
dependencies = [
 "prod-child",
]

[[package]]
name = "prod-child"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3333333333333333333333333333333333333333333333333333333333333333"

[[package]]
name = "prod-parent"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "4444444444444444444444444444444444444444444444444444444444444444"
dependencies = [
 "dup 2.0.0",
 "shared",
]

[[package]]
name = "shared"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "5555555555555555555555555555555555555555555555555555555555555555"

[[package]]
name = "stale-disconnected"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "6666666666666666666666666666666666666666666666666666666666666666"
"#,
    )
    .expect("write exact Cargo lock graph");
    seed_empty_cargo_dump(&cache);

    let run = |filters: &[&str]| {
        let mut arguments = vec!["scan", "--offline", "--format", "json"];
        arguments.extend_from_slice(filters);
        arguments.push(directory.path().to_str().expect("UTF-8 project path"));
        command(&cache)
            .args(arguments)
            .output()
            .expect("run Cargo graph filter scan")
    };

    let baseline = run(&[]);
    assert_exit(&baseline, 0);
    assert_eq!(
        report_package_coordinates(&json_report(&baseline)),
        BTreeSet::from([
            "cargo-filter-root@0.1.0".to_owned(),
            "dev-child@1.0.0".to_owned(),
            "dup@1.0.0".to_owned(),
            "dup@2.0.0".to_owned(),
            "prod-child@1.0.0".to_owned(),
            "prod-parent@1.0.0".to_owned(),
            "shared@1.0.0".to_owned(),
            "stale-disconnected@1.0.0".to_owned(),
        ])
    );

    let direct_only = run(&["--direct-only"]);
    assert_exit(&direct_only, 0);
    let direct_report = json_report(&direct_only);
    assert_eq!(
        report_package_coordinates(&direct_report),
        BTreeSet::from([
            "dup@1.0.0".to_owned(),
            "prod-parent@1.0.0".to_owned(),
            "shared@1.0.0".to_owned(),
            "stale-disconnected@1.0.0".to_owned(),
        ])
    );
    let stale = report_packages(&direct_report)
        .iter()
        .find(|result| {
            result
                .pointer("/package/name")
                .and_then(serde_json::Value::as_str)
                == Some("stale-disconnected")
        })
        .expect("retained disconnected Cargo record");
    assert_eq!(
        stale
            .pointer("/package/direct_known")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        stale
            .pointer("/package/dev_known")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );

    let no_dev = run(&["--no-dev"]);
    assert_exit(&no_dev, 0);
    assert_eq!(
        report_package_coordinates(&json_report(&no_dev)),
        BTreeSet::from([
            "cargo-filter-root@0.1.0".to_owned(),
            "dup@2.0.0".to_owned(),
            "prod-child@1.0.0".to_owned(),
            "prod-parent@1.0.0".to_owned(),
            "shared@1.0.0".to_owned(),
            "stale-disconnected@1.0.0".to_owned(),
        ])
    );

    let combined = run(&["--direct-only", "--no-dev"]);
    assert_exit(&combined, 0);
    assert_eq!(
        report_package_coordinates(&json_report(&combined)),
        BTreeSet::from([
            "prod-parent@1.0.0".to_owned(),
            "shared@1.0.0".to_owned(),
            "stale-disconnected@1.0.0".to_owned(),
        ])
    );
}
