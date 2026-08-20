use super::support::*;
use depscan_core::SourceKind;
use std::fs;

#[test]
fn binds_cargo_directness_and_scope_to_exact_locked_graph_identities() {
    let root = fixture("exact-lock-graph");
    let packages = parse(root.join("Cargo.lock"), SourceKind::CargoLock).unwrap();
    let package = |name: &str, version: &str| {
        packages
            .iter()
            .find(|package| package.name == name && package.version == version)
            .unwrap_or_else(|| panic!("missing Cargo package {name}@{version}"))
    };
    let classification = |name: &str, version: &str| {
        let package = package(name, version);
        (
            package.direct,
            package.direct_known,
            package.dev,
            package.dev_known,
        )
    };

    assert_eq!(classification("dup", "1.0.0"), (true, true, true, true));
    assert_eq!(
        classification("dev-child", "1.0.0"),
        (false, true, true, true)
    );
    assert_eq!(classification("dup", "2.0.0"), (false, true, false, true));
    assert_eq!(
        classification("prod-child", "1.0.0"),
        (false, true, false, true)
    );
    assert_eq!(
        classification("shared", "1.0.0"),
        (true, true, false, true),
        "production-transitive scope must win over direct development scope"
    );
    assert_eq!(
        classification("member-lib", "0.0.0"),
        (true, true, false, true),
        "a member root remains production even when another member uses it only for development"
    );
    assert_eq!(
        classification("member-dev-child", "1.0.0"),
        (true, true, true, true),
        "incoming production root scope must not flow through a member's mixed adjacency"
    );
    assert_eq!(
        classification("member-prod-child", "1.0.0"),
        (true, true, false, true)
    );
    for name in ["prod-parent", "renamed", "git-real"] {
        assert_eq!(
            classification(name, if name == "git-real" { "3.0.0" } else { "1.0.0" }),
            (true, true, false, true)
        );
    }
    assert_eq!(
        classification("scope-collision", "1.0.0"),
        (true, true, false, false),
        "unmapped named-registry prod/dev aliases must keep scope unknown"
    );
    assert_eq!(
        classification("lookalike", "1.0.0"),
        (true, true, false, false)
    );
    assert!(!package("lookalike", "1.0.0").enrichable);
    assert!(!package("scope-collision", "1.0.0").enrichable);
    assert!(!package("git-real", "3.0.0").enrichable);
    assert_eq!(
        classification("stale", "9.0.0"),
        (false, false, false, false)
    );
    assert_eq!(classification("app", "0.5.0"), (false, true, false, true));
}

#[test]
fn parses_legacy_root_and_compact_cargo_dependency_references() {
    let root_only = parse_inline_cargo(
        r#"[package]
name = "root-only"
version = "1.0.0"
"#,
        r#"[root]
name = "root-only"
version = "1.0.0"
"#,
    )
    .unwrap();
    assert!(root_only.is_empty());

    let manifest = r#"[package]
name = "legacy-root"
version = "0.1.0"

[dependencies]
dep = "1"
"#;
    let v1 = parse_inline_cargo(
        manifest,
        r#"[root]
name = "legacy-root"
version = "0.1.0"
dependencies = ["dep 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"]

[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    )
    .unwrap();
    assert_eq!(v1.len(), 1);
    assert!(v1[0].direct && v1[0].direct_known);
    assert!(!v1[0].dev && v1[0].dev_known);

    let v2 = parse_inline_cargo(
        manifest,
        r#"[[package]]
name = "legacy-root"
version = "0.1.0"
dependencies = ["dep"]

[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    )
    .unwrap();
    let dep = v2.iter().find(|package| package.name == "dep").unwrap();
    assert!(dep.direct && dep.direct_known);
    assert!(!dep.dev && dep.dev_known);

    let legacy_git = parse_inline_cargo(
        r#"[package]
name = "legacy-root"
version = "0.1.0"

[dependencies]
same = { git = "https://example.com/repo", branch = "master" }
"#,
        r#"[root]
name = "legacy-root"
version = "0.1.0"
dependencies = ["same 1.0.0 (git+https://example.com/repo)"]

[[package]]
name = "same"
version = "1.0.0"
source = "git+https://example.com/repo?branch=master#0123456789abcdef"

[[package]]
name = "same"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    )
    .unwrap();
    assert_eq!(legacy_git.len(), 1);
    assert!(legacy_git[0].direct && legacy_git[0].direct_known);
    assert!(!legacy_git[0].dev && legacy_git[0].dev_known);

    let legacy_default_manifest = parse_inline_cargo(
        r#"[package]
name = "legacy-root"
version = "0.1.0"

[dev-dependencies]
same = { git = "https://example.com/repo" }
"#,
        r#"[root]
name = "legacy-root"
version = "0.1.0"
dependencies = ["same 1.0.0 (git+https://example.com/repo)"]

[[package]]
name = "same"
version = "1.0.0"
source = "git+https://example.com/repo?branch=master#0123456789abcdef"
"#,
    )
    .unwrap();
    assert!(legacy_default_manifest[0].direct && legacy_default_manifest[0].direct_known);
    assert!(
        !legacy_default_manifest[0].dev_known,
        "legacy edge normalization must not prove mismatched manifest scope"
    );
}

#[test]
fn incomplete_project_identity_keeps_the_aggregate_graph_unknown() {
    let packages = parse_inline_cargo(
        r#"[package]
name = "root"
version = "1.0.0"

[dependencies]
dep = "1"
"#,
        r#"version = 4

[[package]]
name = "root"
version = "2.0.0"
dependencies = ["dep"]

[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    )
    .unwrap();
    assert!(packages.iter().all(|package| !package.direct_known));
    assert!(packages.iter().all(|package| !package.dev_known));
}

#[test]
fn unverified_path_declaration_cannot_assign_known_development_scope() {
    let packages = parse_inline_cargo(
        r#"[package]
name = "root"
version = "1.0.0"

[dev-dependencies]
renamed = { package = "path-target", path = "../not-the-locked-target" }

[workspace]
"#,
        r#"version = 4

[[package]]
name = "root"
version = "1.0.0"
dependencies = ["path-target"]

[[package]]
name = "path-target"
version = "1.0.0"
"#,
    )
    .unwrap();
    let target = packages
        .iter()
        .find(|package| package.name == "path-target")
        .unwrap();
    assert!(target.direct && target.direct_known);
    assert!(
        !target.dev_known,
        "an unverified path must keep scope unknown"
    );
}

#[test]
fn duplicate_workspace_member_identity_fails_before_graph_classification() {
    let directory = tempfile::tempdir().unwrap();
    for member in ["one", "two"] {
        let path = directory.path().join(member);
        fs::create_dir(&path).unwrap();
        fs::write(
            path.join("Cargo.toml"),
            r#"[package]
name = "duplicate-member"
version = "1.0.0"
"#,
        )
        .unwrap();
    }
    fs::write(
        directory.path().join("Cargo.toml"),
        r#"[workspace]
members = ["one", "two"]
"#,
    )
    .unwrap();
    fs::write(
        directory.path().join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "duplicate-member"
version = "1.0.0"
"#,
    )
    .unwrap();

    let error = parse(directory.path().join("Cargo.lock"), SourceKind::CargoLock).unwrap_err();
    assert!(error.contains("repeats package identity"), "{error}");
}

#[test]
fn replacement_edges_keep_scope_unknown_and_reach_replacement_children() {
    let packages = parse_inline_cargo(
        r#"[package]
name = "root"
version = "1.0.0"

[dev-dependencies]
patched = "1"
"#,
        r#"version = 4

[[package]]
name = "root"
version = "1.0.0"
dependencies = [
 "patched 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "patched"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
replace = "patched 1.0.0 (path+file:///tmp/patched)"

[[package]]
name = "patched"
version = "1.0.0"
source = "path+file:///tmp/patched"
dependencies = ["replacement-child"]

[[package]]
name = "replacement-child"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    )
    .unwrap();
    let patched = packages
        .iter()
        .find(|package| package.name == "patched")
        .unwrap();
    assert!(patched.direct && patched.direct_known);
    assert!(!patched.dev_known, "replacement scope must remain unknown");
    assert!(
        !patched.enrichable,
        "the replaced public placeholder is not resolved"
    );

    let child = packages
        .iter()
        .find(|package| package.name == "replacement-child")
        .unwrap();
    assert!(!child.direct && child.direct_known);
    assert!(
        !child.dev_known,
        "unknown replacement scope must reach children"
    );
}
