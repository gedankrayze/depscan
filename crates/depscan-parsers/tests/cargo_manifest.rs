use depscan_core::{DetectedSource, EcosystemParser, Package, SourceKind};
use depscan_parsers::CargoParser;
use serde_json::{Value as Json, json};
use std::{collections::BTreeMap, fs, path::PathBuf};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cargo")
        .join(name)
}

fn parse(path: PathBuf, kind: SourceKind) -> Result<Vec<Package>, String> {
    CargoParser
        .parse(&DetectedSource { path, kind })
        .map_err(|error| error.to_string())
}

fn parse_inline_cargo(manifest: &str, lock: &str) -> Result<Vec<Package>, String> {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("Cargo.toml"), manifest).unwrap();
    fs::write(directory.path().join("Cargo.lock"), lock).unwrap();
    parse(directory.path().join("Cargo.lock"), SourceKind::CargoLock)
}

fn normalized(packages: &[Package], root: &std::path::Path) -> Json {
    Json::Array(
        packages
            .iter()
            .map(|package| {
                json!({
                    "name": package.name,
                    "display_name": package.display_name,
                    "version": package.version,
                    "direct": package.direct,
                    "direct_known": package.direct_known,
                    "dev": package.dev,
                    "dev_known": package.dev_known,
                    "enrichable": package.enrichable,
                    "resolved_from_range": package.resolved_from_range,
                    "source": package.source_file.strip_prefix(root).unwrap(),
                })
            })
            .collect(),
    )
}

#[test]
fn parses_virtual_workspace_members_inheritance_targets_and_sources() {
    let root = fixture("workspace-manifest");
    let packages = parse(root.join("Cargo.toml"), SourceKind::CargoToml).unwrap();

    insta::assert_json_snapshot!("cargo_workspace_manifest", normalized(&packages, &root));
    assert!(packages.iter().all(|package| package.direct));
    assert!(packages.iter().all(|package| package.resolved_from_range));
    assert_eq!(
        packages
            .iter()
            .filter(|package| package.name == "serde")
            .count(),
        2,
        "the same dependency declared by two members retains both declaring manifests"
    );
    assert!(!packages.iter().any(|package| {
        matches!(
            package.name.as_str(),
            "excluded-direct" | "unused-real" | "local-only" | "git-only"
        )
    }));
    let package = |name: &str| {
        packages
            .iter()
            .find(|package| package.name == name)
            .unwrap()
    };
    assert_eq!(package("real-crate").version, "^3");
    assert_eq!(
        package("real-crate")
            .manifest_constraint
            .as_ref()
            .map(|constraint| (constraint.raw(), constraint.normalized())),
        Some(("^3", "^3"))
    );
    assert!(package("workspace-dev").dev);
    assert!(package("target-dev").dev);
    assert!(!package("cc").dev, "build dependencies are not dev-only");
    assert!(
        !package("target-build-real").dev,
        "target build dependencies are not dev-only"
    );
    assert!(!package("local-shared").enrichable);
    assert!(!package("git-real").enrichable);
}

#[test]
fn explicit_member_workspace_pointer_resolves_the_complete_workspace() {
    let root = fixture("workspace-manifest");
    let from_root = parse(root.join("Cargo.toml"), SourceKind::CargoToml).unwrap();
    let from_member = parse(root.join("crates/app/Cargo.toml"), SourceKind::CargoToml).unwrap();

    assert_eq!(
        normalized(&from_member, &root),
        normalized(&from_root, &root)
    );
}

#[test]
fn member_without_pointer_discovers_its_parent_workspace() {
    let root = fixture("workspace-manifest");
    let from_root = parse(root.join("Cargo.toml"), SourceKind::CargoToml).unwrap();
    let from_member = parse(root.join("crates/other/Cargo.toml"), SourceKind::CargoToml).unwrap();

    assert_eq!(
        normalized(&from_member, &root),
        normalized(&from_root, &root)
    );
}

#[test]
fn prefers_lockfile_and_marks_renamed_workspace_dependencies_direct() {
    let root = fixture("workspace-manifest");
    let detected = CargoParser.detect(&root);
    assert_eq!(detected.len(), 1);
    assert_eq!(detected[0].kind, SourceKind::CargoLock);

    let packages = parse(detected[0].path.clone(), detected[0].kind.clone()).unwrap();
    insta::assert_json_snapshot!("cargo_workspace_lock", normalized(&packages, &root));
    let by_name: BTreeMap<_, _> = packages
        .iter()
        .map(|package| {
            (
                package.name.as_str(),
                (package.direct, package.dev, package.enrichable),
            )
        })
        .collect();

    assert_eq!(by_name["serde"], (true, false, true));
    assert_eq!(by_name["workspace-dev"], (true, true, true));
    assert_eq!(by_name["target-dev"], (true, true, true));
    assert_eq!(by_name["local-only"], (true, false, false));
    assert_eq!(by_name["git-only"], (true, false, false));
    assert_eq!(by_name["unused-real"], (false, false, true));
    assert_eq!(by_name["excluded-direct"], (false, false, true));

    for name in ["excluded-direct", "unused-real"] {
        let package = packages
            .iter()
            .find(|package| package.name == name)
            .unwrap();
        assert!(!package.direct_known, "{name} was spuriously transitive");
        assert!(!package.dev_known, "{name} had spuriously known scope");
    }
    for name in ["app", "other"] {
        let package = packages
            .iter()
            .find(|package| package.name == name)
            .unwrap();
        assert!(!package.direct, "project root {name} was marked direct");
        assert!(package.direct_known);
        assert!(!package.dev);
        assert!(package.dev_known);
    }
    for name in ["local-only", "local-shared"] {
        let package = packages
            .iter()
            .find(|package| package.name == name)
            .unwrap();
        assert!(package.direct, "project dependency {name} was not direct");
        assert!(package.direct_known);
        assert!(!package.dev, "project root {name} was marked dev-only");
        assert!(package.dev_known);
    }
}

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

#[test]
fn normalizes_lock_sources_with_cargo_url_semantics() {
    let manifest = r#"[package]
name = "root"
version = "1.0.0"

[dependencies]
dep = { version = "1", registry = "private" }
"#;
    let packages = parse_inline_cargo(
        manifest,
        r#"version = 4

[[package]]
name = "root"
version = "1.0.0"
dependencies = ["dep 1.0.0 (registry+https://EXAMPLE.com:443/index)"]

[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://EXAMPLE.com:443/index"
"#,
    )
    .unwrap();
    let dep = packages
        .iter()
        .find(|package| package.name == "dep")
        .unwrap();
    assert!(dep.direct && dep.direct_known);
    assert!(!dep.dev_known, "named registry scope is not URL-proven");

    parse_inline_cargo(
        manifest,
        r#"version = 4
[[package]]
name = "sparse"
version = "1.0.0"
source = "sparse+https://EXAMPLE.com:443/index"
[[package]]
name = "sparse"
version = "1.0.0"
source = "sparse+https://example.com/index"
"#,
    )
    .expect("sparse URL parsing retains the full custom-scheme port identity");

    let local = parse_inline_cargo(
        r#"[package]
name = "root"
version = "1.0.0"

[dependencies]
local = { path = "../outside-local" }
"#,
        r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
dependencies = ["local"]
[[package]]
name = "local"
version = "1.0.0"
source = "path+file:///tmp/local"
[[package]]
name = "local"
version = "1.0.0"
source = "registry+https://example.com/index"
"#,
    )
    .unwrap();
    let local = local
        .iter()
        .find(|package| package.name == "local")
        .unwrap();
    assert!(local.direct && local.direct_known);
    assert!(!local.dev_known, "path declaration scope is conservative");
}

#[test]
fn rejects_ambiguous_dangling_duplicate_and_malformed_cargo_lock_graphs() {
    let manifest = r#"[package]
name = "root"
version = "1.0.0"
"#;
    for (name, lock, expected) in [
        (
            "ambiguous",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
dependencies = ["dup"]
[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "dup"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            "omits a version",
        ),
        (
            "dangling",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
dependencies = ["missing"]
"#,
            "no matching locked package",
        ),
        (
            "self dependency",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
dependencies = ["root"]
"#,
            "cannot depend on itself",
        ),
        (
            "duplicate",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
[[package]]
name = "root"
version = "1.0.0"
"#,
            "repeats exact package identity",
        ),
        (
            "semantically duplicate source",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
source = "registry+https://EXAMPLE.com:443/index"
[[package]]
name = "root"
version = "1.0.0"
source = "registry+https://example.com/index"
"#,
            "repeats exact package identity",
        ),
        (
            "non-string edge",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
dependencies = [42]
"#,
            "must be a non-empty string",
        ),
        (
            "noncanonical dependency spacing",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
dependencies = ["dep  1.0.0"]
[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            "malformed dependency reference",
        ),
        (
            "dependencies and replace",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
dependencies = []
replace = "replacement 1.0.0"
[[package]]
name = "replacement"
version = "1.0.0"
"#,
            "cannot define both dependencies and replace",
        ),
        (
            "dangling replace",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
replace = "missing 1.0.0"
"#,
            "no matching locked package",
        ),
        (
            "replacement coordinate mismatch",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
replace = "other 2.0.0 (git+https://example.com/other#abcdef)"
[[package]]
name = "other"
version = "2.0.0"
source = "git+https://example.com/other#abcdef"
"#,
            "replacement must have the same package name and version",
        ),
        (
            "replacement cycle",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
replace = "root 1.0.0 (git+https://example.com/root#abcdef)"
[[package]]
name = "root"
version = "1.0.0"
source = "git+https://example.com/root#abcdef"
replace = "root 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"
"#,
            "replacement target cannot itself define replace",
        ),
        (
            "malformed git source",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
source = "git+not a URL"
"#,
            "invalid Git source URL",
        ),
        (
            "malformed registry source",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
source = "registry+not a URL"
"#,
            "invalid registry source URL",
        ),
    ] {
        let error = parse_inline_cargo(manifest, lock).unwrap_err();
        assert!(
            error.contains(expected),
            "{name}: expected {expected:?}, got {error:?}"
        );
    }
}

#[test]
fn malformed_workspace_and_dependency_shapes_fail_cleanly() {
    for (fixture_name, expected) in [
        (
            "malformed-missing-inherited",
            "inherits from a missing [workspace.dependencies] entry",
        ),
        (
            "malformed-package-type",
            "field \"package\" must be a string",
        ),
        ("malformed-unmatched-member", "matched no packages"),
    ] {
        let root = fixture(fixture_name);
        let error = parse(root.join("Cargo.toml"), SourceKind::CargoToml).unwrap_err();
        assert!(
            error.contains(expected),
            "{fixture_name}: expected {expected:?}, got {error:?}"
        );
    }
}
