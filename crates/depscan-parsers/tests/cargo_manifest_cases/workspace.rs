use super::support::*;
use depscan_core::{EcosystemParser, SourceKind};
use depscan_parsers::CargoParser;
use std::collections::BTreeMap;

#[test]
fn parses_virtual_workspace_members_inheritance_targets_and_sources() {
    let root = fixture("workspace-manifest");
    let packages = parse(root.join("Cargo.toml"), SourceKind::CargoToml).unwrap();

    insta::with_settings!({
        snapshot_path => "../snapshots",
        prepend_module_to_snapshot => false,
    }, {
        insta::assert_json_snapshot!("cargo_manifest__cargo_workspace_manifest", normalized(&packages, &root));
    });
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
    insta::with_settings!({
        snapshot_path => "../snapshots",
        prepend_module_to_snapshot => false,
    }, {
        insta::assert_json_snapshot!("cargo_manifest__cargo_workspace_lock", normalized(&packages, &root));
    });
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
