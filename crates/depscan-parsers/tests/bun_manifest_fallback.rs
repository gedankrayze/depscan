use depscan_parsers::parse_bun_manifest_fallback;
use std::{collections::BTreeMap, fs};

#[test]
fn parses_root_and_workspace_manifests_with_range_provenance() {
    let directory = tempfile::tempdir().unwrap();
    let lock = directory.path().join("bun.lockb");
    fs::write(&lock, b"binary fixture").unwrap();
    fs::write(
        directory.path().join("package.json"),
        r#"{
            "workspaces": [".", "packages/*"],
            "dependencies": {"root-production": "^1.2.0", "local-workspace": "workspace:*"},
            "devDependencies": {"root-development": "~2.0.0"}
        }"#,
    )
    .unwrap();
    let workspace = directory.path().join("packages/member");
    fs::create_dir_all(&workspace).unwrap();
    fs::write(
        workspace.join("package.json"),
        r#"{
            "dependencies": {"workspace-production": ">=3 <4"},
            "devDependencies": {"workspace-development": "5.x"},
            "optionalDependencies": {"workspace-optional": "^6"}
        }"#,
    )
    .unwrap();

    let packages = parse_bun_manifest_fallback(&lock).unwrap();
    let packages = packages
        .iter()
        .map(|package| (package.name.as_str(), package))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(packages.len(), 6);
    for package in packages.values() {
        assert!(package.direct);
        assert!(package.direct_known);
        assert!(package.dev_known);
        assert!(package.resolved_from_range);
        assert_eq!(
            package
                .manifest_constraint
                .as_ref()
                .map(|constraint| constraint.raw()),
            Some(package.version.as_str())
        );
    }
    assert!(!packages["root-production"].dev);
    assert!(packages["root-development"].dev);
    assert!(!packages["workspace-production"].dev);
    assert!(packages["workspace-development"].dev);
    assert!(!packages["workspace-optional"].dev);
    assert!(packages["root-production"].enrichable);
    assert!(!packages["local-workspace"].enrichable);
    assert_eq!(
        packages["workspace-production"].source_file,
        fs::canonicalize(workspace.join("package.json")).unwrap()
    );
}

#[test]
fn rejects_missing_malformed_and_escaping_manifests() {
    let directory = tempfile::tempdir().unwrap();
    let lock = directory.path().join("bun.lockb");
    fs::write(&lock, b"binary fixture").unwrap();

    let missing = parse_bun_manifest_fallback(&lock).unwrap_err().to_string();
    assert!(
        missing.contains("no usable colocated manifest"),
        "{missing}"
    );

    fs::write(directory.path().join("package.json"), "not json").unwrap();
    let malformed = parse_bun_manifest_fallback(&lock).unwrap_err().to_string();
    assert!(malformed.contains("failed to parse"), "{malformed}");

    fs::write(
        directory.path().join("package.json"),
        r#"{"workspaces":["../outside"]}"#,
    )
    .unwrap();
    let escaping = parse_bun_manifest_fallback(&lock).unwrap_err().to_string();
    assert!(
        escaping.contains("must be a contained relative path pattern"),
        "{escaping}"
    );

    fs::write(
        directory.path().join("package.json"),
        r#"{"dependencies":{"invalid":42}}"#,
    )
    .unwrap();
    let malformed_dependency = parse_bun_manifest_fallback(&lock).unwrap_err().to_string();
    assert!(
        malformed_dependency.contains("must have a non-empty string constraint"),
        "{malformed_dependency}"
    );
}

#[cfg(unix)]
#[test]
fn rejects_workspace_manifest_symlinks_to_inside_and_outside_targets() {
    use std::os::unix::fs::symlink;

    for outside in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let lock = directory.path().join("bun.lockb");
        fs::write(&lock, b"binary fixture").unwrap();
        fs::write(
            directory.path().join("package.json"),
            r#"{"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        let workspace = directory.path().join("packages/member");
        fs::create_dir_all(&workspace).unwrap();
        let target = if outside {
            external.path().join("package.json")
        } else {
            directory.path().join("validated-inside-package.json")
        };
        fs::write(&target, r#"{"dependencies":{"unexpected":"1.0.0"}}"#).unwrap();
        symlink(&target, workspace.join("package.json")).unwrap();

        let error = parse_bun_manifest_fallback(&lock).unwrap_err().to_string();
        assert!(
            error.contains("must be a non-symlink regular file"),
            "workspace symlink outside={outside} returned: {error}"
        );
    }
}
