use depscan_core::{DetectedSource, EcosystemParser, Package, SourceKind};
use depscan_parsers::NodeParser;
use semver::Version;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn fixture(case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/yarn")
        .join(case)
        .join("yarn.lock")
}

fn parse(case: &str) -> Result<Vec<Package>, depscan_core::ParseError> {
    parse_path(fixture(case))
}

fn parse_path(path: PathBuf) -> Result<Vec<Package>, depscan_core::ParseError> {
    NodeParser.parse(&DetectedSource {
        path,
        kind: SourceKind::YarnLock,
    })
}

fn snapshot(packages: &[Package]) -> Value {
    Value::Array(
        packages
            .iter()
            .map(|package| {
                json!({
                    "name": package.name,
                    "display_name": package.display_name,
                    "version": package.version,
                    "direct": package.direct,
                    "dev": package.dev,
                    "enrichable": package.enrichable,
                    "source": package.source_file.file_name().and_then(|name| name.to_str()),
                })
            })
            .collect(),
    )
}

#[test]
fn deep_declared_yarn_workspaces_are_direct_but_arbitrary_manifests_are_ignored() {
    let packages = parse("deep-workspace-directness").unwrap();
    let package = |name: &str, version: &str| {
        packages
            .iter()
            .find(|package| package.name == name && package.version == version)
            .unwrap_or_else(|| panic!("missing Yarn package {name}@{version}"))
    };

    for (name, version) in [
        ("alias-target", "3.1.0"),
        ("deep-direct", "1.0.0"),
        ("normalized-direct", "6.2.2"),
        ("root-direct", "1.0.0"),
        ("same-name", "1.5.0"),
    ] {
        let package = package(name, version);
        assert!(package.direct, "{name}@{version} was not direct");
        assert!(package.direct_known);
        assert!(
            package.dev_known,
            "{name}@{version} had unknown development scope"
        );
    }
    for (name, version) in [
        ("alias-target", "4.1.0"),
        ("ambiguous-direct", "7.1.0"),
        ("ambiguous-direct", "7.2.0"),
        ("ignored-direct", "1.0.0"),
        ("mismatched-selector", "2.1.0"),
        ("same-name", "2.5.0"),
        ("transitive", "1.0.0"),
    ] {
        let package = package(name, version);
        assert!(!package.direct, "{name}@{version} was spuriously direct");
        assert!(
            !package.direct_known,
            "unbound {name}@{version} was spuriously classified as transitive"
        );
        assert!(
            !package.dev_known,
            "unbound {name}@{version} had spuriously known development scope"
        );
    }
}

#[test]
fn missing_and_malformed_yarn_manifests_keep_directness_unknown() {
    let source = fixture("deep-workspace-directness");
    for malformed in [false, true] {
        let project = tempfile::tempdir().unwrap();
        let lock = project.path().join("yarn.lock");
        fs::copy(&source, &lock).unwrap();
        if malformed {
            fs::write(project.path().join("package.json"), "{not-json").unwrap();
        }

        let packages = parse_path(lock).unwrap();
        assert!(packages.iter().all(|package| !package.direct));
        assert!(packages.iter().all(|package| !package.direct_known));
        assert!(packages.iter().all(|package| !package.dev_known));
    }
}

#[cfg(unix)]
#[test]
fn symlinked_root_manifest_cannot_prove_yarn_directness() {
    use std::os::unix::fs::symlink;

    let project = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let lock = project.path().join("yarn.lock");
    fs::copy(fixture("deep-workspace-directness"), &lock).unwrap();
    let outside_manifest = outside.path().join("package.json");
    fs::write(
        &outside_manifest,
        r#"{"dependencies":{"root-direct":"1.0.0"}}"#,
    )
    .unwrap();
    symlink(&outside_manifest, project.path().join("package.json")).unwrap();

    let packages = parse_path(lock).unwrap();
    assert!(packages.iter().all(|package| !package.direct));
    assert!(packages.iter().all(|package| !package.direct_known));
    assert!(packages.iter().all(|package| !package.dev_known));
}

#[test]
fn proven_yarn_directness_survives_an_unreadable_workspace_manifest() {
    let project = tempfile::tempdir().unwrap();
    let lock = project.path().join("yarn.lock");
    fs::copy(fixture("deep-workspace-directness"), &lock).unwrap();
    fs::write(
        project.path().join("package.json"),
        r#"{"workspaces":["packages/*"],"dependencies":{"root-direct":"1.0.0"}}"#,
    )
    .unwrap();
    fs::create_dir(project.path().join("packages")).unwrap();
    fs::create_dir(project.path().join("packages/bad")).unwrap();
    fs::write(project.path().join("packages/bad/package.json"), "{bad").unwrap();

    let packages = parse_path(lock).unwrap();
    let root = packages
        .iter()
        .find(|package| package.name == "root-direct")
        .unwrap();
    assert!(root.direct);
    assert!(root.direct_known);
    assert!(root.dev_known);
    assert!(
        packages
            .iter()
            .filter(|package| package.name != "root-direct")
            .all(|package| !package.direct && !package.direct_known && !package.dev_known)
    );
}

#[test]
fn parses_current_yarn_berry_with_aliases_workspaces_and_protocols() {
    let lock = fixture("berry-v10");
    let packages = parse("berry-v10").unwrap();

    assert!(packages.iter().all(|package| package.source_file == lock));
    assert!(
        packages
            .iter()
            .filter(|package| package.enrichable)
            .all(|package| Version::parse(&package.version).is_ok())
    );
    assert!(
        packages
            .iter()
            .all(|package| !matches!(package.name.as_str(), "berry-root" | "workspace-pkg"))
    );
    assert!(
        packages
            .iter()
            .all(|package| package.dev_known == package.direct)
    );
    insta::assert_json_snapshot!(snapshot(&packages), @r#"
    [
      {
        "dev": false,
        "direct": true,
        "display_name": "@colors/colors",
        "enrichable": true,
        "name": "@colors/colors",
        "source": "yarn.lock",
        "version": "1.6.0"
      },
      {
        "dev": true,
        "direct": true,
        "display_name": "balanced-match",
        "enrichable": true,
        "name": "balanced-match",
        "source": "yarn.lock",
        "version": "1.0.2"
      },
      {
        "dev": false,
        "direct": false,
        "display_name": "is-number",
        "enrichable": true,
        "name": "is-number",
        "source": "yarn.lock",
        "version": "6.0.0"
      },
      {
        "dev": false,
        "direct": true,
        "display_name": "@scope/alias",
        "enrichable": true,
        "name": "is-number",
        "source": "yarn.lock",
        "version": "7.0.0"
      },
      {
        "dev": true,
        "direct": true,
        "display_name": "is-odd",
        "enrichable": true,
        "name": "is-odd",
        "source": "yarn.lock",
        "version": "3.0.1"
      },
      {
        "dev": false,
        "direct": true,
        "display_name": "kleur",
        "enrichable": true,
        "name": "kleur",
        "source": "yarn.lock",
        "version": "4.1.5"
      },
      {
        "dev": false,
        "direct": true,
        "display_name": "local-file",
        "enrichable": false,
        "name": "local-file",
        "source": "yarn.lock",
        "version": "2.3.4"
      },
      {
        "dev": false,
        "direct": true,
        "display_name": "wrappy",
        "enrichable": true,
        "name": "wrappy",
        "source": "yarn.lock",
        "version": "1.0.2"
      }
    ]
    "#);
}

#[test]
fn preserves_yarn_classic_parsing_and_manifest_provenance() {
    let lock = fixture("classic-v1");
    let packages = parse("classic-v1").unwrap();

    assert!(packages.iter().all(|package| package.source_file == lock));
    assert!(
        packages
            .iter()
            .filter(|package| package.enrichable)
            .all(|package| Version::parse(&package.version).is_ok())
    );
    assert!(
        packages
            .iter()
            .all(|package| package.dev_known == package.direct)
    );
    insta::assert_json_snapshot!(snapshot(&packages), @r#"
    [
      {
        "dev": false,
        "direct": true,
        "display_name": "@colors/colors",
        "enrichable": true,
        "name": "@colors/colors",
        "source": "yarn.lock",
        "version": "1.6.0"
      },
      {
        "dev": true,
        "direct": true,
        "display_name": "balanced-match",
        "enrichable": true,
        "name": "balanced-match",
        "source": "yarn.lock",
        "version": "1.0.2"
      },
      {
        "dev": false,
        "direct": false,
        "display_name": "is-number",
        "enrichable": true,
        "name": "is-number",
        "source": "yarn.lock",
        "version": "6.0.0"
      },
      {
        "dev": false,
        "direct": true,
        "display_name": "@scope/alias",
        "enrichable": true,
        "name": "is-number",
        "source": "yarn.lock",
        "version": "7.0.0"
      },
      {
        "dev": true,
        "direct": true,
        "display_name": "is-odd",
        "enrichable": true,
        "name": "is-odd",
        "source": "yarn.lock",
        "version": "3.0.1"
      },
      {
        "dev": false,
        "direct": true,
        "display_name": "local-file",
        "enrichable": false,
        "name": "local-file",
        "source": "yarn.lock",
        "version": "2.3.4"
      },
      {
        "dev": false,
        "direct": true,
        "display_name": "wrappy",
        "enrichable": true,
        "name": "wrappy",
        "source": "yarn.lock",
        "version": "1.0.2"
      }
    ]
    "#);
}

#[test]
fn rejects_unsupported_or_malformed_yarn_lockfiles_with_context() {
    for (case, expected) in [
        (
            "unsupported-version",
            "unsupported Yarn Berry lockfile version 11",
        ),
        ("missing-resolution", "missing a string resolution"),
        (
            "mismatched-version",
            "version \"1.2.0\" does not match npm resolution \"npm:1.3.0\"",
        ),
        ("classic-missing-version", "is missing version"),
        ("unrecognized", "unrecognized Yarn lockfile"),
    ] {
        let error = parse(case).unwrap_err().to_string();
        assert!(
            error.contains(expected),
            "{case} returned an unexpected error: {error}"
        );
        assert!(
            error.contains("yarn.lock"),
            "{case} omitted source context: {error}"
        );
    }
}
