use depscan_core::{DetectedSource, EcosystemParser, Package, SourceKind};
use depscan_parsers::NodeParser;
use semver::Version;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn fixture(case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bun")
        .join(case)
        .join("bun.lock")
}

fn parse(case: &str) -> Result<Vec<Package>, depscan_core::ParseError> {
    NodeParser.parse(&DetectedSource {
        path: fixture(case),
        kind: SourceKind::BunLock,
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
                    "resolved_from_range": package.resolved_from_range,
                })
            })
            .collect(),
    )
}

#[test]
fn parses_current_bun_lock_locators_without_leaking_locator_prefixes() {
    let packages = parse("current-v2-mixed").unwrap();

    insta::assert_json_snapshot!("bun_v2_mixed_packages", snapshot(&packages));
    assert!(
        packages
            .iter()
            .all(|package| Version::parse(&package.version).is_ok())
    );
    assert!(
        packages
            .iter()
            .all(|package| { !package.version.starts_with(&format!("{}@", package.name)) })
    );

    // Non-registry resolutions do not carry a trustworthy npm version in bun.lock.
    // They are validated above but never sent to npm or OSV as made-up versions.
    for non_registry in [
        "workspace-pkg",
        "local-folder",
        "local-link",
        "local-tarball",
        "git-package",
        "git-ssh",
        "remote-tarball",
    ] {
        assert!(
            packages
                .iter()
                .all(|package| package.display_name != non_registry)
        );
    }
}

#[test]
fn parses_version_one_bun_lockfiles() {
    let packages = parse("legacy-v1").unwrap();

    insta::assert_json_snapshot!("bun_v1_packages", snapshot(&packages));
    assert!(
        packages
            .iter()
            .all(|package| Version::parse(&package.version).is_ok())
    );
}

#[test]
fn parses_version_zero_workspace_tuple_shape() {
    let packages = parse("legacy-v0-workspace").unwrap();

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "left-pad");
    assert_eq!(packages[0].version, "1.3.0");
    assert!(packages[0].direct);
}

#[test]
fn rejects_malformed_bun_locator_arrays_with_context() {
    for (case, expected) in [
        ("malformed-empty-array", "must start with a string locator"),
        ("malformed-non-array", "must be a locator array"),
        (
            "malformed-scoped-locator",
            "scoped package name is missing '/'",
        ),
        (
            "malformed-registry-shape",
            "registry entries must be [locator, registry, info, integrity]",
        ),
        (
            "malformed-workspace-reference",
            "references an unknown workspace path",
        ),
        ("malformed-git-shape", "git entries must be"),
        ("malformed-path-shape", "path and tarball entries must be"),
        (
            "malformed-registry-version",
            "registry resolution is not valid SemVer",
        ),
        ("unsupported-version", "unsupported Bun lockfileVersion 3"),
    ] {
        let error = parse(case).unwrap_err().to_string();
        assert!(
            error.contains(expected),
            "{case} returned an unexpected error: {error}"
        );
        if case != "unsupported-version" {
            assert!(
                error.contains("Bun package"),
                "missing package context: {error}"
            );
        }
    }
}
