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

fn package<'a>(packages: &'a [Package], name: &str, version: &str) -> &'a Package {
    packages
        .iter()
        .find(|package| package.name == name && package.version == version)
        .unwrap_or_else(|| panic!("missing {name}@{version}: {packages:#?}"))
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
fn parses_bun_14_generated_v2_and_v3_override_resolutions() {
    let v2 = parse("current-v2-generated").unwrap();
    assert_eq!(v2.len(), 1);
    assert!(package(&v2, "is-number", "7.0.0").direct);

    let off_registry = parse("current-v2-off-registry-integrity").unwrap();
    assert_eq!(off_registry.len(), 1);
    assert!(package(&off_registry, "is-number", "7.0.0").direct);

    let nested = parse("current-v3-nested").unwrap();
    assert_eq!(nested.len(), 3);
    assert!(package(&nested, "is-number", "6.0.0").direct);
    assert!(package(&nested, "is-odd", "3.0.1").direct);
    assert!(!package(&nested, "is-number", "7.0.0").direct);

    let version_scoped = parse("current-v3-version-scoped").unwrap();
    assert_eq!(version_scoped.len(), 2);
    assert!(package(&version_scoped, "is-odd", "3.0.1").direct);
    assert!(!package(&version_scoped, "is-number", "7.0.0").direct);

    assert!(parse("future-config-version").unwrap().is_empty());
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
            "malformed-v2-off-registry-integrity",
            "off-registry npm entries require a supported integrity hash",
        ),
        (
            "malformed-v2-git-tag",
            "git resolved tag must be one safe path component",
        ),
        (
            "malformed-v1-github-tag",
            "git resolved tag must be one safe path component",
        ),
        (
            "malformed-registry-version",
            "registry resolution is not valid SemVer",
        ),
        ("unsupported-version", "unsupported Bun lockfileVersion 4"),
        ("malformed-config-version", "Bun configVersion must be"),
    ] {
        let error = parse(case).unwrap_err().to_string();
        assert!(
            error.contains(expected),
            "{case} returned an unexpected error: {error}"
        );
        if !matches!(case, "unsupported-version" | "malformed-config-version") {
            assert!(
                error.contains("Bun package"),
                "missing package context: {error}"
            );
        }
    }
}
