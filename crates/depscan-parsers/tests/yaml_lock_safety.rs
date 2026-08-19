use depscan_core::{DetectedSource, EcosystemParser, Package, SourceKind};
use depscan_parsers::NodeParser;
use std::fs;
use std::path::{Path, PathBuf};

fn fixture(format: &str, case: &str, file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format)
        .join(case)
        .join(file)
}

fn parse(path: PathBuf, kind: SourceKind) -> Result<Vec<Package>, depscan_core::ParseError> {
    NodeParser.parse(&DetectedSource { path, kind })
}

fn parse_pnpm(case: &str) -> Result<Vec<Package>, depscan_core::ParseError> {
    parse(
        fixture("pnpm", case, "pnpm-lock.yaml"),
        SourceKind::PnpmLock,
    )
}

#[test]
fn preserves_current_pnpm_schema_and_manifest_provenance() {
    let packages = parse_pnpm("current-v9").unwrap();

    let left_pad = packages
        .iter()
        .find(|package| package.name == "left-pad")
        .unwrap();
    assert_eq!(left_pad.version, "1.3.0");
    assert!(left_pad.direct);
    assert!(!left_pad.dev);

    let scoped = packages
        .iter()
        .find(|package| package.name == "@scope/pkg")
        .unwrap();
    assert_eq!(scoped.version, "2.0.1");
    assert!(scoped.direct);
    assert!(scoped.dev);
}

#[test]
fn permits_bounded_anchor_reuse_for_compatible_lockfiles() {
    let packages = parse_pnpm("anchored").unwrap();

    assert_eq!(packages.len(), 2);
    assert!(packages.iter().all(|package| package.dev));
}

#[test]
fn rejects_duplicate_keys_in_pnpm_and_yarn_berry() {
    for (path, kind) in [
        (
            fixture("pnpm", "duplicate-key", "pnpm-lock.yaml"),
            SourceKind::PnpmLock,
        ),
        (
            fixture("yarn", "duplicate-key", "yarn.lock"),
            SourceKind::YarnLock,
        ),
    ] {
        let error = parse(path.clone(), kind).unwrap_err().to_string();
        assert!(
            error.contains("duplicate key"),
            "{} returned an unexpected error: {error}",
            path.display()
        );
        assert!(
            error.contains(path.file_name().unwrap().to_str().unwrap()),
            "{} omitted source context: {error}",
            path.display()
        );
    }
}

#[test]
fn rejects_merge_keys_excessive_alias_expansion_and_deep_nesting() {
    for (case, expected) in [
        ("merge-key", "merge"),
        ("alias-bomb", "alias"),
        ("deep-nesting", "depth"),
    ] {
        let error = parse_pnpm(case).unwrap_err().to_string();
        assert!(
            error.to_ascii_lowercase().contains(expected),
            "{case} returned an unexpected error: {error}"
        );
        assert!(
            error.contains("pnpm-lock.yaml"),
            "{case} omitted source context: {error}"
        );
    }
}

#[test]
fn rejects_oversized_yaml_scalars() {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().join("pnpm-lock.yaml");
    let oversized = "x".repeat(1024 * 1024 + 1);
    fs::write(
        &path,
        format!("lockfileVersion: '9.0'\npayload: {oversized}\npackages: {{}}\n"),
    )
    .unwrap();

    let error = parse(path, SourceKind::PnpmLock).unwrap_err().to_string();
    assert!(
        error.contains("MaxScalarLength") && error.contains("exceeds limit"),
        "large scalar returned an unexpected error: {error}"
    );
}
