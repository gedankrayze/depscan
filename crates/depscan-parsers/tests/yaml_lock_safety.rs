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

fn write_pnpm_project(package_json: Option<&str>, lock: &str) -> (tempfile::TempDir, PathBuf) {
    let project = tempfile::tempdir().unwrap();
    let path = project.path().join("pnpm-lock.yaml");
    fs::write(&path, lock).unwrap();
    if let Some(package_json) = package_json {
        fs::write(project.path().join("package.json"), package_json).unwrap();
    }
    (project, path)
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
fn pnpm_v9_importers_bind_exact_alias_peer_and_version_coordinates() {
    let (_project, path) = write_pnpm_project(
        Some("{not-json"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alias-name:
        specifier: npm:actual@^1.0.0
        version: actual@1.2.3(peer@2.0.0)
      peer-exact:
        specifier: 3.0.0
        version: 3.0.0(peer@2.0.0)
      peer-unmatched:
        specifier: 4.0.0
        version: 4.0.0(peer@2.0.0)
      same:
        specifier: ^1.0.0
        version: 1.0.0
packages:
  actual@1.2.3:
    resolution: {integrity: sha512-alias}
    dev: false
  peer-exact@3.0.0:
    resolution: {integrity: sha512-peer-exact}
    dev: false
  peer-unmatched@4.0.0:
    resolution: {integrity: sha512-peer-unmatched}
    dev: false
  same@1.0.0:
    resolution: {integrity: sha512-direct}
    dev: false
  same@2.0.0:
    resolution: {integrity: sha512-unmatched}
    dev: false
  orphan@5.0.0:
    resolution: {integrity: sha512-orphan}
    dev: false
snapshots:
  actual@1.2.3(peer@2.0.0): {}
  peer-exact@3.0.0(peer@2.0.0): {}
  peer-unmatched@4.0.0(peer@3.0.0): {}
  same@1.0.0: {}
  same@2.0.0: {}
  orphan@5.0.0: {}
"#,
    );
    let packages = parse(path, SourceKind::PnpmLock).unwrap();
    let package = |name: &str, version: &str| {
        packages
            .iter()
            .find(|package| package.name == name && package.version == version)
            .unwrap_or_else(|| panic!("missing pnpm package {name}@{version}"))
    };

    let alias = package("actual", "1.2.3");
    assert!(alias.direct);
    assert!(alias.direct_known);
    assert_eq!(alias.display_name, "alias-name");

    let peer_exact = package("peer-exact", "3.0.0");
    assert!(peer_exact.direct);
    assert!(peer_exact.direct_known);

    let direct_version = package("same", "1.0.0");
    assert!(direct_version.direct);
    assert!(direct_version.direct_known);

    for unknown in [
        package("peer-unmatched", "4.0.0"),
        package("same", "2.0.0"),
        package("orphan", "5.0.0"),
    ] {
        assert!(!unknown.direct);
        assert!(!unknown.direct_known);
    }
}

#[test]
fn pnpm_v6_importers_bind_only_exact_resolved_coordinates() {
    let (_project, path) = write_pnpm_project(
        None,
        r#"lockfileVersion: 6.0
importers:
  .:
    dependencies:
      left-pad:
        specifier: ^1.0.0
        version: 1.3.0
    devDependencies:
      alias-dev:
        specifier: npm:@scope/pkg@^2.0.0
        version: /@scope/pkg@2.0.1(peer@1.0.0)
packages:
  /left-pad@1.3.0:
    resolution: {integrity: sha512-left-pad}
    dev: false
  /@scope/pkg@2.0.1(peer@1.0.0):
    resolution: {integrity: sha512-alias-dev}
    dev: false
  /left-pad@2.0.0:
    resolution: {integrity: sha512-unmatched}
    dev: false
"#,
    );
    let packages = parse(path, SourceKind::PnpmLock).unwrap();
    let left_pad = packages
        .iter()
        .find(|package| package.name == "left-pad" && package.version == "1.3.0")
        .unwrap();
    assert!(left_pad.direct);
    assert!(left_pad.direct_known);
    assert!(!left_pad.dev);

    let alias = packages
        .iter()
        .find(|package| package.name == "@scope/pkg")
        .unwrap();
    assert!(alias.direct);
    assert!(alias.direct_known);
    assert!(alias.dev);
    assert_eq!(alias.display_name, "alias-dev");

    let unmatched = packages
        .iter()
        .find(|package| package.name == "left-pad" && package.version == "2.0.0")
        .unwrap();
    assert!(!unmatched.direct);
    assert!(!unmatched.direct_known);
}

#[test]
fn pnpm_v6_single_project_dependency_groups_are_importer_evidence() {
    let (_project, path) = write_pnpm_project(
        None,
        r#"lockfileVersion: 6.0
dependencies:
  left-pad:
    specifier: ^1.0.0
    version: 1.3.0
packages:
  /left-pad@1.3.0:
    resolution: {integrity: sha512-left-pad}
    dev: false
"#,
    );
    let packages = parse(path, SourceKind::PnpmLock).unwrap();
    assert_eq!(packages.len(), 1);
    assert!(packages[0].direct);
    assert!(packages[0].direct_known);
}

#[test]
fn pnpm_without_importer_evidence_does_not_guess_from_manifests() {
    let lock = r#"lockfileVersion: 6.0
packages:
  /left-pad@1.3.0:
    resolution: {integrity: sha512-fixture}
    dev: false
"#;
    for package_json in [None, Some("{not-json")] {
        let (_project, path) = write_pnpm_project(package_json, lock);
        let packages = parse(path, SourceKind::PnpmLock).unwrap();
        assert_eq!(packages.len(), 1);
        assert!(!packages[0].direct);
        assert!(!packages[0].direct_known);
    }
}

#[test]
fn pnpm_dev_scope_requires_a_package_field_or_exact_importer_evidence() {
    let (_project, path) = write_pnpm_project(
        None,
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      direct-production:
        specifier: 1.0.0
        version: 1.0.0
    devDependencies:
      direct-development:
        specifier: 1.0.0
        version: 1.0.0
packages:
  direct-production@1.0.0:
    resolution: {integrity: sha512-production}
  direct-development@1.0.0:
    resolution: {integrity: sha512-development}
  transitive-development@1.0.0:
    resolution: {integrity: sha512-transitive-development}
    dev: true
  transitive-production@1.0.0:
    resolution: {integrity: sha512-transitive-production}
    dev: false
  transitive-unknown@1.0.0:
    resolution: {integrity: sha512-transitive-unknown}
snapshots:
  direct-production@1.0.0: {}
  direct-development@1.0.0: {}
  transitive-development@1.0.0: {}
  transitive-production@1.0.0: {}
  transitive-unknown@1.0.0: {}
"#,
    );
    let packages = parse(path, SourceKind::PnpmLock).unwrap();
    let package = |name: &str| {
        packages
            .iter()
            .find(|package| package.name == name)
            .unwrap_or_else(|| panic!("missing pnpm package {name}"))
    };

    let direct_production = package("direct-production");
    assert!(direct_production.direct);
    assert!(!direct_production.dev);
    assert!(direct_production.dev_known);

    let direct_development = package("direct-development");
    assert!(direct_development.direct);
    assert!(direct_development.dev);
    assert!(direct_development.dev_known);

    let transitive_development = package("transitive-development");
    assert!(transitive_development.dev);
    assert!(transitive_development.dev_known);

    let transitive_production = package("transitive-production");
    assert!(!transitive_production.dev);
    assert!(transitive_production.dev_known);

    let transitive_unknown = package("transitive-unknown");
    assert!(!transitive_unknown.dev);
    assert!(!transitive_unknown.dev_known);
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
