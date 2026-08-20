use super::*;

#[test]
fn parses_cargo_lock() {
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("Cargo.lock");
    fs::write(&lock, "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n").unwrap();
    let result = CargoParser
        .parse(&DetectedSource {
            path: lock,
            kind: SourceKind::CargoLock,
        })
        .unwrap();
    assert_eq!(result[0].name, "serde");
    assert!(!result[0].direct_known);
    assert!(!result[0].dev_known);
}

#[test]
fn package_json_preserves_the_original_npm_range() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("package.json");
    fs::write(
        &manifest,
        r#"{"dependencies":{"range-package":"^1.2 || 3.x"}}"#,
    )
    .unwrap();

    let packages = parse_package_json_project(&manifest).unwrap();

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].version, "^1.2 || 3.x");
    let constraint = packages[0].manifest_constraint.as_ref().unwrap();
    assert_eq!(constraint.raw(), "^1.2 || 3.x");
    assert_eq!(constraint.normalized(), constraint.raw());
}

#[test]
fn parses_pnpm_scoped_key() {
    assert_eq!(
        parse_pnpm_key("/@scope/pkg@1.2.3(peer@2)"),
        Some(("@scope/pkg", "1.2.3"))
    );
}
