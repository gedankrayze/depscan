use depscan_core::{DetectedSource, EcosystemParser, Package, SourceKind};
use depscan_parsers::PythonParser;
use serde_json::{Value, json};
use std::fs;

fn parse(value: Value) -> Result<Vec<Package>, depscan_core::ParseError> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("Pipfile.lock");
    fs::write(&path, value.to_string()).unwrap();
    PythonParser.parse(&DetectedSource {
        path,
        kind: SourceKind::PipfileLock,
    })
}

fn lock() -> Value {
    json!({
        "_meta": {"pipfile-spec": 6, "sources": [
            {"name": "pypi", "url": "https://pypi.org/simple"},
            {"name": "private", "url": "https://user:secret@private.test/simple"}
        ]},
        "default": {}, "develop": {}
    })
}

#[test]
fn pipfile_index_and_nonregistry_sources_do_not_become_public_coordinates() {
    let mut value = lock();
    value["default"] = json!({
        "public": {"version": "==1.0", "index": "pypi"},
        "private": {"version": "==1.0", "index": "private"},
        "unknown": {"version": "==1.0", "index": "unknown"},
        "ambiguous": {"version": "==1.0"},
        "git-pin": {"version": "==1.0", "git": "https://user:secret@git.test/repo"},
        "path-pin": {"version": "==1.0", "path": "../private"},
        "source-only": {"file": "https://user:secret@private.test/archive.whl"}
    });
    let packages = parse(value).unwrap();
    assert_eq!(packages.len(), 7);
    for package in &packages {
        assert_eq!(package.enrichable, package.name == "public", "{package:?}");
        assert!(!package.version.contains("secret"));
    }
}

#[test]
fn pipfile_custom_categories_are_retained_with_unknown_scope() {
    let mut value = lock();
    value["_meta"]["sources"].as_array_mut().unwrap().pop();
    value["docs"] = json!({"sphinx": {"version": "==8.0"}});
    let packages = parse(value).unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "sphinx");
    assert!(!packages[0].dev_known);
    assert!(!packages[0].direct_known);
    assert!(packages[0].enrichable);
}

#[test]
fn pipfile_missing_and_duplicate_sources_never_guess_public_identity() {
    let mut value = lock();
    value["_meta"].as_object_mut().unwrap().remove("sources");
    value["default"] = json!({"pkg": {"version": "==1.0"}});
    assert!(!parse(value).unwrap()[0].enrichable);

    let mut value = lock();
    value["_meta"]["sources"][1]["name"] = json!("pypi");
    let error = parse(value).unwrap_err().to_string();
    assert!(error.contains("source names must be unique"));
    assert!(!error.contains("secret"));
}

#[test]
fn pipfile_rejects_malformed_pins_categories_and_source_metadata() {
    for (field, malformed) in [
        ("default", json!({"pkg": {"version": ">=1.0"}})),
        ("default", json!({"pkg": {"version": "===1.0"}})),
        ("default", json!({"pkg": {"version": "==not-a-version"}})),
        ("docs", json!([])),
        ("_meta", json!({"pipfile-spec": 6, "sources": "invalid"})),
    ] {
        let mut value = lock();
        value[field] = malformed;
        assert!(parse(value).is_err(), "accepted malformed {field}");
    }
}

#[test]
fn pipfile_a_public_occurrence_keeps_a_duplicate_coordinate_enrichable() {
    let mut value = lock();
    value["default"] = json!({"pkg": {"version": "==1.0", "index": "private"}});
    value["docs"] = json!({"pkg": {"version": "==1.0", "index": "pypi"}});
    let packages = parse(value).unwrap();
    assert_eq!(packages.len(), 1);
    assert!(packages[0].enrichable);
    assert!(packages[0].dev_known);
    assert!(!packages[0].dev);
}
