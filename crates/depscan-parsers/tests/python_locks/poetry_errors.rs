use depscan_core::{DetectedSource, EcosystemParser, SourceKind};
use depscan_parsers::PythonParser;
use std::fs;

#[test]
fn rejects_unsupported_and_malformed_poetry_lockfiles_with_context() {
    let valid = r#"[[package]]
name = "dependency"
version = "1.0.0"
optional = false
groups = ["main"]

[metadata]
lock-version = "2.1"
"#;
    for (case, input, expected) in [
        (
            "future-version",
            valid.replace("lock-version = \"2.1\"", "lock-version = \"2.2\""),
            "unsupported Poetry lock-version \"2.2\"",
        ),
        (
            "missing-optional",
            valid.replace("optional = false\n", ""),
            "missing a boolean optional",
        ),
        (
            "malformed-groups",
            valid.replace("groups = [\"main\"]", "groups = \"main\""),
            "missing an array groups",
        ),
        (
            "invalid-version",
            valid.replace("version = \"1.0.0\"", "version = \"bad version\""),
            "not valid PEP 440",
        ),
        (
            "invalid-package-name",
            valid.replace("name = \"dependency\"", "name = \"dependency-\""),
            "contains invalid Python package name",
        ),
        (
            "missing-metadata",
            valid.replace("[metadata]\nlock-version = \"2.1\"\n", ""),
            "missing a metadata table",
        ),
        (
            "unsupported-source",
            valid.replace(
                "groups = [\"main\"]",
                "groups = [\"main\"]\n\n[package.source]\ntype = \"mystery\"\nurl = \"https://example.invalid\"",
            ),
            "unsupported Poetry source type \"mystery\"",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let lock = directory.path().join("poetry.lock");
        fs::write(&lock, input).unwrap();
        let error = PythonParser
            .parse(&DetectedSource {
                path: lock,
                kind: SourceKind::PoetryLock,
            })
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{case}: {error}");
        assert!(error.contains("poetry.lock"), "{case}: {error}");
    }
}
