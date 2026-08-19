use depscan_core::{DetectedSource, EcosystemParser, Package, SourceKind};
use depscan_parsers::PythonParser;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn fixture(case: &str, file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/python")
        .join(case)
        .join(file)
}

fn parse(case: &str, file: &str) -> Result<Vec<Package>, depscan_core::ParseError> {
    PythonParser.parse(&DetectedSource {
        path: fixture(case, file),
        kind: SourceKind::RequirementsTxt,
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
                    "direct_known": package.direct_known,
                    "dev_known": package.dev_known,
                    "enrichable": package.enrichable,
                    "resolved_from_range": package.resolved_from_range,
                    "source": package.source_file.file_name().and_then(|name| name.to_str()),
                })
            })
            .collect(),
    )
}

#[test]
fn parses_pip_requirements_grammar_and_preserves_file_provenance() {
    let packages = parse("requirements-complete", "requirements.txt").unwrap();

    assert!(packages.iter().all(|package| package.direct));
    assert!(packages.iter().all(|package| package.direct_known));
    assert!(packages.iter().all(|package| !package.dev_known));
    assert!(
        packages
            .iter()
            .all(|package| package.source_file.is_absolute())
    );
    assert!(
        packages
            .iter()
            .all(|package| !package.name.contains(['[', ']']))
    );
    assert!(packages.iter().all(|package| {
        !matches!(
            package.name.as_str(),
            "constraint-only" | "build-constraint-only"
        )
    }));
    let urllib3 = packages
        .iter()
        .find(|package| package.name == "urllib3")
        .unwrap();
    let constraint = urllib3.manifest_constraint.as_ref().unwrap();
    assert_eq!(constraint.raw(), ">= 2, < 3, <2.8");
    assert_eq!(constraint.normalized(), ">=2, <2.8, <3");
    let unpinned = packages
        .iter()
        .find(|package| package.name == "unpinned-name")
        .unwrap();
    let constraint = unpinned.manifest_constraint.as_ref().unwrap();
    assert_eq!(constraint.raw(), "*");
    assert_eq!(constraint.normalized(), ">=0");
    assert!(
        packages
            .iter()
            .filter(|package| !package.resolved_from_range)
            .all(|package| package.manifest_constraint.is_none())
    );

    insta::assert_json_snapshot!(snapshot(&packages), @r#"
    [
      {
        "dev_known": false,
        "direct": true,
        "direct_known": true,
        "display_name": "Archive_Pkg",
        "enrichable": false,
        "name": "archive-pkg",
        "resolved_from_range": true,
        "source": "requirements.txt",
        "version": "https://example.invalid/files/Archive_Pkg-4.2.0.tar.gz#sha256=cccc"
      },
      {
        "dev_known": false,
        "direct": true,
        "direct_known": true,
        "display_name": "Attached_Pkg",
        "enrichable": true,
        "name": "attached-pkg",
        "resolved_from_range": false,
        "source": "attached.txt",
        "version": "3.0"
      },
      {
        "dev_known": false,
        "direct": true,
        "direct_known": true,
        "display_name": "Base.Pkg",
        "enrichable": true,
        "name": "base-pkg",
        "resolved_from_range": false,
        "source": "base.txt",
        "version": "1.0"
      },
      {
        "dev_known": false,
        "direct": true,
        "direct_known": true,
        "display_name": "Editable_Pkg",
        "enrichable": false,
        "name": "editable-pkg",
        "resolved_from_range": true,
        "source": "requirements.txt",
        "version": "git+https://example.invalid/repo.git@main#egg=Editable_Pkg[dev]"
      },
      {
        "dev_known": false,
        "direct": true,
        "direct_known": true,
        "display_name": "Equal.Pkg",
        "enrichable": true,
        "name": "equal-pkg",
        "resolved_from_range": false,
        "source": "equal.txt",
        "version": "4.0"
      },
      {
        "dev_known": false,
        "direct": true,
        "direct_known": true,
        "display_name": "Local_Wheel",
        "enrichable": false,
        "name": "local-wheel",
        "resolved_from_range": true,
        "source": "requirements.txt",
        "version": "./vendor/Local_Wheel-5.0-py3-none-any.whl[feature]"
      },
      {
        "dev_known": false,
        "direct": true,
        "direct_known": true,
        "display_name": "Named_URL",
        "enrichable": false,
        "name": "named-url",
        "resolved_from_range": true,
        "source": "requirements.txt",
        "version": "https://example.invalid/archive.zip"
      },
      {
        "dev_known": false,
        "direct": true,
        "direct_known": true,
        "display_name": "Nested-Pkg",
        "enrichable": true,
        "name": "nested-pkg",
        "resolved_from_range": false,
        "source": "nested.txt",
        "version": "2.0"
      },
      {
        "dev_known": false,
        "direct": true,
        "direct_known": true,
        "display_name": "Requests",
        "enrichable": true,
        "name": "requests",
        "resolved_from_range": false,
        "source": "requirements.txt",
        "version": "2.32.5"
      },
      {
        "dev_known": false,
        "direct": true,
        "direct_known": true,
        "display_name": "UnPinned_Name",
        "enrichable": false,
        "name": "unpinned-name",
        "resolved_from_range": true,
        "source": "requirements.txt",
        "version": "*"
      },
      {
        "dev_known": false,
        "direct": true,
        "direct_known": true,
        "display_name": "urllib3",
        "enrichable": false,
        "name": "urllib3",
        "resolved_from_range": true,
        "source": "requirements.txt",
        "version": ">= 2, < 3"
      }
    ]
    "#);
}

#[test]
fn custom_registry_options_disable_public_registry_enrichment() {
    let packages = parse("requirements-custom-index", "requirements.txt").unwrap();

    assert!(packages.iter().all(|package| !package.enrichable));
    assert!(
        packages
            .iter()
            .find(|package| package.name == "public-looking")
            .is_some_and(|package| !package.resolved_from_range)
    );
    assert!(
        packages
            .iter()
            .find(|package| package.name == "range-package")
            .is_some_and(|package| package.resolved_from_range)
    );
}

#[test]
fn dangerous_and_malformed_forms_fail_without_exposing_option_values() {
    for (file, expected) in [
        ("unknown-option.txt", "unsupported requirements option"),
        ("bad-hash.txt", "hexadecimal digest"),
        ("bad-requirement.txt", "invalid PEP 508 requirement"),
        ("constraint-extra.txt", "constraints must be named"),
        (
            "conflicting-constraint.txt",
            "conflicts with its constraints",
        ),
        ("remote-include.txt", "remote requirements include"),
        ("unterminated-continuation.txt", "unterminated continuation"),
    ] {
        let error = parse("requirements-malformed", file)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(expected),
            "unexpected error for {file}: {error}"
        );
        assert!(!error.contains("user:secret"));
    }
}
