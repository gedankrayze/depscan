use depscan_core::{DetectedSource, EcosystemParser, Package, SourceKind};
use depscan_parsers::NodeParser;
use semver::Version;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn fixture(case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/yarn")
        .join(case)
        .join("yarn.lock")
}

fn parse(case: &str) -> Result<Vec<Package>, depscan_core::ParseError> {
    NodeParser.parse(&DetectedSource {
        path: fixture(case),
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
