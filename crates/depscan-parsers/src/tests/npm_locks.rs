use super::*;

#[test]
fn npm_v3_lock_edges_prove_exact_directness_without_external_manifests() {
    assert_npm_lock_edge_directness(&npm_fixture_packages("npm-v3-directness"));
}

#[test]
fn npm_v2_lock_edges_prove_exact_directness_without_external_manifest() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/npm-v3-directness/package-lock.json");
    let mut value: Json = serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
    value["lockfileVersion"] = json!(2);
    let packages = parse_npm_value(&value).unwrap();
    assert_npm_lock_edge_directness(&packages);
}

#[test]
fn parses_nested_npm_v2_packages_and_workspace_dependencies() {
    let packages = npm_fixture_packages("npm-v2-nested");

    insta::assert_json_snapshot!(normalized_npm_packages(&packages), @r#"
    [
      {
        "dev": false,
        "direct": false,
        "name": "@nested/tool",
        "source": "package-lock.json",
        "version": "1.5.0"
      },
      {
        "dev": false,
        "direct": true,
        "name": "@scope/root",
        "source": "package-lock.json",
        "version": "3.0.0"
      },
      {
        "dev": false,
        "direct": true,
        "name": "alpha",
        "source": "package-lock.json",
        "version": "2.0.0"
      },
      {
        "dev": true,
        "direct": false,
        "name": "dev-child",
        "source": "package-lock.json",
        "version": "1.0.0"
      },
      {
        "dev": true,
        "direct": true,
        "name": "dev-tool",
        "source": "package-lock.json",
        "version": "4.0.0"
      },
      {
        "dev": false,
        "direct": false,
        "name": "duplicate",
        "source": "package-lock.json",
        "version": "1.0.0"
      },
      {
        "dev": false,
        "direct": true,
        "name": "duplicate",
        "source": "package-lock.json",
        "version": "2.0.0"
      },
      {
        "dev": false,
        "direct": false,
        "name": "duplicate",
        "source": "package-lock.json",
        "version": "3.0.0"
      },
      {
        "dev": false,
        "direct": false,
        "name": "shared",
        "source": "package-lock.json",
        "version": "5.0.0"
      },
      {
        "dev": true,
        "direct": true,
        "name": "workspace-dev",
        "source": "package-lock.json",
        "version": "6.0.0"
      },
      {
        "dev": false,
        "direct": true,
        "name": "workspace-direct",
        "source": "package-lock.json",
        "version": "5.0.0"
      }
    ]
    "#);
}

#[test]
fn parses_nested_npm_v3_packages_and_skips_local_descriptors() {
    let packages = npm_fixture_packages("npm-v3-nested");

    insta::assert_json_snapshot!(normalized_npm_packages(&packages), @r#"
    [
      {
        "dev": false,
        "direct": false,
        "name": "@nested/scoped",
        "source": "package-lock.json",
        "version": "2.1.0"
      },
      {
        "dev": false,
        "direct": true,
        "name": "@scope/direct",
        "source": "package-lock.json",
        "version": "2.0.0"
      },
      {
        "dev": false,
        "direct": true,
        "name": "producer",
        "source": "package-lock.json",
        "version": "1.0.0"
      },
      {
        "dev": false,
        "direct": false,
        "name": "repeated",
        "source": "package-lock.json",
        "version": "0.8.0"
      },
      {
        "dev": false,
        "direct": false,
        "name": "repeated",
        "source": "package-lock.json",
        "version": "0.9.0"
      },
      {
        "dev": false,
        "direct": true,
        "name": "repeated",
        "source": "package-lock.json",
        "version": "1.5.0"
      },
      {
        "dev": false,
        "direct": true,
        "name": "workspace-only",
        "source": "package-lock.json",
        "version": "7.0.0"
      }
    ]
    "#);
}

#[test]
fn rejects_malformed_npm_v2_v3_package_records() {
    let cases = [
        (
            "non-object entry",
            "node_modules/bad",
            json!("not an object"),
            "must be an object",
        ),
        (
            "missing version",
            "node_modules/bad",
            json!({"dev": true}),
            "non-empty string version",
        ),
        (
            "wrong version type",
            "node_modules/bad",
            json!({"version": 1}),
            "field \"version\" must be a non-empty string",
        ),
        (
            "invalid registry version",
            "node_modules/bad",
            json!({"version": "^1.0.0"}),
            "invalid registry SemVer",
        ),
        (
            "malformed scoped location",
            "node_modules/@scope/too/many",
            json!({"version": "1.0.0"}),
            "valid node_modules install location",
        ),
        (
            "parent traversal before node_modules",
            "../node_modules/bad",
            json!({"version": "1.0.0"}),
            "valid node_modules install location",
        ),
        (
            "parent traversal in install prefix",
            "packages/../node_modules/bad",
            json!({"version": "1.0.0"}),
            "valid node_modules install location",
        ),
        (
            "unknown local descriptor",
            "vendor/bad",
            json!({"version": "1.0.0"}),
            "neither a linked local descriptor",
        ),
        (
            "unproven install prefix",
            "vendor/node_modules/bad",
            json!({"version": "1.0.0"}),
            "unproven install prefix",
        ),
        (
            "wrong dev type",
            "node_modules/bad",
            json!({"version": "1.0.0", "dev": "true"}),
            "field \"dev\" must be a boolean",
        ),
        (
            "wrong link type",
            "node_modules/bad",
            json!({"version": "1.0.0", "link": 1}),
            "field \"link\" must be a boolean",
        ),
        (
            "link without target",
            "node_modules/bad",
            json!({"link": true}),
            "non-empty string resolved target",
        ),
        (
            "link with missing descriptor",
            "node_modules/bad",
            json!({"link": true, "resolved": "packages/missing"}),
            "does not name an existing package descriptor object",
        ),
        (
            "wrong resolved type",
            "node_modules/bad",
            json!({"version": "1.0.0", "resolved": false}),
            "field \"resolved\" must be a non-empty string",
        ),
        (
            "garbage resolved source",
            "node_modules/bad",
            json!({"version": "1.0.0", "resolved": "not-a-source"}),
            "unsupported or malformed resolved source",
        ),
        (
            "credential-like bare tarball source",
            "node_modules/bad",
            json!({
                "version": "1.0.0",
                "resolved": "user:password@private.example/path/package.tgz"
            }),
            "unsupported or malformed resolved source",
        ),
        (
            "empty file version source",
            "node_modules/bad",
            json!({"version": "file:"}),
            "unsupported or malformed version source",
        ),
        (
            "empty Git version source",
            "node_modules/bad",
            json!({"version": "git:"}),
            "unsupported or malformed version source",
        ),
        (
            "empty HTTPS version source",
            "node_modules/bad",
            json!({"version": "https:"}),
            "unsupported or malformed version source",
        ),
        (
            "empty workspace version source",
            "node_modules/bad",
            json!({"version": "workspace:"}),
            "unsupported or malformed version source",
        ),
        (
            "empty SCP repository source",
            "node_modules/bad",
            json!({"version": "git@private.example:"}),
            "unsupported or malformed version source",
        ),
        (
            "SCP source with only a fragment",
            "node_modules/bad",
            json!({"version": "git@private.example:#token"}),
            "unsupported or malformed version source",
        ),
        (
            "SCP source with only a query",
            "node_modules/bad",
            json!({"version": "git@private.example:?token"}),
            "unsupported or malformed version source",
        ),
    ];

    for version in [2, 3] {
        for (label, location, entry, expected) in &cases {
            let value = json!({
                "name": "strict-fixture",
                "lockfileVersion": version,
                "packages": {
                    "": {"name": "strict-fixture", "version": "1.0.0"},
                    (*location): (*entry).clone(),
                }
            });
            let error = match parse_npm_value(&value) {
                Ok(_) => panic!("npm v{version} accepted {label}"),
                Err(error) => error,
            };
            let ParseError::Invalid { message, .. } = error else {
                panic!("npm v{version} returned I/O error for {label}");
            };
            assert!(
                message.contains(expected),
                "npm v{version} {label} returned unexpected error: {message}"
            );
        }
    }
}
