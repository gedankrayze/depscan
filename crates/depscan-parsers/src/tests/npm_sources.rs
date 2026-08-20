use super::*;

#[test]
fn npm_registry_declarations_coalesced_at_one_install_must_agree() {
    let error = parse_npm_value(&json!({
        "name": "coalesced-identities",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "coalesced-identities",
                "version": "1.0.0",
                "workspaces": ["packages/*"],
                "dependencies": {"shared": "npm:lodash@4.17.20"}
            },
            "node_modules/a": {"link": true, "resolved": "packages/a"},
            "packages/a": {
                "name": "a",
                "version": "1.0.0",
                "dependencies": {"shared": "1.0.0"}
            },
            "node_modules/shared": {
                "name": "lodash",
                "version": "4.17.20",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
            }
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = error else {
        panic!("coalesced npm identities returned an I/O error");
    };
    assert!(message.contains("inconsistent with its registry declarations"));
}

#[test]
fn npm_workspace_source_provenance_survives_hoisting() {
    let packages = npm_fixture_packages("npm-v3-hoisted-url");

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "lodash");
    assert_eq!(packages[0].version, "4.17.20");
    assert!(packages[0].direct);
    assert!(!packages[0].enrichable);
}

#[test]
fn npm_alias_validation_is_scoped_to_the_declaring_descriptor() {
    let source_collision = npm_fixture_packages("npm-v3-alias-source-collision")
        .into_iter()
        .map(|package| (package.name.clone(), package))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(source_collision.len(), 2);
    assert!(source_collision["lodash"].enrichable);
    assert!(!source_collision["underscore"].enrichable);

    let registry_collision = npm_fixture_packages("npm-v3-alias-registry-collision")
        .into_iter()
        .map(|package| (package.name.clone(), package))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(registry_collision.len(), 2);
    assert!(registry_collision["lodash"].enrichable);
    assert!(registry_collision["is-number"].enrichable);
}

#[test]
fn npm_workspace_sources_bind_to_their_concrete_installed_records() {
    let packages = npm_fixture_packages("npm-v3-workspace-source-collision")
        .into_iter()
        .map(|package| (package.name.clone(), package))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(packages.len(), 2);
    assert_eq!(packages["lodash"].version, "4.17.20");
    assert!(packages["lodash"].enrichable);
    assert_eq!(packages["underscore"].version, "1.13.7");
    assert!(!packages["underscore"].enrichable);
}

#[test]
fn npm_dedup_keeps_a_proven_public_occurrence_enrichable() {
    let packages = parse_npm_value(&json!({
        "name": "mixed-source-same-coordinate",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "mixed-source-same-coordinate",
                "version": "1.0.0",
                "dependencies": {
                    "public-lodash": "npm:lodash@4.17.20",
                    "url-lodash": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
                }
            },
            "node_modules/public-lodash": {
                "name": "lodash",
                "version": "4.17.20",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
            },
            "node_modules/url-lodash": {
                "name": "lodash",
                "version": "4.17.20",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
            }
        }
    }))
    .unwrap();

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "lodash");
    assert!(packages[0].enrichable);
}

#[test]
fn npm_ambiguous_registry_origins_are_visible_but_not_enriched() {
    let omitted = parse_npm_value(&json!({
        "name": "omitted-registry-origin",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "omitted-registry-origin",
                "version": "1.0.0",
                "dependencies": {"lodash": "4.17.20"}
            },
            "node_modules/lodash": {"version": "4.17.20"}
        }
    }))
    .unwrap();
    assert_eq!(omitted.len(), 1);
    assert!(!omitted[0].enrichable);

    let configured = parse_npm_value(&json!({
        "name": "configured-registry-origin",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "configured-registry-origin",
                "version": "1.0.0",
                "dependencies": {"lodash": "4.17.20"}
            },
            "node_modules/lodash": {
                "version": "4.17.20",
                "resolved": "registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
            }
        }
    }))
    .unwrap();
    assert_eq!(configured.len(), 1);
    assert!(!configured[0].enrichable);

    let public = parse_npm_value(&json!({
        "name": "public-registry-origin",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "public-registry-origin",
                "version": "1.0.0",
                "dependencies": {"lodash": "4.17.20"}
            },
            "node_modules/lodash": {
                "version": "4.17.20",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
            }
        }
    }))
    .unwrap();
    assert!(public[0].enrichable);
}

#[test]
fn npm_public_tarball_paths_must_match_the_package_identity() {
    assert!(npm_public_tarball_matches(
        "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
        "lodash",
        "4.17.20"
    ));
    assert!(npm_public_tarball_matches(
        "https://registry.npmjs.org/%40scope%2Fpackage/-/package-1.2.3.tgz",
        "@scope/package",
        "1.2.3"
    ));
    assert!(npm_public_tarball_matches(
        "https://registry.npmjs.org/@scope/package/-/package-1.2.3.tgz",
        "@scope/package",
        "1.2.3"
    ));

    let error = parse_npm_value(&json!({
        "name": "public-path-confusion",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "public-path-confusion",
                "version": "1.0.0",
                "dependencies": {"lodash": "4.17.20"}
            },
            "node_modules/lodash": {
                "version": "4.17.20",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            }
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = error else {
        panic!("mismatched public npm tarball returned an I/O error");
    };
    assert!(message.contains("does not match package \"lodash\" version \"4.17.20\""));
}

#[test]
fn npm_required_dependency_edges_must_resolve_to_installed_records() {
    let error = parse_npm_value(&json!({
        "name": "missing-required-edge",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "missing-required-edge",
                "version": "1.0.0",
                "dependencies": {"lodash": "4.17.20"},
                "optionalDependencies": {"optional-package": "1.0.0"},
                "peerDependencies": {"peer-package": "1.0.0"}
            },
            "node_modules/safe-source": {
                "version": "git+https://example.test/safe.git#abc"
            }
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = error else {
        panic!("missing required npm edge returned an I/O error");
    };
    assert!(message.contains("required dependency \"lodash\""));
    assert!(message.contains("no installed package record"));
}
