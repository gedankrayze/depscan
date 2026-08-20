use super::*;

#[test]
fn npm_links_require_a_proven_workspace_identity() {
    let forged = parse_npm_value(&json!({
        "name": "forged-link",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "forged-link",
                "version": "1.0.0",
                "dependencies": {"lodash": "4.17.20"}
            },
            "node_modules/lodash": {"link": true, "resolved": "packages/fake"},
            "packages/fake": {"name": "fake-lodash", "version": "1.0.0"}
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = forged else {
        panic!("forged npm link returned an I/O error");
    };
    assert!(message.contains("unproven local target"));

    let nameless_forged = parse_npm_value(&json!({
        "name": "nameless-forged-link",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "nameless-forged-link",
                "version": "1.0.0",
                "workspaces": ["packages/*"],
                "dependencies": {"lodash": "4.17.20"}
            },
            "node_modules/lodash": {"link": true, "resolved": "packages/fake"},
            "packages/fake": {"version": "1.0.0"}
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = nameless_forged else {
        panic!("nameless forged npm link returned an I/O error");
    };
    assert!(message.contains("unproven local target"));

    let workspace_shadow = parse_npm_value(&json!({
        "name": "workspace-shadow",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "workspace-shadow",
                "version": "1.0.0",
                "workspaces": ["packages/*"],
                "dependencies": {"a": "npm:lodash@4.17.20"}
            },
            "node_modules/a": {"link": true, "resolved": "packages/a"},
            "packages/a": {"version": "1.0.0"}
        }
    }))
    .unwrap();
    assert!(workspace_shadow.is_empty());

    let conflicting_workspace_alias = parse_npm_value(&json!({
        "name": "workspace-alias-conflict",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "workspace-alias-conflict",
                "version": "1.0.0",
                "workspaces": ["packages/*"]
            },
            "node_modules/b": {"link": true, "resolved": "packages/b"},
            "packages/a": {
                "name": "a",
                "version": "1.0.0",
                "dependencies": {"b": "npm:lodash@4.17.20"}
            },
            "packages/b": {"name": "b", "version": "1.0.0"}
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = conflicting_workspace_alias else {
        panic!("conflicting workspace alias returned an I/O error");
    };
    assert!(message.contains("unproven local target"));

    let malformed_link_field = parse_npm_value(&json!({
        "name": "malformed-link-field",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "malformed-link-field",
                "version": "1.0.0",
                "workspaces": ["packages/*"]
            },
            "node_modules/a": {
                "link": true,
                "resolved": "packages/a",
                "dev": "yes"
            },
            "packages/a": {"name": "a", "version": "1.0.0"}
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = malformed_link_field else {
        panic!("malformed link dev field returned an I/O error");
    };
    assert!(message.contains("field \"dev\" must be a boolean"));

    let link_with_package_metadata = parse_npm_value(&json!({
        "name": "link-package-metadata",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "link-package-metadata",
                "version": "1.0.0",
                "workspaces": ["packages/*"]
            },
            "node_modules/a": {
                "link": true,
                "resolved": "packages/a",
                "dependencies": {"lodash": "4.17.20"}
            },
            "packages/a": {"name": "a", "version": "1.0.0"}
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = link_with_package_metadata else {
        panic!("npm link package metadata returned an I/O error");
    };
    assert!(message.contains("must not contain package metadata field \"dependencies\""));

    let duplicate_target_identity = parse_npm_value(&json!({
        "name": "duplicate-target-identity",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "duplicate-target-identity",
                "version": "1.0.0",
                "workspaces": ["packages/*"]
            },
            "node_modules/a": {"link": true, "resolved": "packages/a"},
            "node_modules/b": {"link": true, "resolved": "packages/a"},
            "packages/a": {"version": "1.0.0"}
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = duplicate_target_identity else {
        panic!("duplicate workspace target identity returned an I/O error");
    };
    assert!(message.contains("no matching workspace identity"));

    let orphan_external = parse_npm_value(&json!({
        "name": "orphan-external-link",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "orphan-external-link", "version": "1.0.0"},
            "node_modules/lodash": {"link": true, "resolved": "../outside"},
            "../outside": {"name": "lodash", "version": "4.17.20"}
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = orphan_external else {
        panic!("orphan external npm link returned an I/O error");
    };
    assert!(message.contains("explicit non-registry declaration"));

    let self_link = parse_npm_value(&json!({
        "name": "self-link",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "self-link", "version": "1.0.0"},
            "node_modules/hidden": {
                "link": true,
                "resolved": "node_modules/hidden"
            }
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = self_link else {
        panic!("self-referential npm link returned an I/O error");
    };
    assert!(message.contains("must not be itself or another link record"));

    let malformed_target_version = parse_npm_value(&json!({
        "name": "malformed-target-version",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "malformed-target-version",
                "version": "1.0.0",
                "workspaces": ["packages/*"]
            },
            "node_modules/a": {"link": true, "resolved": "packages/a"},
            "packages/a": {"name": "a", "version": 123}
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = malformed_target_version else {
        panic!("malformed npm link target version returned an I/O error");
    };
    assert!(message.contains("field \"version\" must be a non-empty string"));

    let unproven_prefix = parse_npm_value(&json!({
        "name": "unproven-link-prefix",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "unproven-link-prefix",
                "version": "1.0.0",
                "workspaces": ["packages/*"]
            },
            "vendor/node_modules/a": {"link": true, "resolved": "packages/a"},
            "packages/a": {"name": "a", "version": "1.0.0"}
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = unproven_prefix else {
        panic!("unproven npm link prefix returned an I/O error");
    };
    assert!(message.contains("unproven install prefix \"vendor\""));
}

#[test]
fn npm_external_link_descriptors_do_not_require_uninstalled_edges() {
    let packages = parse_npm_value(&json!({
        "name": "external-link",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "external-link",
                "version": "1.0.0",
                "dependencies": {"outside": "file:../outside"}
            },
            "node_modules/outside": {"link": true, "resolved": "../outside"},
            "../outside": {
                "name": "outside",
                "version": "1.0.0",
                "dependencies": {"not-installed": "1.0.0"},
                "devDependencies": {"also-not-installed": "1.0.0"}
            }
        }
    }))
    .unwrap();
    assert!(packages.is_empty());
}

#[test]
fn npm_non_root_registry_constraints_cannot_fall_back_to_an_incompatible_workspace() {
    let error = parse_npm_value(&json!({
        "name": "workspace-range-confusion",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "workspace-range-confusion",
                "version": "1.0.0",
                "workspaces": ["packages/*"]
            },
            "node_modules/lodash": {
                "link": true,
                "resolved": "packages/local-lodash"
            },
            "node_modules/y": {"link": true, "resolved": "packages/y"},
            "packages/local-lodash": {
                "name": "lodash",
                "version": "1.0.0"
            },
            "packages/y": {
                "name": "y",
                "version": "1.0.0",
                "dependencies": {"lodash": "4.17.21"}
            }
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = error else {
        panic!("incompatible workspace fallback returned an I/O error");
    };
    assert!(message.contains("does not accept linked workspace version \"1.0.0\""));
}

#[test]
fn npm_sources_must_resolve_to_the_selected_link_target() {
    let valid = parse_npm_value(&json!({
        "name": "workspace-file-link",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "workspace-file-link",
                "version": "1.0.0",
                "workspaces": ["packages/*"]
            },
            "node_modules/a": {"link": true, "resolved": "packages/a"},
            "node_modules/y": {"link": true, "resolved": "packages/y"},
            "packages/a": {"name": "a", "version": "1.0.0"},
            "packages/y": {
                "name": "y",
                "version": "1.0.0",
                "dependencies": {"a": "file:../a"}
            }
        }
    }))
    .unwrap();
    assert!(valid.is_empty());

    let error = parse_npm_value(&json!({
        "name": "workspace-source-confusion",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "workspace-source-confusion",
                "version": "1.0.0",
                "workspaces": ["packages/*"]
            },
            "node_modules/lodash": {
                "link": true,
                "resolved": "packages/local-lodash"
            },
            "node_modules/y": {"link": true, "resolved": "packages/y"},
            "packages/local-lodash": {
                "name": "lodash",
                "version": "1.0.0"
            },
            "packages/y": {
                "name": "y",
                "version": "1.0.0",
                "dependencies": {"lodash": "file:../../external-lodash"}
            }
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = error else {
        panic!("mismatched non-root npm source returned an I/O error");
    };
    assert!(message.contains("does not resolve to linked target \"packages/local-lodash\""));

    for (name, specification) in [
        ("url-source", "https://private.example/package.tgz"),
        ("workspace-source", "workspace:*"),
    ] {
        let target = format!("../outside-{name}");
        let error = parse_npm_value(&json!({
            "name": "root-source-confusion",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "root-source-confusion",
                    "version": "1.0.0",
                    "dependencies": {(name): specification}
                },
                (format!("node_modules/{name}")): {
                    "link": true,
                    "resolved": target.clone()
                },
                (target.clone()): {"name": name, "version": "1.0.0"}
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = error else {
            panic!("root {name} source confusion returned an I/O error");
        };
        assert!(
            message.contains("does not resolve to linked target")
                || message.contains("cannot resolve to non-workspace link target"),
            "root {name} source confusion returned unexpected context: {message}"
        );
    }
}
