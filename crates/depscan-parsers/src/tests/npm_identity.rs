use super::*;

#[test]
fn link_metadata_cannot_hide_an_installed_npm_package_record() {
    let packages = parse_npm_value(&json!({
        "name": "strict-fixture",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "strict-fixture", "version": "1.0.0"},
            "node_modules/lodash": {
                "version": "4.17.20",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
            },
            "node_modules/decoy": {
                "link": true,
                "resolved": "node_modules/lodash"
            }
        }
    }))
    .unwrap();

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "lodash");
    assert_eq!(packages[0].version, "4.17.20");
    assert!(packages[0].enrichable);

    let error = parse_npm_value(&json!({
        "name": "strict-fixture",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "strict-fixture", "version": "1.0.0"},
            "node_modules/@scope": {"version": "1.0.0"},
            "node_modules/decoy": {
                "link": true,
                "resolved": "node_modules/@scope"
            }
        }
    }))
    .unwrap_err();
    let ParseError::Invalid { message, .. } = error else {
        panic!("malformed installed link target returned an I/O error");
    };
    assert!(message.contains("not a valid installed package location"));
}

#[test]
fn npm_alias_records_require_the_declared_registry_identity() {
    for (label, name) in [
        ("missing name", None),
        ("mismatched name", Some(json!("underscore"))),
    ] {
        let mut entry = serde_json::Map::new();
        entry.insert("version".to_owned(), json!("4.17.20"));
        if let Some(name) = name {
            entry.insert("name".to_owned(), name);
        }
        let error = parse_npm_value(&json!({
            "name": "alias-fixture",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "alias-fixture",
                    "version": "1.0.0",
                    "dependencies": {"alias-lodash": "npm:lodash@4.17.20"}
                },
                "node_modules/alias-lodash": Json::Object(entry)
            }
        }))
        .unwrap_err();

        let ParseError::Invalid { message, .. } = error else {
            panic!("{label} alias returned an I/O error");
        };
        assert!(
            message.contains("alias package entry")
                && message.contains("lodash")
                && message.contains("alias-lodash"),
            "{label} alias returned unexpected context: {message}"
        );
    }
}

#[test]
fn npm_alias_targets_allow_the_npm_default_version() {
    assert_eq!(npm_alias_target("lodash").unwrap(), "lodash");
    assert_eq!(npm_alias_target("lodash@latest").unwrap(), "lodash");
    assert_eq!(
        npm_alias_target("@scope/package").unwrap(),
        "@scope/package"
    );
    assert_eq!(
        npm_alias_target("@scope/package@^1.0.0").unwrap(),
        "@scope/package"
    );
    assert_eq!(npm_alias_target("lodash@").unwrap(), "lodash");
    assert_eq!(
        npm_alias_target("@scope/package@").unwrap(),
        "@scope/package"
    );
    assert!(npm_alias_target("lodash@file:../package").is_err());
    assert!(npm_alias_target("lodash@npm:other").is_err());

    let packages = npm_fixture_packages("npm-v3-alias-bare");

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "lodash");
    assert_eq!(packages[0].version, "4.18.1");
    assert!(packages[0].direct);
    assert!(packages[0].enrichable);
}

#[test]
fn npm_installed_identity_selects_the_effective_duplicate_group_alias() {
    let packages = parse_npm_value(&json!({
        "name": "duplicate-group-alias",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "duplicate-group-alias",
                "version": "1.0.0",
                "dependencies": {"same": "npm:lodash@4.17.20"},
                "devDependencies": {"same": "npm:underscore@1.13.7"}
            },
            "node_modules/same": {
                "name": "underscore",
                "version": "1.13.7",
                "resolved": "https://registry.npmjs.org/underscore/-/underscore-1.13.7.tgz",
                "dev": true
            }
        }
    }))
    .unwrap();

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "underscore");
    assert_eq!(packages[0].version, "1.13.7");
    assert!(packages[0].dev);
    assert!(packages[0].enrichable);
}

#[test]
fn npm_effective_dev_declaration_overrides_a_source_declaration() {
    let packages = parse_npm_value(&json!({
        "name": "duplicate-group-source",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "duplicate-group-source",
                "version": "1.0.0",
                "dependencies": {
                    "same": "https://registry.npmjs.org/underscore/-/underscore-1.13.7.tgz"
                },
                "devDependencies": {"same": "npm:lodash@4.17.20"}
            },
            "node_modules/same": {
                "name": "lodash",
                "version": "4.17.20",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                "dev": true
            }
        }
    }))
    .unwrap();

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "lodash");
    assert!(packages[0].dev);
    assert!(packages[0].enrichable);
}

#[test]
fn npm_workspace_patterns_follow_npm_negation_semantics() {
    fn patterns(values: Json) -> NpmWorkspacePatterns {
        let document = json!({
            "": {
                "name": "workspace-patterns",
                "version": "1.0.0",
                "workspaces": values
            }
        });
        npm_lock_workspace_patterns(
            Path::new("package-lock.json"),
            document.as_object().unwrap(),
        )
        .unwrap()
    }

    fn is_workspace(location: &str, patterns: &NpmWorkspacePatterns) -> bool {
        npm_is_workspace_descriptor(Path::new("package-lock.json"), location, patterns).unwrap()
    }

    let braces = patterns(json!(["/packages/{a,b}/"]));
    assert!(is_workspace("packages/a", &braces));
    assert!(is_workspace("packages/b", &braces));
    assert!(is_workspace(
        "packages/a",
        &patterns(json!([".//packages/*"]))
    ));
    assert!(!is_workspace(
        "packages/a",
        &patterns(json!(["././packages/*"]))
    ));
    assert!(!is_workspace(
        "packages/a",
        &patterns(json!(["/./packages/*"]))
    ));

    let negated_before_include = patterns(json!(["!packages/b", "packages/*"]));
    assert!(is_workspace("packages/a", &negated_before_include));
    assert!(!is_workspace("packages/b", &negated_before_include));

    let adjacent_negations = patterns(json!(["!packages/*", "!packages/a", "packages/a"]));
    assert!(!is_workspace("packages/a", &adjacent_negations));

    let double_negation = patterns(json!(["!!packages\\c"]));
    assert!(is_workspace("packages/c", &double_negation));
    let exact_extglob = patterns(json!(["packages/@(a|b)"]));
    assert!(is_workspace("packages/a", &exact_extglob));
    assert!(is_workspace("packages/b", &exact_extglob));
    assert!(!is_workspace("packages/c", &exact_extglob));

    let optional_extglob = patterns(json!(["packages/item?(s|z)"]));
    assert!(is_workspace("packages/item", &optional_extglob));
    assert!(is_workspace("packages/items", &optional_extglob));

    let literal_dollar = patterns(json!(["packages/$"]));
    assert!(is_workspace("packages/$", &literal_dollar));
    assert!(!is_workspace("packages/a", &literal_dollar));

    let negative_extglob = patterns(json!(["packages/!(c)"]));
    assert!(is_workspace("packages/a", &negative_extglob));
    assert!(!is_workspace("packages/c", &negative_extglob));

    let numeric_brace = patterns(json!(["packages/{1..3}"]));
    assert!(is_workspace("packages/2", &numeric_brace));
    assert!(!is_workspace("packages/4", &numeric_brace));

    let alphabetic_brace = patterns(json!(["packages/{a..e..2}"]));
    assert!(is_workspace("packages/c", &alphabetic_brace));
    assert!(!is_workspace("packages/d", &alphabetic_brace));

    let posix_class = patterns(json!(["packages/[[:alpha:]]"]));
    assert!(is_workspace("packages/a", &posix_class));
    assert!(!is_workspace("packages/7", &posix_class));

    assert!(!is_workspace(
        "packages/a",
        &patterns(json!(["packages/{a}"]))
    ));
    assert!(!is_workspace(
        "packages/.a",
        &patterns(json!(["packages/*"]))
    ));
    assert!(!is_workspace("#a", &patterns(json!(["#*"]))));
    assert!(!is_workspace("node_modules/c", &patterns(json!(["**"]))));
}
