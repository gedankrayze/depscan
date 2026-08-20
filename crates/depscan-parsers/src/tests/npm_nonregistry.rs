use super::*;

#[test]
fn preserves_explicit_npm_nonregistry_records_without_enrichment() {
    let packages = parse_npm_value(&json!({
        "name": "strict-fixture",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "strict-fixture",
                "version": "1.0.0",
                "workspaces": ["packages/*"],
                "dependencies": {
                    "alias": "npm:actual-package@3.0.0",
                    "bare-secret-source": "file:../bare-secret-source",
                    "git-no-version": "git+https://example.test/no-version.git#abc",
                    "git-nonsemver": "git+file:///tmp/nonsemver#abc",
                    "git-package": "github:example/repo#abc",
                    "gitlab-package": "gitlab:example/repo#abc",
                    "opaque-secret-source": "file:../opaque-secret-source",
                    "private-package": "6.0.0",
                    "relative-credential-source": "../user:password@private.example/repository",
                    "relative-secret-source": "../private#token=secret",
                    "registry-package": "2.0.0",
                    "scp-source": "git@private.example:owner/repo.git#token=secret",
                    "secret-source": "https://user:password@private.example/package.tgz?token=secret#fragment",
                    "url-package": "https://example.test/package.tgz"
                }
            },
            "node_modules/workspace-package": {
                "resolved": "packages/workspace-package",
                "link": true
            },
            "packages/workspace-package": {
                "name": "workspace-package",
                "version": "1.0.0"
            },
            "node_modules/registry-package": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/registry-package/-/registry-package-2.0.0.tgz"
            },
            "node_modules/alias": {
                "name": "actual-package",
                "version": "3.0.0",
                "resolved": "https://registry.npmjs.org/actual-package/-/actual-package-3.0.0.tgz"
            },
            "node_modules/bare-secret-source": {
                "version": "folder?token=secret/package.tgz",
                "resolved": "file:../bare-secret-source"
            },
            "node_modules/git-package": {
                "version": "4.0.0",
                "resolved": "git+ssh://git@example.test/repo.git#abc"
            },
            "node_modules/git-no-version": {
                "resolved": "git+https://example.test/no-version.git#abc"
            },
            "node_modules/git-nonsemver": {
                "version": "dev",
                "resolved": "git+file:///tmp/nonsemver#abc"
            },
            "node_modules/gitlab-package": {
                "version": "branch",
                "resolved": "gitlab:example/repo#abc"
            },
            "node_modules/opaque-secret-source": {
                "version": "user:password@private.example/path/package.tgz",
                "resolved": "file:../opaque-secret-source"
            },
            "node_modules/private-package": {
                "version": "6.0.0",
                "resolved": "https://npm.private.example/private-package/-/private-package-6.0.0.tgz"
            },
            "node_modules/relative-credential-source": {
                "version": "../user:password@private.example/repository"
            },
            "node_modules/relative-secret-source": {
                "resolved": "../private#token=secret"
            },
            "node_modules/scp-source": {
                "resolved": "git@private.example:owner/repo.git#token=secret"
            },
            "node_modules/secret-source": {
                "resolved": "https://user:password@private.example/package.tgz?token=secret#fragment"
            },
            "node_modules/url-package": {
                "version": "5.0.0",
                "resolved": "https://example.test/package.tgz"
            }
        }
    }))
    .unwrap();

    assert_eq!(packages.len(), 14);
    let packages = packages
        .into_iter()
        .map(|package| (package.name.clone(), package))
        .collect::<BTreeMap<_, _>>();
    assert!(packages["registry-package"].enrichable);
    assert!(packages["actual-package"].enrichable);
    assert_eq!(packages["bare-secret-source"].version, "folder");
    assert!(!packages["bare-secret-source"].enrichable);
    assert!(!packages["git-package"].enrichable);
    assert!(!packages["git-no-version"].enrichable);
    assert!(
        packages["git-no-version"]
            .version
            .starts_with("git+https://")
    );
    assert_eq!(packages["git-nonsemver"].version, "dev");
    assert!(!packages["git-nonsemver"].enrichable);
    assert_eq!(packages["gitlab-package"].version, "branch");
    assert!(!packages["gitlab-package"].enrichable);
    assert_eq!(
        packages["opaque-secret-source"].version,
        "[redacted-source]"
    );
    assert!(!packages["opaque-secret-source"].enrichable);
    assert!(!packages["private-package"].enrichable);
    assert_eq!(
        packages["relative-credential-source"].version,
        "[redacted-source]"
    );
    assert!(!packages["relative-credential-source"].enrichable);
    assert_eq!(packages["relative-secret-source"].version, "../private");
    assert!(!packages["relative-secret-source"].enrichable);
    assert_eq!(
        packages["scp-source"].version,
        "git@private.example:owner/repo.git"
    );
    assert!(!packages["scp-source"].enrichable);
    assert_eq!(
        packages["secret-source"].version,
        "https://private.example/package.tgz"
    );
    assert!(!packages["secret-source"].enrichable);
    assert!(!packages["url-package"].enrichable);
    assert!(!packages.contains_key("workspace-package"));
    assert!(!packages.contains_key("alias"));
    assert_eq!(
        npm_lock_report_coordinate("?token=secret"),
        "[redacted-source]"
    );
    for credential_shaped in [
        "./user:password@private.example/repository",
        "../user:password@private.example/repository",
        "/user:password@private.example/repository",
        "file:../user:password@private.example/repository",
        "file:///user:password@private.example/repository",
        "file:///user%3Apassword%40private.example/repository",
    ] {
        assert_eq!(
            npm_lock_report_coordinate(credential_shaped),
            "[redacted-source]",
            "credential-shaped source {credential_shaped:?} was not redacted"
        );
    }

    for source in [
        "bitbucket:example/repo#abc",
        "gist:example/repo#abc",
        "gitlab:example/repo#abc",
        "git+file:///tmp/repo#abc",
    ] {
        assert!(npm_lock_source_locator(source));
        assert_eq!(
            npm_lock_resolved_source(Some(source)).unwrap(),
            NpmResolvedSource::Nonregistry
        );
    }
}

#[test]
fn keeps_legacy_npm_v1_nested_packages_best_effort() {
    let packages = npm_fixture_packages("npm-v1-nested");

    insta::assert_json_snapshot!(normalized_npm_packages(&packages), @r#"
    [
      {
        "dev": false,
        "direct": false,
        "name": "@scope/child",
        "source": "package-lock.json",
        "version": "1.1.0"
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
        "name": "direct-dev",
        "source": "package-lock.json",
        "version": "3.0.0"
      },
      {
        "dev": false,
        "direct": true,
        "name": "direct-one",
        "source": "package-lock.json",
        "version": "1.0.0"
      },
      {
        "dev": false,
        "direct": false,
        "name": "duplicate",
        "source": "package-lock.json",
        "version": "0.5.0"
      },
      {
        "dev": false,
        "direct": false,
        "name": "duplicate",
        "source": "package-lock.json",
        "version": "2.0.0"
      },
      {
        "dev": false,
        "direct": false,
        "name": "retained-child",
        "source": "package-lock.json",
        "version": "4.0.0"
      }
    ]
    "#);
}

#[test]
fn legacy_npm_v1_never_enriches_explicit_source_locators() {
    let packages = parse_npm_value(&json!({
        "name": "legacy-source-fixture",
        "lockfileVersion": 1,
        "dependencies": {
            "registry-package": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/registry-package/-/registry-package-1.0.0.tgz"
            },
            "git-package": {"version": "git+https://example.test/repo.git#abc"},
            "file-package": {"version": "file:../package"},
            "raw-source": {
                "version": "folder?token=secret/package.tgz",
                "resolved": "file:../raw-source"
            },
            "invalid-public-version": {
                "version": "^1.0.0",
                "resolved": "https://registry.npmjs.org/invalid-public-version/-/invalid-public-version-1.0.0.tgz"
            },
            "url-package": {"version": "https://user:password@example.test/package.tgz?token=secret#fragment"}
        }
    }))
    .unwrap();

    assert_eq!(packages.len(), 6);
    for package in &packages {
        assert_eq!(package.enrichable, package.name == "registry-package");
    }
    let raw_source = packages
        .iter()
        .find(|package| package.name == "raw-source")
        .expect("legacy raw source package");
    assert_eq!(raw_source.version, "folder");
    let url_package = packages
        .iter()
        .find(|package| package.name == "url-package")
        .expect("legacy URL package");
    assert_eq!(url_package.version, "https://example.test/package.tgz");
}
