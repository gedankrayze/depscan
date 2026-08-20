use super::*;
use serde_json::json;
use std::path::PathBuf;

fn package(ecosystem: Ecosystem, name: &str, version: &str) -> Package {
    Package::new(ecosystem, name, version, PathBuf::from("fixture.lock"))
}

fn evaluate(package: &Package, entries: Value) -> OsvAffectedEvaluation {
    evaluate_osv_affected(package, entries.as_array().unwrap()).unwrap()
}

#[test]
fn evaluates_schema_range_examples_and_boundaries() {
    let npm = package(Ecosystem::Npm, "schema-example", "1.0.1");
    let fixed = json!([{
        "package": {"ecosystem": "npm", "name": "schema-example"},
        "ranges": [{
            "type": "SEMVER",
            "events": [{"introduced": "0"}, {"fixed": "1.0.2"}]
        }]
    }]);
    assert_eq!(
        evaluate(&npm, fixed.clone()),
        OsvAffectedEvaluation {
            affected: true,
            fixed_versions: vec!["1.0.2".to_owned()]
        }
    );

    let at_fix = package(Ecosystem::Npm, "schema-example", "1.0.2");
    assert!(!evaluate(&at_fix, fixed).affected);

    let last_affected = json!([{
        "package": {"ecosystem": "npm", "name": "schema-example"},
        "ranges": [{
            "type": "SEMVER",
            "events": [{"last_affected": "2.1.214"}, {"introduced": "0"}]
        }]
    }]);
    let ceiling = package(Ecosystem::Npm, "schema-example", "2.1.214");
    assert!(evaluate(&ceiling, last_affected.clone()).affected);
    let above = package(Ecosystem::Npm, "schema-example", "2.1.215");
    assert!(!evaluate(&above, last_affected).affected);

    let build_metadata = json!([{
        "package": {"ecosystem": "npm", "name": "schema-example"},
        "ranges": [{
            "type": "SEMVER",
            "events": [
                {"introduced": "1.0.0+advisory-build"},
                {"fixed": "1.0.1"}
            ]
        }]
    }]);
    let equivalent_build = package(Ecosystem::Npm, "schema-example", "1.0.0+installed-build");
    assert!(evaluate(&equivalent_build, build_metadata).affected);
}

#[test]
fn unsorted_django_style_intervals_keep_the_matching_interval_active() {
    let django = package(Ecosystem::PyPI, "Django", "4.2.17");
    let entries = json!([{
        "package": {"ecosystem": "PyPI", "name": "django"},
        "ranges": [{
            "type": "ECOSYSTEM",
            "events": [
                {"fixed": "5.1.4"},
                {"introduced": "5.1"},
                {"fixed": "4.2.18"},
                {"introduced": "4.2"},
                {"fixed": "5.0.10"},
                {"introduced": "5.0"}
            ]
        }]
    }]);

    assert_eq!(
        evaluate(&django, entries),
        OsvAffectedEvaluation {
            affected: true,
            fixed_versions: vec!["4.2.18".to_owned()]
        }
    );
}

#[test]
fn limit_is_exclusive_and_wildcard_is_infinite() {
    let range = |limit: &str| {
        json!([{
            "package": {"ecosystem": "NuGet", "name": "Example.Package"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"limit": limit}]
            }]
        }])
    };
    let before = package(Ecosystem::NuGet, "example.package", "1.9.9.9");
    assert!(evaluate(&before, range("2.0.0.0")).affected);
    let at = package(Ecosystem::NuGet, "example.package", "2.0.0.0");
    assert!(!evaluate(&at, range("2.0.0.0")).affected);
    let future = package(Ecosystem::NuGet, "example.package", "999.0.0");
    assert!(evaluate(&future, range("2.*")).affected);
}

#[test]
fn nuget_ranges_use_numeric_prerelease_and_metadata_precedence() {
    let range = json!([{
        "package": {"ecosystem": "NuGet", "name": "Example.Package"},
        "ranges": [{
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "1.0.0-rc.2+advisory"},
                {"fixed": "1.0.0-rc.10+fixed-build"}
            ]
        }]
    }]);

    let affected = package(
        Ecosystem::NuGet,
        "example.package",
        "1.0.0-RC.9+installed-build",
    );
    assert!(evaluate(&affected, range.clone()).affected);

    let fixed = package(
        Ecosystem::NuGet,
        "example.package",
        "1.0.0-rc.10+different-build",
    );
    assert!(!evaluate(&fixed, range).affected);
}

#[test]
fn explicit_versions_and_identity_are_restricted_to_the_package() {
    let serde_package = package(Ecosystem::CratesIo, "serde", "1.0.200");
    let entries = json!([
        {
            "package": {"ecosystem": "crates.io", "name": "serde"},
            "versions": ["1.0.199", "1.0.200"]
        },
        {
            "package": {"ecosystem": "npm", "name": "serde"},
            "versions": ["1.0.200"]
        },
        {
            "package": {"ecosystem": "crates.io", "name": "not-serde"},
            "versions": ["1.0.200"]
        }
    ]);
    assert!(evaluate(&serde_package, entries).affected);

    let other = package(Ecosystem::CratesIo, "serde_json", "1.0.200");
    assert!(!evaluate(&other, json!([])).affected);

    let pypi = package(Ecosystem::PyPI, "exact-versions", "1.0.0");
    let semantically_equal = json!([{
        "package": {"ecosystem": "PyPI", "name": "exact-versions"},
        "versions": ["1.0"]
    }]);
    assert!(!evaluate(&pypi, semantically_equal).affected);
}

#[test]
fn wildcard_name_matches_every_package_only_in_its_ecosystem() {
    let npm = package(Ecosystem::Npm, "any-npm-package", "1.5.0");
    let wildcard = json!([{
        "package": {"ecosystem": "npm", "name": "*"},
        "ranges": [{
            "type": "SEMVER",
            "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]
        }]
    }]);
    assert!(evaluate(&npm, wildcard.clone()).affected);

    let pypi = package(Ecosystem::PyPI, "any-python-package", "1.5.0");
    assert!(!evaluate(&pypi, wildcard).affected);
}

#[test]
fn uses_every_supported_ecosystem_comparator() {
    let cases = [
        (Ecosystem::Npm, "npm-package", "1.2.3-beta.2", "1.2.3"),
        (Ecosystem::CratesIo, "crate", "1.0.0-rc.1", "1.0.0"),
        (Ecosystem::PyPI, "python-package", "1.0rc1", "1.0"),
        (Ecosystem::NuGet, "NuGet.Package", "1.0.0.4", "1.0.0.5"),
    ];

    for (ecosystem, name, installed, fixed) in cases {
        let package = package(ecosystem, name, installed);
        let entries = json!([{
            "package": {"ecosystem": ecosystem.osv_name(), "name": name},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": fixed}]
            }]
        }]);
        let evaluation = evaluate(&package, entries);
        assert!(evaluation.affected, "{ecosystem:?} did not match");
        assert_eq!(evaluation.fixed_versions, [fixed]);
    }
}

#[test]
fn reports_unsupported_and_malformed_matching_ranges() {
    let package = package(Ecosystem::Npm, "example", "1.0.0");
    let range = |range_type: &str, events: Value| {
        json!([{
            "package": {"ecosystem": "npm", "name": "example"},
            "ranges": [{"type": range_type, "events": events}]
        }])
    };

    for range_type in ["GIT", "FUTURE"] {
        let entries = range(range_type, json!([{"introduced": "0"}]));
        assert!(matches!(
            evaluate_osv_affected(&package, entries.as_array().unwrap()),
            Err(OsvEvaluationError::UnsupportedRangeType(kind)) if kind == range_type
        ));
    }

    let malformed = [
        range("SEMVER", json!([])),
        range("SEMVER", json!([{"fixed": "2.0.0"}])),
        range(
            "SEMVER",
            json!([{"introduced": "0"}, {"fixed": "2.0.0", "limit": "3.0.0"}]),
        ),
        range(
            "SEMVER",
            json!([{"introduced": "0"}, {"fixed": "not-semver"}]),
        ),
        range(
            "SEMVER",
            json!([{"introduced": "0"}, {"fixed": "2.0.0"}, {"last_affected": "1.9.9"}]),
        ),
    ];
    for entries in malformed {
        assert!(evaluate_osv_affected(&package, entries.as_array().unwrap()).is_err());
    }
}

#[test]
fn unrelated_malformed_entries_do_not_poison_a_package() {
    let package = package(Ecosystem::Npm, "example", "1.0.0");
    let entries = json!([
        {
            "package": {"ecosystem": "PyPI", "name": "broken"},
            "ranges": "not-an-array"
        },
        {
            "package": {"ecosystem": "npm", "name": "example"},
            "versions": ["1.0.0"]
        }
    ]);
    assert!(evaluate(&package, entries).affected);
}
