use super::*;
use chrono::{DateTime, NaiveDate, Utc};
use std::{cmp::Ordering, path::PathBuf};

#[test]
fn package_metadata_merge_preserves_unknown_classifications_conservatively() {
    let mut package = Package::new(
        Ecosystem::PyPI,
        "demo",
        "1.0.0",
        PathBuf::from("poetry.lock"),
    );
    package.dev = true;

    let mut unknown = package.clone();
    unknown.direct_known = false;
    unknown.dev = false;
    unknown.dev_known = false;
    unknown.enrichable = false;
    package.merge_metadata(&unknown);

    assert!(!package.direct);
    assert!(!package.direct_known);
    assert!(!package.dev);
    assert!(!package.dev_known);
    assert!(package.enrichable);

    let mut unavailable = package.clone();
    unavailable.enrichable = false;
    let mut also_unavailable = unavailable.clone();
    also_unavailable.enrichable = false;
    unavailable.merge_metadata(&also_unavailable);
    assert!(!unavailable.enrichable);

    let mut observed = package.clone();
    observed.direct = true;
    observed.direct_known = true;
    observed.dev_known = true;
    package.merge_metadata(&observed);

    assert!(package.direct);
    assert!(package.direct_known);
    assert!(!package.dev);
    assert!(package.dev_known);
}

#[test]
fn normalizes_pypi_names() {
    assert_eq!(
        normalize_name(Ecosystem::PyPI, "My__Package.Name"),
        "my-package-name"
    );
}

#[test]
fn nuget_identity_is_case_insensitive_but_display_case_is_preserved() {
    let canonical = Package::new(
        Ecosystem::NuGet,
        "Newtonsoft.Json",
        "12.0.1",
        PathBuf::from("packages.lock.json"),
    );
    let lowercase = Package::new(
        Ecosystem::NuGet,
        "newtonsoft.json",
        "12.0.1",
        PathBuf::from("packages.lock.json"),
    );

    assert_eq!(canonical.name, "newtonsoft.json");
    assert_eq!(canonical.display_name, "Newtonsoft.Json");
    assert_eq!(canonical.key(), lowercase.key());
    assert_eq!(canonical.key(), "NuGet:newtonsoft.json:12.0.1");
}

#[test]
fn classifies_semver() {
    assert_eq!(
        classify_staleness(Ecosystem::Npm, "1.2.3", "2.0.0"),
        Staleness::Major
    );
    assert_eq!(
        classify_staleness(Ecosystem::CratesIo, "1.2.3", "1.2.4"),
        Staleness::Patch
    );
}

#[test]
fn orders_and_classifies_nuget_versions_with_parsed_precedence() {
    let order_cases = [
        ("1.0.0-rc.2", "1.0.0-rc.10", Ordering::Less),
        ("1.0.0-alpha.1", "1.0.0-alpha.beta", Ordering::Less),
        ("1.0.0-alpha", "1.0.0-Alpha", Ordering::Equal),
        ("1.0.0-rc.10", "1.0.0", Ordering::Less),
        ("1.0.0+left", "1.0.0+right", Ordering::Equal),
        ("1.0.0.4", "1.0.0.5", Ordering::Less),
        ("1.00", "1.0.0.0", Ordering::Equal),
    ];

    for (left, right, expected) in order_cases {
        assert_eq!(
            compare_versions(Ecosystem::NuGet, left, right),
            expected,
            "unexpected ordering for {left:?} and {right:?}"
        );
    }

    let staleness_cases = [
        ("1.0.0-rc.2", "1.0.0", Staleness::Patch),
        ("1.0.0.4", "1.0.0.5", Staleness::Patch),
        ("1.0.0", "1.1.0", Staleness::Minor),
        ("1.0.0", "2.0.0", Staleness::Major),
        ("not-a-version", "2.0.0", Staleness::Unknown),
        ("1.0.0", "not-a-version", Staleness::Unknown),
    ];

    for (installed, latest, expected) in staleness_cases {
        assert_eq!(
            classify_staleness(Ecosystem::NuGet, installed, latest),
            expected,
            "unexpected staleness for {installed:?} -> {latest:?}"
        );
    }
}

#[test]
fn orders_pypi_versions_with_pep440() {
    let cases = [
        ("2.9.2", "2.32.5", Ordering::Less),
        ("2.32.5", "2.34.2", Ordering::Less),
        ("2.0", "1!1.0", Ordering::Less),
        ("1.0.dev1", "1.0a1", Ordering::Less),
        ("1.0a1", "1.0rc1", Ordering::Less),
        ("1.0rc1", "1.0", Ordering::Less),
        ("1.0", "1.0.post1", Ordering::Less),
        ("1.0", "1.0+local.1", Ordering::Less),
        ("1.0-alpha1", "1.0a1", Ordering::Equal),
        ("1.0_rc1", "1.0rc1", Ordering::Equal),
        ("1.0-post1", "1.0.post1", Ordering::Equal),
        ("1.0+ubuntu-1", "1.0+ubuntu.1", Ordering::Equal),
    ];

    for (left, right, expected) in cases {
        assert_eq!(
            compare_versions(Ecosystem::PyPI, left, right),
            expected,
            "unexpected ordering for {left:?} and {right:?}"
        );
    }
}

#[test]
fn handles_invalid_pypi_versions_deterministically() {
    assert_eq!(
        compare_versions(Ecosystem::PyPI, "not a version", "1.0"),
        Ordering::Less
    );
    assert_eq!(
        compare_versions(Ecosystem::PyPI, "invalid-b", "invalid-a"),
        Ordering::Greater
    );
    assert_eq!(
        compare_versions(Ecosystem::PyPI, " INVALID ", "invalid"),
        Ordering::Less
    );
}

#[test]
fn detects_stable_pypi_versions_with_pep440() {
    let cases = [
        ("1.0", true, false),
        ("1.0.post1", true, false),
        ("1.0+local.1", true, false),
        ("1.0a1", false, true),
        ("1.0rc1", false, true),
        ("1.0.dev1", false, true),
        ("not a version", false, false),
    ];

    for (version, stable, prerelease) in cases {
        assert_eq!(
            pypi_version_is_stable(version),
            stable,
            "unexpected stable classification for {version:?}"
        );
        assert_eq!(
            pypi_version_is_prerelease(version),
            prerelease,
            "unexpected pre-release classification for {version:?}"
        );
    }
}

#[test]
fn classifies_pypi_staleness_from_parsed_release_segments() {
    let cases = [
        ("2.32.5", "2.34.2", Staleness::Minor),
        ("2.34.1", "2.34.2", Staleness::Patch),
        ("1.9", "2.0", Staleness::Major),
        ("1!2.0", "2!1.0", Staleness::Major),
        ("1.0rc1", "1.0", Staleness::Patch),
        ("not a version", "1.0", Staleness::Unknown),
    ];

    for (installed, latest, expected) in cases {
        assert_eq!(
            classify_staleness(Ecosystem::PyPI, installed, latest),
            expected,
            "unexpected staleness for {installed:?} -> {latest:?}"
        );
    }
}

#[test]
fn scan_document_uses_an_injected_clock_and_canonical_collection_order() {
    fn result(name: &str, aliases: &[&str]) -> ScanResult {
        let vulnerability = Vulnerability {
            id: format!("OSV-{name}"),
            aliases: aliases.iter().map(|value| (*value).to_owned()).collect(),
            summary: "fixture".to_owned(),
            severity: Some(Severity::High),
            cvss_score: Some(8.0),
            fixed_in: vec!["1.2.0".to_owned(), "1.1.0".to_owned()],
            references: vec![
                "https://b.example".to_owned(),
                "https://a.example".to_owned(),
            ],
            withdrawn: false,
        };
        ScanResult {
            package: Package::new(
                Ecosystem::Npm,
                name,
                "1.0.0",
                PathBuf::from("package-lock.json"),
            ),
            vulns: vec![vulnerability.clone()],
            latest: None,
            errors: vec![
                EnrichError {
                    provider: "z-provider".to_owned(),
                    message: "last".to_owned(),
                },
                EnrichError {
                    provider: "a-provider".to_owned(),
                    message: "first".to_owned(),
                },
            ],
            suppressed: vec![SuppressedFinding {
                vulnerability,
                active: true,
                matches: vec![
                    SuppressionMatch {
                        matched_id: "Z-SUPPRESSED".to_owned(),
                        source: SuppressionSource::Config,
                        reason: Some("temporary exception".to_owned()),
                        expires: NaiveDate::from_ymd_opt(2030, 1, 1),
                        state: SuppressionState::Active,
                    },
                    SuppressionMatch {
                        matched_id: "A-SUPPRESSED".to_owned(),
                        source: SuppressionSource::Cli,
                        reason: None,
                        expires: None,
                        state: SuppressionState::Active,
                    },
                ],
            }],
        }
    }

    let timestamp = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
    let first = ScanDocument::at(
        vec![
            result("z-package", &["Z-ALIAS", "A-ALIAS"]),
            result("a-package", &["A-ALIAS", "Z-ALIAS"]),
        ],
        timestamp,
    );
    let second = ScanDocument::at(
        vec![
            result("a-package", &["Z-ALIAS", "A-ALIAS"]),
            result("z-package", &["A-ALIAS", "Z-ALIAS"]),
        ],
        timestamp,
    );

    assert_eq!(
        serde_json::to_string_pretty(&first).unwrap(),
        serde_json::to_string_pretty(&second).unwrap()
    );
    assert_eq!(first.generated_at, timestamp);
    assert_eq!(first.results[0].package.name, "a-package");
    assert_eq!(first.results[0].vulns[0].aliases, ["A-ALIAS", "Z-ALIAS"]);
    assert_eq!(first.results[0].vulns[0].fixed_in, ["1.1.0", "1.2.0"]);
    assert_eq!(first.results[0].errors[0].provider, "a-provider");
    assert_eq!(
        first.results[0].suppressed[0]
            .matches
            .iter()
            .map(|matched| matched.matched_id.as_str())
            .collect::<Vec<_>>(),
        ["A-SUPPRESSED", "Z-SUPPRESSED"]
    );
}

#[test]
fn scan_document_new_uses_a_current_utc_timestamp() {
    let before = Utc::now();
    let document = ScanDocument::new(Vec::new());
    let after = Utc::now();

    assert!(document.generated_at >= before);
    assert!(document.generated_at <= after);
    assert_eq!(document.generated_at.timezone(), Utc);
}
