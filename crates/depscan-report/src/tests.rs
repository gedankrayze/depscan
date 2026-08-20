use super::*;
use chrono::NaiveDate;
use depscan_core::{
    Ecosystem, EnrichError, LatestVersions, Package, ScanResult, Severity, Staleness,
    SuppressedFinding, SuppressionMatch, SuppressionSource, SuppressionState, Vulnerability,
};
use serde_json::{Value, json};
use std::path::PathBuf;

fn freshness_document(staleness: Staleness, yanked: bool) -> ScanDocument {
    ScanDocument::new(vec![ScanResult {
        package: Package::new(
            Ecosystem::CratesIo,
            "example",
            "2.0.0",
            PathBuf::from("Cargo.lock"),
        ),
        vulns: vec![],
        latest: Some(LatestVersions {
            latest_stable: if staleness > Staleness::Current {
                "3.0.0".to_owned()
            } else {
                "1.9.0".to_owned()
            },
            latest_matching: None,
            staleness,
            yanked,
        }),
        errors: vec![],
        suppressed: vec![],
    }])
}

#[test]
fn soft_provider_errors_are_visible_in_every_report_format() {
    let mut document = freshness_document(Staleness::Current, false);
    document.results[0].errors.push(EnrichError {
        provider: "osv".to_owned(),
        message: "advisory TEST-FAIL hydration failed".to_owned(),
    });

    let table = render_table(&document, false);
    assert!(table.contains("1 soft failures"));
    assert!(table.contains("WARNING"));
    assert!(table.contains("TEST-FAIL"));

    let summary = render_summary(&document);
    assert!(summary.contains("1 soft failures"));

    let markdown = render_markdown(&document);
    assert!(markdown.contains("## Soft failures"));
    assert!(markdown.contains("advisory TEST-FAIL hydration failed"));

    let json = render(&document, OutputFormat::Json, false).unwrap();
    assert!(json.contains("\"provider\": \"osv\""));
    assert!(json.contains("TEST-FAIL"));

    let sarif = render_sarif(&document);
    let soft_failure = sarif
        .pointer("/runs/0/results")
        .and_then(Value::as_array)
        .and_then(|results| {
            results.iter().find(|result| {
                result.get("ruleId").and_then(Value::as_str) == Some("DEPSCAN-PROVIDER-ERROR")
            })
        })
        .expect("SARIF soft failure result");
    assert_eq!(
        soft_failure.pointer("/properties/provider"),
        Some(&json!("osv"))
    );
    assert_eq!(
        soft_failure.pointer("/properties/soft_failure"),
        Some(&json!(true))
    );
}

fn vulnerability_document(withdrawn: bool) -> ScanDocument {
    ScanDocument::new(vec![ScanResult {
        package: Package::new(
            Ecosystem::Npm,
            "example",
            "1.0.0",
            PathBuf::from("package-lock.json"),
        ),
        vulns: vec![Vulnerability {
            id: "GHSA-WITHDRAWN".to_owned(),
            aliases: vec![],
            summary: "withdrawn fixture".to_owned(),
            severity: Some(Severity::High),
            cvss_score: Some(8.0),
            fixed_in: vec![],
            references: vec![],
            withdrawn,
        }],
        latest: None,
        errors: vec![],
        suppressed: vec![],
    }])
}

fn suppression_document(active: bool) -> ScanDocument {
    let vulnerability = Vulnerability {
        id: "GHSA-SUPPRESSED".to_owned(),
        aliases: vec!["CVE-2099-0001".to_owned()],
        summary: "suppression fixture".to_owned(),
        severity: Some(Severity::High),
        cvss_score: Some(8.0),
        fixed_in: vec!["1.1.0".to_owned()],
        references: vec!["https://example.test/advisory".to_owned()],
        withdrawn: false,
    };
    let mut matches = vec![SuppressionMatch {
        matched_id: "CVE-2099-0001".to_owned(),
        source: SuppressionSource::Config,
        reason: Some("accepted until the next release".to_owned()),
        expires: NaiveDate::from_ymd_opt(2099, 1, 1),
        state: if active {
            SuppressionState::Active
        } else {
            SuppressionState::Expired
        },
    }];
    if active {
        matches.push(SuppressionMatch {
            matched_id: "GHSA-SUPPRESSED".to_owned(),
            source: SuppressionSource::Config,
            reason: Some("old exception".to_owned()),
            expires: NaiveDate::from_ymd_opt(2020, 1, 1),
            state: SuppressionState::Expired,
        });
    }
    ScanDocument::new(vec![ScanResult {
        package: Package::new(
            Ecosystem::Npm,
            "example",
            "1.0.0",
            PathBuf::from("package-lock.json"),
        ),
        vulns: if active {
            vec![]
        } else {
            vec![vulnerability.clone()]
        },
        latest: None,
        errors: vec![],
        suppressed: vec![SuppressedFinding {
            vulnerability,
            active,
            matches,
        }],
    }])
}

#[test]
fn emits_schema_version_json() {
    let doc = ScanDocument::new(vec![ScanResult {
        package: Package::new(
            Ecosystem::Npm,
            "x",
            "1.0.0",
            PathBuf::from("package-lock.json"),
        ),
        vulns: vec![],
        latest: None,
        errors: vec![],
        suppressed: vec![],
    }]);
    assert!(
        render(&doc, OutputFormat::Json, false)
            .unwrap()
            .contains("\"schema_version\": 4")
    );
}

#[test]
fn manifest_resolution_preserves_constraint_and_distinguishes_latest_versions() {
    let mut package = Package::new(
        Ecosystem::Npm,
        "range-example",
        "^1.2.0",
        PathBuf::from("package.json"),
    );
    package.set_manifest_constraint("^1.2.0");
    let document = ScanDocument::new(vec![ScanResult {
        package,
        vulns: vec![],
        latest: Some(LatestVersions {
            latest_stable: "2.0.0".to_owned(),
            latest_matching: Some("1.9.4".to_owned()),
            staleness: Staleness::Unknown,
            yanked: false,
        }),
        errors: vec![],
        suppressed: vec![],
    }]);

    let table = render(&document, OutputFormat::Table, false).unwrap();
    let markdown = render(&document, OutputFormat::Markdown, false).unwrap();
    let json = render(&document, OutputFormat::Json, false).unwrap();

    assert!(table.contains("RESOLVED  range-example ^1.2.0 → 1.9.4"));
    assert!(table.contains("latest stable: 2.0.0"));
    assert!(markdown.contains("| range-example | ^1.2.0 | 1.9.4 | 2.0.0 | Resolved |"));
    assert!(json.contains("\"raw\": \"^1.2.0\""));
    assert!(json.contains("\"normalized\": \"^1.2.0\""));
    assert!(json.contains("\"latest_stable\": \"2.0.0\""));
    assert!(json.contains("\"latest_matching\": \"1.9.4\""));
}

#[test]
fn yanked_current_is_visible_in_every_format_and_counted_once() {
    let document = freshness_document(Staleness::Current, true);
    let table = render(&document, OutputFormat::Table, false).unwrap();
    let markdown = render(&document, OutputFormat::Markdown, false).unwrap();
    let json = render(&document, OutputFormat::Json, false).unwrap();
    let sarif = render(&document, OutputFormat::Sarif, false).unwrap();
    let summary = render(&document, OutputFormat::Summary, false).unwrap();

    assert!(table.contains("YANKED"));
    assert!(table.contains("latest non-yanked stable is 1.9.0"));
    assert!(!table.contains("CURRENT"));
    assert!(markdown.contains("Yanked"));
    assert!(json.contains("\"yanked\": true"));
    assert!(sarif.contains("DEPSCAN-YANKED"));
    assert!(sarif.contains("\"level\": \"warning\""));
    assert!(summary.contains("1 outdated (0 major, 1 yanked)"));

    let totals = Totals::from_document(&document);
    assert_eq!(totals.outdated, 1);
    assert_eq!(totals.yanked, 1);
}

#[test]
fn yanked_outdated_renders_both_risks_without_double_counting() {
    let document = freshness_document(Staleness::Major, true);
    let table = render(&document, OutputFormat::Table, false).unwrap();

    assert_eq!(table.matches("YANKED").count(), 1);
    assert_eq!(table.matches("MAJOR").count(), 1);
    assert!(table.contains("3.0.0 available"));
    let totals = Totals::from_document(&document);
    assert_eq!(totals.outdated, 1);
    assert_eq!(totals.yanked, 1);
}

#[test]
fn non_yanked_current_release_has_no_risk_signal() {
    let document = freshness_document(Staleness::Current, false);

    for format in [
        OutputFormat::Table,
        OutputFormat::Markdown,
        OutputFormat::Json,
        OutputFormat::Sarif,
        OutputFormat::Summary,
    ] {
        let rendered = render(&document, format, false).unwrap();
        assert!(!rendered.contains("DEPSCAN-YANKED"));
        assert!(!rendered.contains("YANKED"));
    }
    let totals = Totals::from_document(&document);
    assert_eq!(totals.outdated, 0);
    assert_eq!(totals.yanked, 0);
}

#[test]
fn retained_withdrawn_advisory_is_visible_in_every_format_and_total() {
    let document = vulnerability_document(true);
    let table = render(&document, OutputFormat::Table, false).unwrap();
    let markdown = render(&document, OutputFormat::Markdown, false).unwrap();
    let json = render(&document, OutputFormat::Json, false).unwrap();
    let sarif = render(&document, OutputFormat::Sarif, false).unwrap();
    let summary = render(&document, OutputFormat::Summary, false).unwrap();

    assert!(table.contains("GHSA-WITHDRAWN [WITHDRAWN]"));
    assert!(markdown.contains("| Withdrawn | withdrawn fixture |"));
    assert!(json.contains("\"withdrawn\": true"));
    assert!(sarif.contains("withdrawn advisory"));
    assert!(sarif.contains("\"withdrawn\": true"));
    assert!(summary.contains("1 vulns (1 high) | 1 withdrawn"));
    let totals = Totals::from_document(&document);
    assert_eq!(totals.vulnerable, 1);
    assert_eq!(totals.vulns, 1);
    assert_eq!(totals.withdrawn, 1);
}

#[test]
fn active_advisory_is_not_labeled_withdrawn() {
    let document = vulnerability_document(false);

    assert!(
        !render(&document, OutputFormat::Table, false)
            .unwrap()
            .contains("[WITHDRAWN]")
    );
    assert!(
        !render(&document, OutputFormat::Sarif, false)
            .unwrap()
            .contains("withdrawn advisory")
    );
    assert!(
        !render(&document, OutputFormat::Markdown, false)
            .unwrap()
            .contains("| Withdrawn |")
    );
    assert_eq!(Totals::from_document(&document).withdrawn, 0);
}

#[test]
fn active_suppression_is_auditable_in_every_format() {
    let document = suppression_document(true);
    let table = render(&document, OutputFormat::Table, false).unwrap();
    let markdown = render(&document, OutputFormat::Markdown, false).unwrap();
    let json = render(&document, OutputFormat::Json, false).unwrap();
    let sarif = render(&document, OutputFormat::Sarif, false).unwrap();
    let summary = render(&document, OutputFormat::Summary, false).unwrap();

    assert!(table.contains("SUPPRESS"));
    assert!(table.contains("EXPIRED"));
    assert!(table.contains("accepted until the next release"));
    assert!(table.contains("expired rule did not suppress this finding"));
    assert!(markdown.contains("| Active | example | GHSA-SUPPRESSED | CVE-2099-0001 | config |"));
    assert!(
        markdown.contains("| Expired | example | GHSA-SUPPRESSED | GHSA-SUPPRESSED | config |")
    );
    assert!(json.contains("\"active\": true"));
    assert!(json.contains("\"vulnerability\""));
    assert!(json.contains("\"reason\": \"accepted until the next release\""));
    assert!(json.contains("\"state\": \"expired\""));
    assert!(sarif.contains("\"suppressions\""));
    assert!(sarif.contains("\"status\": \"accepted\""));
    assert!(sarif.contains("DEPSCAN-EXPIRED-SUPPRESSION"));
    assert!(summary.contains("1 suppressed | 1 expired ignores"));

    let totals = Totals::from_document(&document);
    assert_eq!(totals.vulns, 0);
    assert_eq!(totals.suppressed, 1);
    assert_eq!(totals.expired_ignores, 1);
}

#[test]
fn expired_only_suppression_keeps_the_vulnerability_actionable() {
    let document = suppression_document(false);
    let table = render(&document, OutputFormat::Table, false).unwrap();
    let markdown = render(&document, OutputFormat::Markdown, false).unwrap();
    let sarif = render(&document, OutputFormat::Sarif, false).unwrap();
    let summary = render(&document, OutputFormat::Summary, false).unwrap();

    assert!(table.contains("HIGH"));
    assert!(table.contains("EXPIRED"));
    assert!(!table.contains("\n  SUPPRESS"));
    assert!(markdown.contains("| Expired | example | GHSA-SUPPRESSED | CVE-2099-0001 | config |"));
    assert_eq!(sarif.matches("\"ruleId\": \"GHSA-SUPPRESSED\"").count(), 1);
    assert_eq!(
        sarif
            .matches("\"ruleId\": \"DEPSCAN-EXPIRED-SUPPRESSION\"")
            .count(),
        1
    );
    assert!(summary.contains("1 vulns (1 high)"));
    assert!(summary.contains("0 suppressed | 1 expired ignores"));

    let totals = Totals::from_document(&document);
    assert_eq!(totals.vulns, 1);
    assert_eq!(totals.suppressed, 0);
    assert_eq!(totals.expired_ignores, 1);
}
