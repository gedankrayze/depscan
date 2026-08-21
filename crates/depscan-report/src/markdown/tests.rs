use super::*;
use crate::OutputFormat;
use chrono::{TimeZone, Utc};
use depscan_core::{
    Ecosystem, EnrichError, LatestVersions, Package, Severity, Staleness, SuppressedFinding,
    SuppressionMatch, SuppressionSource, Vulnerability,
};
use std::path::{Path, PathBuf};

#[test]
fn renders_complete_auditable_sections_and_escapes_untrusted_cells() {
    let mut package = Package::new(
        Ecosystem::Npm,
        "pkg|<script>_[x]",
        "1.0.0",
        PathBuf::from("package-lock.json"),
    );
    package.set_manifest_constraint("^1.0.0");
    let vulnerability = Vulnerability {
        id: "GHSA|<unsafe>".to_owned(),
        aliases: vec!["CVE-2099-0001".to_owned()],
        summary: "first line\n<script>second|line</script>".to_owned(),
        severity: Some(Severity::High),
        cvss_score: Some(8.0),
        fixed_in: vec!["2.0.0".to_owned()],
        references: vec![],
        withdrawn: true,
    };
    let document = ScanDocument::at(
        vec![ScanResult {
            package,
            vulns: vec![vulnerability.clone()],
            latest: Some(LatestVersions {
                latest_stable: "2.0.0".to_owned(),
                latest_matching: Some("1.9.0".to_owned()),
                staleness: Staleness::Major,
                yanked: true,
            }),
            errors: vec![EnrichError {
                provider: "registry".to_owned(),
                message: "failed | <unsafe>".to_owned(),
            }],
            suppressed: vec![SuppressedFinding {
                vulnerability,
                active: true,
                matches: vec![SuppressionMatch {
                    matched_id: "CVE-2099-0001".to_owned(),
                    source: SuppressionSource::Config,
                    reason: Some("accepted | <temporarily>".to_owned()),
                    expires: None,
                    state: SuppressionState::Active,
                }],
            }],
        }],
        Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap(),
    );

    let rendered = render_markdown(&document);

    assert!(rendered.starts_with(
        "# depscan report\n\n_Gedank Rayze DepScan, v2.0.0, \
         [https://github.com/gedankrayze/depscan](https://github.com/gedankrayze/depscan)_\n\n\
         Generated: `2026-08-20T12:00:00+00:00`"
    ));
    for section in [
        "## Summary",
        "## Vulnerabilities",
        "## Dependency status",
        "## Suppressions",
        "## Soft failures",
    ] {
        assert!(rendered.contains(section));
    }
    assert!(rendered.contains("pkg&#124;&lt;script&gt;&#95;&#91;x&#93;"));
    assert!(rendered.contains("first line<br>&lt;script&gt;second&#124;line&lt;/script&gt;"));
    assert!(rendered.contains("Yanked, major update, Resolved"));
    assert!(rendered.contains("accepted &#124; &lt;temporarily&gt;"));
    assert!(rendered.contains("failed &#124; &lt;unsafe&gt;"));
    assert!(!rendered.contains("<script>"));
}

#[test]
fn empty_document_names_every_empty_audit_section() {
    let document = ScanDocument::at(vec![], Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap());

    let rendered = render_markdown(&document);

    assert!(rendered.contains("| Packages | 0 |"));
    assert_eq!(rendered.matches("_None._").count(), 4);
}

#[test]
fn unresolved_manifest_constraint_remains_visible_without_registry_metadata() {
    let mut package = Package::new(
        Ecosystem::NuGet,
        "Preview.Package",
        "1.0.0-alpha",
        PathBuf::from("example.csproj"),
    );
    package.set_manifest_constraint("1.0.0-alpha");
    let document = ScanDocument::new(vec![ScanResult {
        package,
        vulns: vec![],
        latest: None,
        errors: vec![],
        suppressed: vec![],
    }]);

    let rendered = render_markdown(&document);

    assert!(
        rendered.contains("| Preview.Package | 1.0.0-alpha | Unknown | Unknown | Unresolved |")
    );
}

#[test]
fn markdown_format_infers_only_documented_extensions() {
    assert_eq!(
        OutputFormat::infer(Path::new("report.md")),
        Some(OutputFormat::Markdown)
    );
    assert_eq!(
        OutputFormat::infer(Path::new("report.markdown")),
        Some(OutputFormat::Markdown)
    );
}
