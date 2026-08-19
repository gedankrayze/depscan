//! Stable report renderers for human terminals and CI integrations.

use depscan_core::{
    LatestVersions, ScanDocument, ScanResult, Severity, Staleness, SuppressionMatch,
    SuppressionSource, SuppressionState, Vulnerability,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
    Sarif,
    Summary,
}
impl OutputFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "table" => Some(Self::Table),
            "json" => Some(Self::Json),
            "sarif" => Some(Self::Sarif),
            "summary" => Some(Self::Summary),
            _ => None,
        }
    }
    pub fn infer(path: &Path) -> Option<Self> {
        match path.extension().and_then(|x| x.to_str()) {
            Some("json") => Some(Self::Json),
            Some("sarif") => Some(Self::Sarif),
            Some("txt" | "log") => Some(Self::Summary),
            _ => None,
        }
    }
}

pub fn render(
    document: &ScanDocument,
    format: OutputFormat,
    color: bool,
) -> Result<String, serde_json::Error> {
    match format {
        OutputFormat::Table => Ok(render_table(document, color)),
        OutputFormat::Json => serde_json::to_string_pretty(document),
        OutputFormat::Sarif => serde_json::to_string_pretty(&render_sarif(document)),
        OutputFormat::Summary => Ok(render_summary(document)),
    }
}

pub fn render_table(document: &ScanDocument, color: bool) -> String {
    let totals = Totals::from_document(document);
    let mut text = format!(
        "depscan: {} packages scanned | {} vulnerable | {} withdrawn | {} outdated | {} yanked | {} suppressed | {} expired ignores | {} soft failures\n",
        totals.packages,
        totals.vulnerable,
        totals.withdrawn,
        totals.outdated,
        totals.yanked,
        totals.suppressed,
        totals.expired_ignores,
        totals.errors
    );
    let mut grouped: BTreeMap<_, Vec<&ScanResult>> = BTreeMap::new();
    for result in &document.results {
        grouped
            .entry(result.package.ecosystem)
            .or_default()
            .push(result);
    }
    for (ecosystem, mut results) in grouped {
        results.sort_by_key(|result| std::cmp::Reverse(result_sort_key(result)));
        let vulnerable = results.iter().filter(|r| !r.vulns.is_empty()).count();
        let outdated = results
            .iter()
            .filter(|r| r.latest.as_ref().is_some_and(latest_requires_action))
            .count();
        let yanked = results
            .iter()
            .filter(|result| result.latest.as_ref().is_some_and(|latest| latest.yanked))
            .count();
        text.push_str(&format!(
            "\n{} ({} packages, {} vulnerable, {} outdated, {} yanked)\n",
            ecosystem.display_name(),
            results.len(),
            vulnerable,
            outdated,
            yanked
        ));
        for result in results {
            for vuln in &result.vulns {
                let sev = vuln.severity.unwrap_or(Severity::Unknown);
                let label = severity_label(sev, color);
                let aliases = if vuln.aliases.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", vuln.aliases.join(", "))
                };
                let fixed = if vuln.fixed_in.is_empty() {
                    String::new()
                } else {
                    format!(" fixed in {}", vuln.fixed_in.join(", "))
                };
                let withdrawn = if vuln.withdrawn { " [WITHDRAWN]" } else { "" };
                text.push_str(&format!(
                    "  {label:>8}  {} {} → {}{withdrawn}{}{}\n",
                    result.package.display_name, result.package.version, vuln.id, aliases, fixed
                ));
                text.push_str(&format!(
                    "            {}\n",
                    vuln.summary.lines().next().unwrap_or("No summary supplied")
                ));
            }
            for finding in &result.suppressed {
                for matched in &finding.matches {
                    let (raw_label, color_code, suffix) = match matched.state {
                        SuppressionState::Active => ("SUPPRESS", 36, ""),
                        SuppressionState::Expired => (
                            "EXPIRED",
                            31,
                            "; expired rule did not suppress this finding",
                        ),
                    };
                    let label = paint(raw_label, color_code, color);
                    text.push_str(&format!(
                        "  {label:>8}  {} {} → {} matched {} ({}){suffix}\n",
                        result.package.display_name,
                        result.package.version,
                        finding.vulnerability.id,
                        matched.matched_id,
                        suppression_match_details(matched)
                    ));
                }
            }
            if let Some(latest) = &result.latest {
                if let Some(constraint) = &result.package.manifest_constraint {
                    let label = paint("RESOLVED", 36, color);
                    if let Some(matching) = &latest.latest_matching {
                        text.push_str(&format!(
                            "  {label:>8}  {} {} → {} (latest stable: {})\n",
                            result.package.display_name,
                            constraint.raw(),
                            matching,
                            latest.latest_stable
                        ));
                    } else {
                        text.push_str(&format!(
                            "  {label:>8}  {} {} has no matching published release (latest stable: {})\n",
                            result.package.display_name,
                            constraint.raw(),
                            latest.latest_stable
                        ));
                    }
                }
                if latest.yanked {
                    let label = paint("YANKED", 31, color);
                    text.push_str(&format!(
                        "  {label:>8}  {} {} is yanked/deprecated; latest non-yanked stable is {}\n",
                        result.package.display_name,
                        result.package.version,
                        latest.latest_stable
                    ));
                }
                if latest.staleness > Staleness::Current {
                    let label = staleness_label(latest.staleness, color);
                    text.push_str(&format!(
                        "  {label:>8}  {} {} → {} available\n",
                        result.package.display_name, result.package.version, latest.latest_stable
                    ));
                }
            }
            for error in &result.errors {
                text.push_str(&format!(
                    "  WARNING   {} {}: {}\n",
                    result.package.display_name, error.provider, error.message
                ));
            }
        }
    }
    text
}
fn result_sort_key(result: &ScanResult) -> (Severity, bool, Staleness) {
    (
        result
            .vulns
            .iter()
            .map(|v| v.severity.unwrap_or(Severity::Unknown))
            .max()
            .unwrap_or(Severity::Unknown),
        result.latest.as_ref().is_some_and(|latest| latest.yanked),
        result
            .latest
            .as_ref()
            .map(|l| l.staleness)
            .unwrap_or(Staleness::Unknown),
    )
}

fn latest_requires_action(latest: &LatestVersions) -> bool {
    latest.yanked || latest.staleness > Staleness::Current
}
fn severity_label(severity: Severity, color: bool) -> String {
    let raw = match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Unknown => "UNKNOWN",
    };
    paint(
        raw,
        match severity {
            Severity::Critical | Severity::High => 31,
            Severity::Medium => 33,
            Severity::Low => 36,
            Severity::Unknown => 37,
        },
        color,
    )
}
fn staleness_label(staleness: Staleness, color: bool) -> String {
    let raw = match staleness {
        Staleness::Major => "MAJOR",
        Staleness::Minor => "MINOR",
        Staleness::Patch => "PATCH",
        Staleness::Current => "CURRENT",
        Staleness::Unknown => "UNKNOWN",
    };
    paint(
        raw,
        match staleness {
            Staleness::Major => 35,
            Staleness::Minor => 33,
            Staleness::Patch => 36,
            _ => 37,
        },
        color,
    )
}
fn paint(input: &str, code: u8, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{code}m{input}\x1b[0m")
    } else {
        input.to_owned()
    }
}

fn suppression_source_label(source: SuppressionSource) -> &'static str {
    match source {
        SuppressionSource::Cli => "cli",
        SuppressionSource::Config => "config",
    }
}

fn suppression_match_details(matched: &SuppressionMatch) -> String {
    let mut details = vec![format!(
        "source: {}",
        suppression_source_label(matched.source)
    )];
    if let Some(reason) = &matched.reason {
        details.push(format!("reason: {reason}"));
    }
    if let Some(expires) = matched.expires {
        details.push(format!("expires: {expires}"));
    }
    details.join(", ")
}

pub fn render_summary(document: &ScanDocument) -> String {
    let t = Totals::from_document(document);
    let mut severities = BTreeMap::<Severity, usize>::new();
    for result in &document.results {
        for vuln in &result.vulns {
            *severities
                .entry(vuln.severity.unwrap_or(Severity::Unknown))
                .or_default() += 1;
        }
    }
    let detail = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ]
    .into_iter()
    .filter_map(|s| {
        severities
            .get(&s)
            .map(|n| format!("{n} {}", format!("{s:?}").to_ascii_lowercase()))
    })
    .collect::<Vec<_>>()
    .join(", ");
    let major = document
        .results
        .iter()
        .filter(|r| {
            r.latest
                .as_ref()
                .is_some_and(|l| l.staleness == Staleness::Major)
        })
        .count();
    format!(
        "depscan: {} packages | {} vulns{} | {} withdrawn | {} outdated ({} major, {} yanked) | {} suppressed | {} expired ignores | {} soft failures\n",
        t.packages,
        t.vulns,
        if detail.is_empty() {
            String::new()
        } else {
            format!(" ({detail})")
        },
        t.withdrawn,
        t.outdated,
        major,
        t.yanked,
        t.suppressed,
        t.expired_ignores,
        t.errors
    )
}

pub fn render_sarif(document: &ScanDocument) -> Value {
    let mut rules = BTreeMap::<String, Value>::new();
    let mut results = Vec::new();
    for result in &document.results {
        for vuln in &result.vulns {
            insert_vulnerability_rule(&mut rules, vuln);
            results.push(sarif_vulnerability_result(result, vuln));
        }
        for finding in &result.suppressed {
            if finding.active {
                insert_vulnerability_rule(&mut rules, &finding.vulnerability);
                let mut sarif_result = sarif_vulnerability_result(result, &finding.vulnerability);
                let active_matches = finding
                    .matches
                    .iter()
                    .filter(|matched| matched.state == SuppressionState::Active)
                    .collect::<Vec<_>>();
                sarif_result
                    .as_object_mut()
                    .expect("result is an object")
                    .insert(
                        "suppressions".to_owned(),
                        json!([{
                            "kind": "external",
                            "status": "accepted",
                            "justification": active_matches
                                .iter()
                                .map(|matched| suppression_match_details(matched))
                                .collect::<Vec<_>>()
                                .join("; ")
                        }]),
                    );
                sarif_result
                    .get_mut("properties")
                    .and_then(Value::as_object_mut)
                    .expect("result properties are an object")
                    .extend([
                        ("suppressed".to_owned(), json!(true)),
                        ("suppression_matches".to_owned(), json!(finding.matches)),
                    ]);
                results.push(sarif_result);
            }
            for matched in finding
                .matches
                .iter()
                .filter(|matched| matched.state == SuppressionState::Expired)
            {
                let rule_id = "DEPSCAN-EXPIRED-SUPPRESSION";
                rules.entry(rule_id.to_owned()).or_insert_with(|| {
                    json!({
                        "id": rule_id,
                        "shortDescription": {
                            "text": "Expired dependency suppression no longer applies"
                        }
                    })
                });
                results.push(json!({
                    "ruleId": rule_id,
                    "level": "warning",
                    "message": {"text": format!(
                        "Expired suppression {} did not suppress {} {} affected by {} ({})",
                        matched.matched_id,
                        result.package.display_name,
                        result.package.version,
                        finding.vulnerability.id,
                        suppression_match_details(matched)
                    )},
                    "locations": [{"physicalLocation": {"artifactLocation": {
                        "uri": result.package.source_file.to_string_lossy()
                    }}}],
                    "properties": {
                        "ecosystem": result.package.ecosystem.osv_name(),
                        "package": result.package.name,
                        "version": result.package.version,
                        "vulnerability": finding.vulnerability.id,
                        "suppression_match": matched
                    }
                }));
            }
        }
        if let Some(latest) = &result.latest
            && latest.yanked
        {
            let rule_id = "DEPSCAN-YANKED";
            rules.entry(rule_id.to_owned()).or_insert_with(|| json!({
                "id": rule_id,
                "shortDescription": {"text": "Installed dependency version is yanked or deprecated"}
            }));
            results.push(json!({
                "ruleId": rule_id,
                "level": "warning",
                "message": {"text": format!(
                    "{} {} is yanked or deprecated; latest non-yanked stable version is {}",
                    result.package.display_name,
                    result.package.version,
                    latest.latest_stable
                )},
                "locations": [{"physicalLocation": {"artifactLocation": {
                    "uri": result.package.source_file.to_string_lossy()
                }}}],
                "properties": {
                    "ecosystem": result.package.ecosystem.osv_name(),
                    "package": result.package.name,
                    "version": result.package.version,
                    "latest_stable": latest.latest_stable,
                    "staleness": latest.staleness,
                    "yanked": true
                }
            }));
        }
        for error in &result.errors {
            let rule_id = "DEPSCAN-PROVIDER-ERROR";
            rules.entry(rule_id.to_owned()).or_insert_with(|| {
                json!({
                    "id": rule_id,
                    "shortDescription": {
                        "text": "Dependency enrichment was incomplete"
                    }
                })
            });
            results.push(json!({
                "ruleId": rule_id,
                "level": "warning",
                "message": {"text": format!(
                    "{} {} could not be fully enriched by {}: {}",
                    result.package.display_name,
                    result.package.version,
                    error.provider,
                    error.message
                )},
                "locations": [{"physicalLocation": {"artifactLocation": {
                    "uri": result.package.source_file.to_string_lossy()
                }}}],
                "properties": {
                    "ecosystem": result.package.ecosystem.osv_name(),
                    "package": result.package.name,
                    "version": result.package.version,
                    "provider": error.provider,
                    "soft_failure": true
                }
            }));
        }
    }
    json!({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "depscan", "informationUri": "https://github.com/gedankrayze/depscan", "rules": rules.into_values().collect::<Vec<_>>() }}, "results": results}]})
}

fn insert_vulnerability_rule(rules: &mut BTreeMap<String, Value>, vulnerability: &Vulnerability) {
    rules.entry(vulnerability.id.clone()).or_insert_with(|| {
        json!({
            "id": vulnerability.id,
            "shortDescription": {"text": vulnerability.summary},
            "helpUri": vulnerability.references.first()
        })
    });
}

fn sarif_vulnerability_result(result: &ScanResult, vulnerability: &Vulnerability) -> Value {
    let withdrawn = if vulnerability.withdrawn {
        " (withdrawn advisory)"
    } else {
        ""
    };
    json!({
        "ruleId": vulnerability.id,
        "level": vulnerability.severity.unwrap_or(Severity::Unknown).sarif_level(),
        "message": {"text": format!(
            "{} {} is affected by {}{withdrawn}: {}",
            result.package.display_name,
            result.package.version,
            vulnerability.id,
            vulnerability.summary
        )},
        "locations": [{"physicalLocation": {"artifactLocation": {
            "uri": result.package.source_file.to_string_lossy()
        }}}],
        "properties": {
            "ecosystem": result.package.ecosystem.osv_name(),
            "package": result.package.name,
            "version": result.package.version,
            "fixed_in": vulnerability.fixed_in,
            "withdrawn": vulnerability.withdrawn
        }
    })
}

#[derive(Debug, Default)]
pub struct Totals {
    pub packages: usize,
    pub vulnerable: usize,
    pub vulns: usize,
    pub withdrawn: usize,
    pub outdated: usize,
    pub yanked: usize,
    pub suppressed: usize,
    pub expired_ignores: usize,
    pub errors: usize,
}
impl Totals {
    pub fn from_document(document: &ScanDocument) -> Self {
        let packages = document.results.len();
        let vulnerable = document
            .results
            .iter()
            .filter(|r| !r.vulns.is_empty())
            .count();
        let vulns = document.results.iter().flat_map(|r| r.vulns.iter()).count();
        let withdrawn = document
            .results
            .iter()
            .flat_map(|result| result.vulns.iter())
            .filter(|vulnerability| vulnerability.withdrawn)
            .count();
        let outdated = document
            .results
            .iter()
            .filter(|r| r.latest.as_ref().is_some_and(latest_requires_action))
            .count();
        let yanked = document
            .results
            .iter()
            .filter(|result| result.latest.as_ref().is_some_and(|latest| latest.yanked))
            .count();
        let suppressed = document
            .results
            .iter()
            .flat_map(|result| result.suppressed.iter())
            .filter(|finding| finding.active)
            .count();
        let expired_ignores = document
            .results
            .iter()
            .flat_map(|result| result.suppressed.iter())
            .flat_map(|finding| finding.matches.iter())
            .filter(|matched| matched.state == SuppressionState::Expired)
            .count();
        let errors = document.results.iter().map(|r| r.errors.len()).sum();
        Self {
            packages,
            vulnerable,
            vulns,
            withdrawn,
            outdated,
            yanked,
            suppressed,
            expired_ignores,
            errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use depscan_core::{
        Ecosystem, EnrichError, LatestVersions, Package, ScanResult, SuppressedFinding,
        SuppressionMatch, SuppressionSource, SuppressionState, Vulnerability,
    };
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
        let json = render(&document, OutputFormat::Json, false).unwrap();

        assert!(table.contains("RESOLVED  range-example ^1.2.0 → 1.9.4"));
        assert!(table.contains("latest stable: 2.0.0"));
        assert!(json.contains("\"raw\": \"^1.2.0\""));
        assert!(json.contains("\"normalized\": \"^1.2.0\""));
        assert!(json.contains("\"latest_stable\": \"2.0.0\""));
        assert!(json.contains("\"latest_matching\": \"1.9.4\""));
    }

    #[test]
    fn yanked_current_is_visible_in_every_format_and_counted_once() {
        let document = freshness_document(Staleness::Current, true);
        let table = render(&document, OutputFormat::Table, false).unwrap();
        let json = render(&document, OutputFormat::Json, false).unwrap();
        let sarif = render(&document, OutputFormat::Sarif, false).unwrap();
        let summary = render(&document, OutputFormat::Summary, false).unwrap();

        assert!(table.contains("YANKED"));
        assert!(table.contains("latest non-yanked stable is 1.9.0"));
        assert!(!table.contains("CURRENT"));
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
        let json = render(&document, OutputFormat::Json, false).unwrap();
        let sarif = render(&document, OutputFormat::Sarif, false).unwrap();
        let summary = render(&document, OutputFormat::Summary, false).unwrap();

        assert!(table.contains("GHSA-WITHDRAWN [WITHDRAWN]"));
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
        assert_eq!(Totals::from_document(&document).withdrawn, 0);
    }

    #[test]
    fn active_suppression_is_auditable_in_every_format() {
        let document = suppression_document(true);
        let table = render(&document, OutputFormat::Table, false).unwrap();
        let json = render(&document, OutputFormat::Json, false).unwrap();
        let sarif = render(&document, OutputFormat::Sarif, false).unwrap();
        let summary = render(&document, OutputFormat::Summary, false).unwrap();

        assert!(table.contains("SUPPRESS"));
        assert!(table.contains("EXPIRED"));
        assert!(table.contains("accepted until the next release"));
        assert!(table.contains("expired rule did not suppress this finding"));
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
        let sarif = render(&document, OutputFormat::Sarif, false).unwrap();
        let summary = render(&document, OutputFormat::Summary, false).unwrap();

        assert!(table.contains("HIGH"));
        assert!(table.contains("EXPIRED"));
        assert!(!table.contains("\n  SUPPRESS"));
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
}
