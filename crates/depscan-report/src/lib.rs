//! Stable report renderers for human terminals and CI integrations.

use depscan_core::{ScanDocument, ScanResult, Severity, Staleness};
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
        "depscan: {} packages scanned | {} vulnerable | {} outdated | {} suppressed | {} soft failures\n",
        totals.packages, totals.vulnerable, totals.outdated, totals.suppressed, totals.errors
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
            .filter(|r| {
                r.latest
                    .as_ref()
                    .is_some_and(|l| l.staleness > Staleness::Current)
            })
            .count();
        text.push_str(&format!(
            "\n{} ({} packages, {} vulnerable, {} outdated)\n",
            ecosystem.display_name(),
            results.len(),
            vulnerable,
            outdated
        ));
        for result in results {
            for vuln in result.vulns.iter().filter(|v| !v.withdrawn) {
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
                text.push_str(&format!(
                    "  {label:>8}  {} {} → {}{}{}\n",
                    result.package.display_name, result.package.version, vuln.id, aliases, fixed
                ));
                text.push_str(&format!(
                    "            {}\n",
                    vuln.summary.lines().next().unwrap_or("No summary supplied")
                ));
            }
            if let Some(latest) = &result.latest
                && latest.staleness > Staleness::Current
            {
                let label = staleness_label(latest.staleness, color);
                text.push_str(&format!(
                    "  {label:>8}  {} {} → {} available{}\n",
                    result.package.display_name,
                    result.package.version,
                    latest.latest_stable,
                    if latest.yanked {
                        " (installed version yanked)"
                    } else {
                        ""
                    }
                ));
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
fn result_sort_key(result: &ScanResult) -> (Severity, Staleness) {
    (
        result
            .vulns
            .iter()
            .filter(|v| !v.withdrawn)
            .map(|v| v.severity.unwrap_or(Severity::Unknown))
            .max()
            .unwrap_or(Severity::Unknown),
        result
            .latest
            .as_ref()
            .map(|l| l.staleness)
            .unwrap_or(Staleness::Unknown),
    )
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

pub fn render_summary(document: &ScanDocument) -> String {
    let t = Totals::from_document(document);
    let mut severities = BTreeMap::<Severity, usize>::new();
    for result in &document.results {
        for vuln in &result.vulns {
            if !vuln.withdrawn {
                *severities
                    .entry(vuln.severity.unwrap_or(Severity::Unknown))
                    .or_default() += 1;
            }
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
        "depscan: {} packages | {} vulns{} | {} outdated ({} major) | {} suppressed\n",
        t.packages,
        t.vulns,
        if detail.is_empty() {
            String::new()
        } else {
            format!(" ({detail})")
        },
        t.outdated,
        major,
        t.suppressed
    )
}

pub fn render_sarif(document: &ScanDocument) -> Value {
    let mut rules = BTreeMap::<String, Value>::new();
    let mut results = Vec::new();
    for result in &document.results {
        for vuln in result.vulns.iter().filter(|v| !v.withdrawn) {
            rules.entry(vuln.id.clone()).or_insert_with(|| json!({"id": vuln.id, "shortDescription": {"text": vuln.summary}, "helpUri": vuln.references.first()}));
            results.push(json!({"ruleId": vuln.id, "level": vuln.severity.unwrap_or(Severity::Unknown).sarif_level(), "message": {"text": format!("{} {} is affected by {}: {}", result.package.display_name, result.package.version, vuln.id, vuln.summary)}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": result.package.source_file.to_string_lossy()}}}], "properties": {"ecosystem": result.package.ecosystem.osv_name(), "package": result.package.name, "version": result.package.version, "fixed_in": vuln.fixed_in}}));
        }
    }
    json!({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "depscan", "informationUri": "https://github.com/gedankrayze/depscan", "rules": rules.into_values().collect::<Vec<_>>() }}, "results": results}]})
}

#[derive(Debug, Default)]
pub struct Totals {
    pub packages: usize,
    pub vulnerable: usize,
    pub vulns: usize,
    pub outdated: usize,
    pub suppressed: usize,
    pub errors: usize,
}
impl Totals {
    pub fn from_document(document: &ScanDocument) -> Self {
        let packages = document.results.len();
        let vulnerable = document
            .results
            .iter()
            .filter(|r| r.vulns.iter().any(|v| !v.withdrawn))
            .count();
        let vulns = document
            .results
            .iter()
            .flat_map(|r| r.vulns.iter())
            .filter(|v| !v.withdrawn)
            .count();
        let outdated = document
            .results
            .iter()
            .filter(|r| {
                r.latest
                    .as_ref()
                    .is_some_and(|l| l.staleness > Staleness::Current)
            })
            .count();
        let suppressed = document.results.iter().map(|r| r.suppressed.len()).sum();
        let errors = document.results.iter().map(|r| r.errors.len()).sum();
        Self {
            packages,
            vulnerable,
            vulns,
            outdated,
            suppressed,
            errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use depscan_core::{Ecosystem, Package, ScanResult};
    use std::path::PathBuf;
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
                .contains("schema_version")
        );
    }
}
