use crate::{
    Totals,
    formatting::{
        latest_requires_action, paint, result_sort_key, severity_label, staleness_label,
        suppression_match_details,
    },
};
use depscan_core::{ScanDocument, ScanResult, Severity, Staleness, SuppressionState};
use std::collections::BTreeMap;

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
