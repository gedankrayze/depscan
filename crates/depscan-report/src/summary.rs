use crate::Totals;
use depscan_core::{ScanDocument, Severity, Staleness};
use std::collections::BTreeMap;

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
