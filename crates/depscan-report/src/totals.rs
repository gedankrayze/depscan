use crate::formatting::latest_requires_action;
use depscan_core::{ScanDocument, SuppressionState};

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
