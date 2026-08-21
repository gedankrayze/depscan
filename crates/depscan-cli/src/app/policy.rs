use super::*;

pub(super) fn has_vulnerability_failure(
    document: &ScanDocument,
    threshold: VulnerabilityThreshold,
) -> bool {
    let min = match threshold {
        VulnerabilityThreshold::Never => return false,
        VulnerabilityThreshold::Any => Severity::Unknown,
        VulnerabilityThreshold::Low => Severity::Low,
        VulnerabilityThreshold::Medium => Severity::Medium,
        VulnerabilityThreshold::High => Severity::High,
        VulnerabilityThreshold::Critical => Severity::Critical,
    };
    document
        .results
        .iter()
        .flat_map(|r| &r.vulns)
        .any(|v| v.severity.unwrap_or(Severity::Unknown) >= min)
}
pub(super) fn has_outdated_failure(document: &ScanDocument, threshold: OutdatedThreshold) -> bool {
    let min = match threshold {
        OutdatedThreshold::Never => return false,
        OutdatedThreshold::Patch => Staleness::Patch,
        OutdatedThreshold::Minor => Staleness::Minor,
        OutdatedThreshold::Major => Staleness::Major,
    };
    document
        .results
        .iter()
        .filter_map(|r| r.latest.as_ref())
        .any(|latest| latest.yanked || latest.staleness >= min)
}
fn filter_packages(packages: &mut Vec<Package>, no_dev: bool, direct_only: bool) {
    packages.retain(|package| {
        (!no_dev || !package.dev_known || !package.dev)
            && (!direct_only || !package.direct_known || package.direct)
    });
}

pub(super) fn consolidate_packages(
    packages: Vec<Package>,
    no_dev: bool,
    direct_only: bool,
) -> Vec<Package> {
    let mut packages = depscan_core::dedup_packages(packages);
    filter_packages(&mut packages, no_dev, direct_only);
    packages
}
