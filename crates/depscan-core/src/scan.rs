use crate::{
    Ecosystem, EnrichError, LatestVersions, Package, SCHEMA_VERSION, SuppressedFinding,
    Vulnerability, compare_versions,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub package: Package,
    #[serde(default)]
    pub vulns: Vec<Vulnerability>,
    pub latest: Option<LatestVersions>,
    #[serde(default)]
    pub errors: Vec<EnrichError>,
    #[serde(default)]
    pub suppressed: Vec<SuppressedFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDocument {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub results: Vec<ScanResult>,
}

impl ScanDocument {
    pub fn new(results: Vec<ScanResult>) -> Self {
        Self::at(results, Utc::now())
    }

    /// Build a scan document with an orchestration-supplied timestamp and canonical collection
    /// ordering. Supplying the time makes byte-reproducible JSON possible without weakening the
    /// default, real-time timestamp used by [`Self::new`].
    pub fn at(mut results: Vec<ScanResult>, generated_at: DateTime<Utc>) -> Self {
        for result in &mut results {
            for vulnerability in &mut result.vulns {
                canonicalize_vulnerability(vulnerability, result.package.ecosystem);
            }
            result.vulns.sort_by(compare_vulnerabilities);
            result.errors.sort_by(|left, right| {
                left.provider
                    .cmp(&right.provider)
                    .then_with(|| left.message.cmp(&right.message))
            });
            for finding in &mut result.suppressed {
                canonicalize_vulnerability(&mut finding.vulnerability, result.package.ecosystem);
                finding.matches.sort();
                finding.matches.dedup();
            }
            result.suppressed.sort_by(|left, right| {
                compare_vulnerabilities(&left.vulnerability, &right.vulnerability)
                    .then_with(|| left.active.cmp(&right.active))
                    .then_with(|| left.matches.cmp(&right.matches))
            });
            result.suppressed.dedup();
        }
        results.sort_by(|left, right| {
            left.package
                .ecosystem
                .cmp(&right.package.ecosystem)
                .then_with(|| left.package.name.cmp(&right.package.name))
                .then_with(|| left.package.version.cmp(&right.package.version))
                .then_with(|| left.package.display_name.cmp(&right.package.display_name))
                .then_with(|| left.package.source_file.cmp(&right.package.source_file))
                .then_with(|| left.package.direct.cmp(&right.package.direct))
                .then_with(|| left.package.direct_known.cmp(&right.package.direct_known))
                .then_with(|| left.package.dev.cmp(&right.package.dev))
                .then_with(|| left.package.dev_known.cmp(&right.package.dev_known))
                .then_with(|| left.package.enrichable.cmp(&right.package.enrichable))
                .then_with(|| {
                    left.package
                        .manifest_constraint
                        .as_ref()
                        .map(|constraint| (&constraint.raw, &constraint.normalized))
                        .cmp(
                            &right
                                .package
                                .manifest_constraint
                                .as_ref()
                                .map(|constraint| (&constraint.raw, &constraint.normalized)),
                        )
                })
                .then_with(|| {
                    left.package
                        .resolved_from_range
                        .cmp(&right.package.resolved_from_range)
                })
        });

        Self {
            schema_version: SCHEMA_VERSION,
            generated_at,
            results,
        }
    }
}

fn canonicalize_vulnerability(vulnerability: &mut Vulnerability, ecosystem: Ecosystem) {
    vulnerability.aliases.sort();
    vulnerability.aliases.dedup();
    vulnerability.fixed_in.sort_by(|left, right| {
        compare_versions(ecosystem, left, right).then_with(|| left.cmp(right))
    });
    vulnerability.fixed_in.dedup();
    vulnerability.references.sort();
    vulnerability.references.dedup();
}

fn compare_vulnerabilities(left: &Vulnerability, right: &Vulnerability) -> Ordering {
    left.id
        .cmp(&right.id)
        .then_with(|| left.withdrawn.cmp(&right.withdrawn))
        .then_with(|| left.severity.cmp(&right.severity))
        .then_with(|| match (left.cvss_score, right.cvss_score) {
            (Some(left), Some(right)) => left.total_cmp(&right),
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
        .then_with(|| left.summary.cmp(&right.summary))
        .then_with(|| left.aliases.cmp(&right.aliases))
        .then_with(|| left.fixed_in.cmp(&right.fixed_in))
        .then_with(|| left.references.cmp(&right.references))
}
