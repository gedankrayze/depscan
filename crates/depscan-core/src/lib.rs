//! Shared domain model and ecosystem-aware version/range logic for depscan.

mod constraint;
mod file_identity;
mod nuget;
mod osv;

pub use constraint::{VersionConstraintError, latest_matching_version};
#[doc(hidden)]
pub use file_identity::FileIdentity;
pub use nuget::{NuGetVersion, NuGetVersionError};
pub use osv::{OsvAffectedEvaluation, OsvEvaluationError, evaluate_osv_affected};

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use pep440_rs::Version as Pep440Version;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::HashMap,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub const SCHEMA_VERSION: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    PyPI,
    NuGet,
    CratesIo,
}

impl Ecosystem {
    pub fn osv_name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::PyPI => "PyPI",
            Self::NuGet => "NuGet",
            Self::CratesIo => "crates.io",
        }
    }
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::PyPI => "PyPI",
            Self::NuGet => "NuGet",
            Self::CratesIo => "crates.io",
        }
    }
    pub fn from_cli(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "npm" | "node" | "bun" => Some(Self::Npm),
            "pypi" | "python" => Some(Self::PyPI),
            "nuget" | "dotnet" | ".net" => Some(Self::NuGet),
            "cargo" | "crates" | "crates.io" | "rust" => Some(Self::CratesIo),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceKind {
    BunLock,
    BunLockBinary,
    PackageLock,
    PnpmLock,
    YarnLock,
    PackageJson,
    UvLock,
    PoetryLock,
    PipfileLock,
    RequirementsTxt,
    PyProject,
    PackagesLock,
    ProjectFile,
    DirectoryPackagesProps,
    PackagesConfig,
    CargoLock,
    CargoToml,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedSource {
    pub path: PathBuf,
    pub kind: SourceKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestConstraint {
    /// Exact source spelling, retained for diagnostics and reports.
    pub raw: String,
    /// Registry-standard constraint consumed by the ecosystem evaluator.
    pub normalized: String,
}

impl ManifestConstraint {
    pub fn new(raw: impl Into<String>) -> Self {
        let raw = raw.into();
        Self {
            normalized: raw.clone(),
            raw,
        }
    }

    pub fn with_normalized(raw: impl Into<String>, normalized: impl Into<String>) -> Self {
        Self {
            raw: raw.into(),
            normalized: normalized.into(),
        }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn normalized(&self) -> &str {
        &self.normalized
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    pub ecosystem: Ecosystem,
    /// Normalized package identity, also suitable for registry lookups.
    pub name: String,
    /// Source-preserved spelling used for display and case-sensitive provider lookups.
    pub display_name: String,
    /// A resolved version, or a range in manifest-only mode.
    pub version: String,
    pub direct: bool,
    /// Whether `direct` is an observed classification rather than a conservative default.
    #[serde(default = "classification_known")]
    pub direct_known: bool,
    pub dev: bool,
    /// Whether `dev` is an observed classification rather than a conservative default.
    #[serde(default = "classification_known")]
    pub dev_known: bool,
    pub source_file: PathBuf,
    pub enrichable: bool,
    pub resolved_from_range: bool,
    /// Manifest-only constraint provenance. `normalized` may differ from `raw` when a manifest
    /// uses an ecosystem-specific shorthand such as Poetry's caret requirements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_constraint: Option<ManifestConstraint>,
}

impl Package {
    pub fn new(
        ecosystem: Ecosystem,
        name: impl Into<String>,
        version: impl Into<String>,
        source_file: PathBuf,
    ) -> Self {
        let display_name = name.into();
        let name = normalize_name(ecosystem, &display_name);
        Self {
            ecosystem,
            name,
            display_name,
            version: version.into(),
            direct: false,
            direct_known: true,
            dev: false,
            dev_known: true,
            source_file,
            enrichable: true,
            resolved_from_range: false,
            manifest_constraint: None,
        }
    }

    pub fn set_manifest_constraint(&mut self, raw: impl Into<String>) {
        self.manifest_constraint = Some(ManifestConstraint::new(raw));
        self.resolved_from_range = true;
    }

    pub fn set_normalized_manifest_constraint(
        &mut self,
        raw: impl Into<String>,
        normalized: impl Into<String>,
    ) {
        self.manifest_constraint = Some(ManifestConstraint::with_normalized(raw, normalized));
        self.resolved_from_range = true;
    }
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.ecosystem.osv_name(),
            self.name,
            self.version
        )
    }

    /// Merge parser metadata for the same package coordinate without turning unknown
    /// classifications into false certainty. Provider eligibility is existential:
    /// one proven public-registry occurrence is sufficient to query that coordinate.
    pub fn merge_metadata(&mut self, other: &Self) {
        merge_directness(
            &mut self.direct,
            &mut self.direct_known,
            other.direct,
            other.direct_known,
        );
        merge_development_scope(
            &mut self.dev,
            &mut self.dev_known,
            other.dev,
            other.dev_known,
        );
        self.enrichable |= other.enrichable;
        self.resolved_from_range &= other.resolved_from_range;
    }
}

const fn classification_known() -> bool {
    true
}

fn merge_directness(value: &mut bool, known: &mut bool, other_value: bool, other_known: bool) {
    if (*known && *value) || (other_known && other_value) {
        *value = true;
        *known = true;
    } else if *known && other_known {
        *value = false;
    } else {
        *value = false;
        *known = false;
    }
}

fn merge_development_scope(
    value: &mut bool,
    known: &mut bool,
    other_value: bool,
    other_known: bool,
) {
    if (*known && !*value) || (other_known && !other_value) {
        *value = false;
        *known = true;
    } else if *known && other_known {
        *value = true;
    } else {
        *value = false;
        *known = false;
    }
}

pub fn normalize_name(ecosystem: Ecosystem, name: &str) -> String {
    match ecosystem {
        Ecosystem::PyPI => {
            let mut out = String::new();
            let mut separator = false;
            for ch in name.chars() {
                if matches!(ch, '-' | '_' | '.') {
                    separator = true;
                } else {
                    if separator && !out.is_empty() {
                        out.push('-');
                    }
                    separator = false;
                    out.push(ch.to_ascii_lowercase());
                }
            }
            out
        }
        Ecosystem::NuGet => name.to_ascii_lowercase(),
        _ => name.to_owned(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_cvss(score: f32) -> Self {
        if score >= 9.0 {
            Self::Critical
        } else if score >= 7.0 {
            Self::High
        } else if score >= 4.0 {
            Self::Medium
        } else if score > 0.0 {
            Self::Low
        } else {
            Self::Unknown
        }
    }
    pub fn sarif_level(self) -> &'static str {
        match self {
            Self::Critical | Self::High => "error",
            Self::Medium => "warning",
            Self::Low | Self::Unknown => "note",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub summary: String,
    pub severity: Option<Severity>,
    pub cvss_score: Option<f32>,
    #[serde(default)]
    pub fixed_in: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub withdrawn: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum SuppressionSource {
    Cli,
    Config,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum SuppressionState {
    Active,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct SuppressionMatch {
    /// The advisory ID or alias that matched the suppression rule.
    pub matched_id: String,
    pub source: SuppressionSource,
    pub reason: Option<String>,
    pub expires: Option<NaiveDate>,
    pub state: SuppressionState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SuppressedFinding {
    /// The complete finding remains available for audit and machine-readable reports.
    pub vulnerability: Vulnerability,
    /// `true` when at least one active match removed this vulnerability from failure thresholds.
    pub active: bool,
    /// Every distinct matching rule, including expired and cross-source duplicates.
    pub matches: Vec<SuppressionMatch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum Staleness {
    Unknown,
    Current,
    Patch,
    Minor,
    Major,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatestVersions {
    pub latest_stable: String,
    pub latest_matching: Option<String>,
    pub staleness: Staleness,
    pub yanked: bool,
}

impl LatestVersions {
    pub fn unknown() -> Self {
        Self {
            latest_stable: String::new(),
            latest_matching: None,
            staleness: Staleness::Unknown,
            yanked: false,
        }
    }
}

/// Registry data used while planning provider work.
///
/// `canonical_name` is provider-facing metadata and is deliberately kept separate from
/// [`LatestVersions`] and [`Package`]. This lets orchestration use a registry-authoritative name
/// without changing the source spelling retained in reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEnrichment {
    pub latest: LatestVersions,
    pub canonical_name: Option<String>,
}

impl RegistryEnrichment {
    pub fn versions_only(latest: LatestVersions) -> Self {
        Self {
            latest,
            canonical_name: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrichError {
    pub provider: String,
    pub message: String,
}

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

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("failed to parse {path}: {message}")]
    Invalid { path: PathBuf, message: String },
    #[error("I/O for {path}: {message}")]
    Io { path: PathBuf, message: String },
}

#[derive(Debug, Clone, Error)]
pub enum ProviderError {
    #[error("network provider failed: {0}")]
    Network(String),
    #[error("offline data is unavailable: {0}")]
    Offline(String),
    #[error("invalid package name {name:?} for {ecosystem:?}: {reason}")]
    InvalidPackageName {
        ecosystem: Ecosystem,
        name: String,
        reason: String,
    },
    #[error("invalid provider response: {0}")]
    InvalidResponse(String),
    #[error("cache error: {0}")]
    Cache(String),
}

pub trait EcosystemParser: Send + Sync {
    fn ecosystem(&self) -> Ecosystem;
    fn detect(&self, dir: &Path) -> Vec<DetectedSource>;
    fn parse(&self, source: &DetectedSource) -> Result<Vec<Package>, ParseError>;
}

pub type VulnMap = HashMap<String, Vec<Vulnerability>>;

/// A vulnerability-provider result that can preserve trustworthy package results when another
/// package could not be enriched.
///
/// Keys in both maps are [`Package::key`] values. A package with an error must not be interpreted
/// as having a clean vulnerability result, even when its vulnerability vector is empty.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VulnQueryOutcome {
    pub vulnerabilities: VulnMap,
    pub errors: HashMap<String, Vec<EnrichError>>,
}

impl VulnQueryOutcome {
    pub fn complete(vulnerabilities: VulnMap) -> Self {
        Self {
            vulnerabilities,
            errors: HashMap::new(),
        }
    }
}

#[async_trait]
pub trait VulnProvider: Send + Sync {
    async fn query(&self, packages: &[Package]) -> Result<VulnQueryOutcome, ProviderError>;
}
#[async_trait]
pub trait VersionProvider: Send + Sync {
    async fn latest(&self, package: &Package) -> Result<RegistryEnrichment, ProviderError>;
}

pub fn compare_versions(ecosystem: Ecosystem, a: &str, b: &str) -> Ordering {
    match ecosystem {
        Ecosystem::Npm | Ecosystem::CratesIo => Version::parse(a).ok().cmp(&Version::parse(b).ok()),
        Ecosystem::NuGet => compare_nuget(a, b),
        Ecosystem::PyPI => compare_pep440(a, b),
    }
}

fn compare_nuget(a: &str, b: &str) -> Ordering {
    match (NuGetVersion::parse(a), NuGetVersion::parse(b)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        // A malformed registry version must never displace a valid NuGet version.
        (Ok(_), Err(_)) => Ordering::Greater,
        (Err(_), Ok(_)) => Ordering::Less,
        (Err(_), Err(_)) => a
            .trim()
            .to_ascii_lowercase()
            .cmp(&b.trim().to_ascii_lowercase())
            .then_with(|| a.cmp(b)),
    }
}

fn parse_pep440(version: &str) -> Option<Pep440Version> {
    version.trim().parse().ok()
}

fn compare_pep440(a: &str, b: &str) -> Ordering {
    match (parse_pep440(a), parse_pep440(b)) {
        (Some(a), Some(b)) => a.cmp(&b),
        // A malformed registry version must never displace a valid PEP 440 version.
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => a
            .trim()
            .to_ascii_lowercase()
            .cmp(&b.trim().to_ascii_lowercase())
            .then_with(|| a.cmp(b)),
    }
}

/// Returns whether a PyPI version is a valid PEP 440 pre-release or development release.
/// Invalid versions return `false`.
pub fn pypi_version_is_prerelease(version: &str) -> bool {
    parse_pep440(version).is_some_and(|version| version.any_prerelease())
}

/// Returns whether a PyPI version is valid PEP 440 and stable.
/// Invalid versions return `false` so they cannot be selected as registry candidates.
pub fn pypi_version_is_stable(version: &str) -> bool {
    parse_pep440(version).is_some_and(|version| version.is_stable())
}

pub fn classify_staleness(ecosystem: Ecosystem, installed: &str, latest: &str) -> Staleness {
    if ecosystem == Ecosystem::NuGet {
        return match (NuGetVersion::parse(installed), NuGetVersion::parse(latest)) {
            (Ok(installed), Ok(latest)) if installed >= latest => Staleness::Current,
            (Ok(installed), Ok(latest)) => {
                classify_release_segments(installed.release_segments(), latest.release_segments())
            }
            _ => Staleness::Unknown,
        };
    }

    if compare_versions(ecosystem, installed, latest) != Ordering::Less {
        return Staleness::Current;
    }
    match ecosystem {
        Ecosystem::Npm | Ecosystem::CratesIo => {
            match (Version::parse(installed), Version::parse(latest)) {
                (Ok(a), Ok(b)) if a.major != b.major => Staleness::Major,
                (Ok(a), Ok(b)) if a.minor != b.minor => Staleness::Minor,
                (Ok(_), Ok(_)) => Staleness::Patch,
                _ => Staleness::Unknown,
            }
        }
        Ecosystem::NuGet => unreachable!("NuGet staleness is handled using parsed versions"),
        Ecosystem::PyPI => match (parse_pep440(installed), parse_pep440(latest)) {
            (Some(a), Some(b)) if a.epoch() != b.epoch() => Staleness::Major,
            (Some(a), Some(b)) => classify_release_segments(a.release(), b.release()),
            _ => Staleness::Unknown,
        },
    }
}

fn classify_release_segments<T: PartialEq>(installed: &[T], latest: &[T]) -> Staleness {
    if installed.first() != latest.first() {
        Staleness::Major
    } else if installed.get(1) != latest.get(1) {
        Staleness::Minor
    } else {
        Staleness::Patch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
