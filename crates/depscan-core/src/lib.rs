//! Shared domain model and ecosystem-aware version/range logic for depscan.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pep440_rs::Version as Pep440Version;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::HashMap,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub const SCHEMA_VERSION: u32 = 1;

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
pub struct Package {
    pub ecosystem: Ecosystem,
    /// Normalized package identity, also suitable for registry lookups.
    pub name: String,
    /// Source-preserved spelling used for display and case-sensitive provider lookups.
    pub display_name: String,
    /// A resolved version, or a range in manifest-only mode.
    pub version: String,
    pub direct: bool,
    pub dev: bool,
    pub source_file: PathBuf,
    pub enrichable: bool,
    pub resolved_from_range: bool,
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
            dev: false,
            source_file,
            enrichable: true,
            resolved_from_range: false,
        }
    }
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.ecosystem.osv_name(),
            self.name,
            self.version
        )
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
    pub suppressed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDocument {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub results: Vec<ScanResult>,
}

impl ScanDocument {
    pub fn new(results: Vec<ScanResult>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            generated_at: Utc::now(),
            results,
        }
    }
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("failed to parse {path}: {message}")]
    Invalid { path: PathBuf, message: String },
    #[error("I/O for {path}: {message}")]
    Io { path: PathBuf, message: String },
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("network provider failed: {0}")]
    Network(String),
    #[error("offline data is unavailable: {0}")]
    Offline(String),
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

#[async_trait]
pub trait VulnProvider: Send + Sync {
    async fn query(&self, packages: &[Package]) -> Result<VulnMap, ProviderError>;
}
#[async_trait]
pub trait VersionProvider: Send + Sync {
    async fn latest(&self, package: &Package) -> Result<LatestVersions, ProviderError>;
}

pub fn compare_versions(ecosystem: Ecosystem, a: &str, b: &str) -> Ordering {
    match ecosystem {
        Ecosystem::Npm | Ecosystem::CratesIo => Version::parse(a).ok().cmp(&Version::parse(b).ok()),
        Ecosystem::NuGet => compare_nuget(a, b),
        Ecosystem::PyPI => compare_pep440(a, b),
    }
}

fn compare_nuget(a: &str, b: &str) -> Ordering {
    let (an, ap) = a.split_once('-').unwrap_or((a, ""));
    let (bn, bp) = b.split_once('-').unwrap_or((b, ""));
    let av: Vec<u64> = an.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    let bv: Vec<u64> = bn.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    for i in 0..av.len().max(bv.len()).max(4) {
        match av
            .get(i)
            .copied()
            .unwrap_or(0)
            .cmp(&bv.get(i).copied().unwrap_or(0))
        {
            Ordering::Equal => {}
            x => return x,
        }
    }
    match (ap.is_empty(), bp.is_empty()) {
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        _ => ap.cmp(bp),
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
        Ecosystem::NuGet => {
            let a = numeric_release(installed);
            let b = numeric_release(latest);
            classify_release_segments(&a, &b)
        }
        Ecosystem::PyPI => match (parse_pep440(installed), parse_pep440(latest)) {
            (Some(a), Some(b)) if a.epoch() != b.epoch() => Staleness::Major,
            (Some(a), Some(b)) => classify_release_segments(a.release(), b.release()),
            _ => Staleness::Unknown,
        },
    }
}

fn classify_release_segments(installed: &[u64], latest: &[u64]) -> Staleness {
    if installed.first() != latest.first() {
        Staleness::Major
    } else if installed.get(1) != latest.get(1) {
        Staleness::Minor
    } else {
        Staleness::Patch
    }
}

fn numeric_release(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap_or(0))
        .collect()
}

/// Match an installed version against a single OSV affected range. Events are evaluated in order;
/// `introduced: "0"` opens a range and `fixed` or `last_affected` closes it.
pub fn osv_range_matches(
    ecosystem: Ecosystem,
    version: &str,
    events: &[serde_json::Value],
) -> bool {
    let mut active = false;
    for event in events {
        if let Some(introduced) = event.get("introduced").and_then(|v| v.as_str()) {
            active = introduced == "0"
                || compare_versions(ecosystem, version, introduced) != Ordering::Less;
        }
        if active {
            if let Some(fixed) = event.get("fixed").and_then(|v| v.as_str()) {
                if compare_versions(ecosystem, version, fixed) != Ordering::Less {
                    active = false;
                }
            }
            if let Some(last) = event.get("last_affected").and_then(|v| v.as_str()) {
                if compare_versions(ecosystem, version, last) == Ordering::Greater {
                    active = false;
                }
            }
        }
    }
    active
}

pub fn osv_fixed_versions(
    ecosystem: Ecosystem,
    installed: &str,
    affected: &[serde_json::Value],
) -> Vec<String> {
    let mut fixed = Vec::new();
    for item in affected {
        for range in item
            .get("ranges")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let events = range
                .get("events")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if osv_range_matches(ecosystem, installed, &events) {
                fixed.extend(
                    events
                        .into_iter()
                        .filter_map(|e| e.get("fixed").and_then(|v| v.as_str()).map(str::to_owned)),
                );
            }
        }
    }
    fixed.sort_by(|a, b| compare_versions(ecosystem, a, b));
    fixed.dedup();
    fixed
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn matches_osv_events() {
        let events: Vec<serde_json::Value> =
            serde_json::from_str(r#"[{"introduced":"0"},{"fixed":"2.0.0"}]"#).unwrap();
        assert!(osv_range_matches(Ecosystem::Npm, "1.5.0", &events));
        assert!(!osv_range_matches(Ecosystem::Npm, "2.0.0", &events));
    }
}
