//! Shared domain model and ecosystem-aware version/range logic for depscan.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
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
    /// Canonical name used for API lookups.
    pub name: String,
    /// Original casing, retained for human output when applicable.
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
        Ecosystem::PyPI => compare_pep440ish(a, b),
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

// A deliberately conservative PEP 440 ordering fallback. It recognizes epochs, release
// segments, common pre-release labels, and post/dev releases without treating text as a panic.
fn compare_pep440ish(a: &str, b: &str) -> Ordering {
    fn parts(s: &str) -> (u64, Vec<u64>, i8, u64, i64, i64) {
        let s = s.trim().to_ascii_lowercase();
        let (epoch, rest) = s
            .split_once('!')
            .map_or((0, s.as_str()), |(e, r)| (e.parse().unwrap_or(0), r));
        let mut release = Vec::new();
        let mut token = String::new();
        let mut phase = 0i8;
        let mut phase_no = 0u64;
        let mut post = -1i64;
        let mut dev = -1i64;
        let mut chars = rest.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch.is_ascii_digit() {
                token.push(ch);
                continue;
            }
            if !token.is_empty() {
                release.push(token.parse().unwrap_or(0));
                token.clear();
            }
            let remainder: String = chars.collect();
            let text = format!("{}{}", ch, remainder);
            let parse_tail = |x: &str| {
                x.trim_start_matches(|c: char| !c.is_ascii_digit())
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse()
                    .unwrap_or(0)
            };
            if text.starts_with("a") || text.starts_with("alpha") {
                phase = -3;
                phase_no = parse_tail(&text);
            } else if text.starts_with("b") || text.starts_with("beta") {
                phase = -2;
                phase_no = parse_tail(&text);
            } else if text.starts_with("rc") || text.starts_with("c") || text.starts_with("pre") {
                phase = -1;
                phase_no = parse_tail(&text);
            } else if text.starts_with("post") || text.starts_with("rev") || text.starts_with("r") {
                post = parse_tail(&text) as i64;
            } else if text.starts_with("dev") {
                dev = parse_tail(&text) as i64;
                phase = -4;
            }
            break;
        }
        if !token.is_empty() {
            release.push(token.parse().unwrap_or(0));
        }
        while release.last() == Some(&0) {
            release.pop();
        }
        (epoch, release, phase, phase_no, post, dev)
    }
    let (ae, ar, aph, apn, apo, adv) = parts(a);
    let (be, br, bph, bpn, bpo, bdv) = parts(b);
    ae.cmp(&be)
        .then_with(|| {
            for i in 0..ar.len().max(br.len()) {
                let c = ar
                    .get(i)
                    .copied()
                    .unwrap_or(0)
                    .cmp(&br.get(i).copied().unwrap_or(0));
                if c != Ordering::Equal {
                    return c;
                }
            }
            Ordering::Equal
        })
        .then(aph.cmp(&bph))
        .then(apn.cmp(&bpn))
        .then(apo.cmp(&bpo))
        .then(adv.cmp(&bdv))
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
        Ecosystem::NuGet | Ecosystem::PyPI => {
            let a = numeric_release(installed);
            let b = numeric_release(latest);
            if a.first() != b.first() {
                Staleness::Major
            } else if a.get(1) != b.get(1) {
                Staleness::Minor
            } else {
                Staleness::Patch
            }
        }
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
    fn matches_osv_events() {
        let events: Vec<serde_json::Value> =
            serde_json::from_str(r#"[{"introduced":"0"},{"fixed":"2.0.0"}]"#).unwrap();
        assert!(osv_range_matches(Ecosystem::Npm, "1.5.0", &events));
        assert!(!osv_range_matches(Ecosystem::Npm, "2.0.0", &events));
    }
}
