use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

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
/// [`LatestVersions`] and [`crate::Package`]. This lets orchestration use a registry-authoritative
/// name
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
