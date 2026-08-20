//! Shared domain model and ecosystem-aware version/range logic for depscan.

mod constraint;
mod ecosystem;
mod errors;
mod file_identity;
mod finding;
mod nuget;
mod osv;
mod package;
mod providers;
mod scan;
mod version;

pub use constraint::{VersionConstraintError, latest_matching_version};
pub use ecosystem::{DetectedSource, Ecosystem, SourceKind, normalize_name};
pub use errors::{ParseError, ProviderError};
#[doc(hidden)]
pub use file_identity::FileIdentity;
pub use finding::{
    EnrichError, LatestVersions, RegistryEnrichment, Severity, Staleness, SuppressedFinding,
    SuppressionMatch, SuppressionSource, SuppressionState, Vulnerability,
};
pub use nuget::{NuGetVersion, NuGetVersionError};
pub use osv::{OsvAffectedEvaluation, OsvEvaluationError, evaluate_osv_affected};
pub use package::{ManifestConstraint, Package};
pub use providers::{EcosystemParser, VersionProvider, VulnMap, VulnProvider, VulnQueryOutcome};
pub use scan::{ScanDocument, ScanResult};
pub use version::{
    classify_staleness, compare_versions, pypi_version_is_prerelease, pypi_version_is_stable,
};

pub const SCHEMA_VERSION: u32 = 4;

#[cfg(test)]
mod tests;
