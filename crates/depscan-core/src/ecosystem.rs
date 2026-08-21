use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Deliberately exhaustive (not `#[non_exhaustive]`): adding an ecosystem is a
/// semver-major event on purpose, so every match across the workspace and downstream is a
/// compile-time checklist of the code a new ecosystem must touch.
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
    /// Human-readable name used in reports. Currently identical to [`Self::osv_name`] for
    /// every supported ecosystem; kept as a separate accessor so report naming can diverge
    /// from OSV's identifiers without an API break.
    pub fn display_name(self) -> &'static str {
        self.osv_name()
    }
}

/// Deliberately exhaustive (not `#[non_exhaustive]`), like [`Ecosystem`]: a new lockfile or
/// manifest kind is a semver-major event so parser dispatch and every consumer must handle it
/// at compile time rather than falling into a silent wildcard.
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
