//! Offline, filesystem-only dependency parsers.

use depscan_core::{
    DetectedSource, Ecosystem, EcosystemParser, Package, ParseError, SourceKind,
    latest_matching_version, normalize_name,
};
use noyalib::policy::MaxScalarLength;
use noyalib::{DuplicateKeyPolicy, MergeKeyPolicy, ParserConfig, Value as Yaml};
use quick_xml::Reader;
use quick_xml::XmlVersion;
use quick_xml::escape::unescape;
use quick_xml::events::{BytesStart, Event};
use serde_json::Value as Json;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};
use toml::Value as Toml;
use url::Url;
use walkdir::WalkDir;

mod npm_minimatch;
mod python_locks;
mod python_manifest;
mod requirements;
mod tool_outputs;

use npm_minimatch::{MAX_WORKSPACE_PATTERNS, NpmMinimatch};

pub use tool_outputs::{parse_bun_lockb_output, parse_dotnet_list_json};

fn nonempty_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Parse the root and declared workspace manifests beside a legacy binary Bun lockfile.
///
/// This is the filesystem-only degraded path used when the CLI cannot execute Bun. Every
/// returned package retains its manifest constraint; no version is invented from `bun.lockb`.
pub fn parse_bun_manifest_fallback(lock_path: &Path) -> Result<Vec<Package>, ParseError> {
    let root = nonempty_parent(lock_path);
    let manifest = root.join("package.json");
    if !manifest.is_file() {
        return Err(invalid(
            lock_path,
            format!(
                "binary Bun lockfile has no usable colocated manifest at {}; install Bun and authorize tool execution, commit bun.lock, or add package.json",
                manifest.display()
            ),
        ));
    }
    parse_package_json_project(&manifest)
}

fn io_error(path: &Path, error: impl ToString) -> ParseError {
    ParseError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}
fn invalid(path: &Path, error: impl ToString) -> ParseError {
    ParseError::Invalid {
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

const YAML_MAX_DOCUMENT_BYTES: usize = 64 * 1024 * 1024;
const YAML_MAX_SCALAR_BYTES: usize = 1024 * 1024;

fn read_yaml_text(path: &Path) -> Result<String, ParseError> {
    let file = fs::File::open(path).map_err(|error| io_error(path, error))?;
    let mut text = String::new();
    file.take(YAML_MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_string(&mut text)
        .map_err(|error| io_error(path, error))?;
    if text.len() > YAML_MAX_DOCUMENT_BYTES {
        return Err(invalid(
            path,
            format!("YAML document exceeds the {YAML_MAX_DOCUMENT_BYTES}-byte input limit"),
        ));
    }
    Ok(text)
}

fn parse_yaml_document(path: &Path, text: &str) -> Result<Yaml, ParseError> {
    let config = ParserConfig::new()
        .max_depth(64)
        .max_document_length(YAML_MAX_DOCUMENT_BYTES)
        .max_alias_expansions(64)
        .max_mapping_keys(100_000)
        .max_sequence_length(100_000)
        .max_events(2_000_000)
        .max_nodes(1_000_000)
        .max_total_scalar_bytes(YAML_MAX_DOCUMENT_BYTES)
        .max_documents(1)
        .alias_anchor_ratio(Some(8.0))
        .duplicate_key_policy(DuplicateKeyPolicy::Error)
        .merge_key_policy(MergeKeyPolicy::Error)
        .with_policy(MaxScalarLength(YAML_MAX_SCALAR_BYTES));

    noyalib::from_str_with_config(text, &config).map_err(|error| invalid(path, error))
}

pub struct ParserSet {
    parsers: Vec<Box<dyn EcosystemParser>>,
}

impl std::fmt::Debug for ParserSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParserSet")
            .field("parsers", &self.parsers.len())
            .finish_non_exhaustive()
    }
}
impl Default for ParserSet {
    fn default() -> Self {
        Self {
            parsers: vec![
                Box::new(NodeParser),
                Box::new(PythonParser),
                Box::new(NugetParser),
                Box::new(CargoParser),
            ],
        }
    }
}
impl ParserSet {
    pub fn detect(&self, root: &Path, allowed: &HashSet<Ecosystem>) -> Vec<DetectedSource> {
        self.parsers
            .iter()
            .filter(|p| allowed.is_empty() || allowed.contains(&p.ecosystem()))
            .flat_map(|p| p.detect(root))
            .collect()
    }
    pub fn parse(&self, source: &DetectedSource) -> Result<Vec<Package>, ParseError> {
        self.parsers
            .iter()
            .find(|p| p.ecosystem() == ecosystem_for_kind(&source.kind))
            .ok_or_else(|| invalid(&source.path, "no parser for detected source"))?
            .parse(source)
    }
}

fn ecosystem_for_kind(kind: &SourceKind) -> Ecosystem {
    match kind {
        SourceKind::BunLock
        | SourceKind::BunLockBinary
        | SourceKind::PackageLock
        | SourceKind::PnpmLock
        | SourceKind::YarnLock
        | SourceKind::PackageJson => Ecosystem::Npm,
        SourceKind::UvLock
        | SourceKind::PoetryLock
        | SourceKind::PipfileLock
        | SourceKind::RequirementsTxt
        | SourceKind::PyProject => Ecosystem::PyPI,
        SourceKind::PackagesLock
        | SourceKind::ProjectFile
        | SourceKind::DirectoryPackagesProps
        | SourceKind::PackagesConfig => Ecosystem::NuGet,
        SourceKind::CargoLock | SourceKind::CargoToml => Ecosystem::CratesIo,
    }
}

fn source(root: &Path, file: &str, kind: SourceKind) -> Option<DetectedSource> {
    let path = root.join(file);
    path.is_file().then_some(DetectedSource { path, kind })
}

mod node;
pub use node::NodeParser;
use node::*;
mod python;
pub use python::PythonParser;
mod nuget;
pub use nuget::NugetParser;
mod cargo;
pub use cargo::CargoParser;

use depscan_core::dedup_packages as dedup;

#[cfg(test)]
mod tests;
