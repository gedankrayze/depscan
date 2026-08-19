//! Offline, filesystem-only dependency parsers.

use depscan_core::{
    DetectedSource, Ecosystem, EcosystemParser, Package, ParseError, SourceKind, normalize_name,
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
use walkdir::WalkDir;

mod python_locks;
mod python_manifest;
mod requirements;
mod tool_outputs;

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

fn candidate(root: &Path, file: &str, kind: SourceKind) -> Option<DetectedSource> {
    let path = root.join(file);
    path.is_file().then_some(DetectedSource { path, kind })
}
fn source(root: &Path, name: &str, kind: SourceKind) -> Option<DetectedSource> {
    candidate(root, name, kind)
}

fn sorted_project_files(root: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let mut paths: Vec<_> = WalkDir::new(root)
        .max_depth(5)
        .into_iter()
        .filter_entry(|e| {
            !matches!(
                e.file_name().to_str(),
                Some("node_modules" | ".git" | "target" | ".venv")
            )
        })
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_type().is_file()
                && extensions
                    .iter()
                    .any(|ext| e.path().extension().and_then(|x| x.to_str()) == Some(*ext))
        })
        .map(|e| e.into_path())
        .collect();
    paths.sort();
    paths
}

pub struct NodeParser;
impl EcosystemParser for NodeParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }
    fn detect(&self, root: &Path) -> Vec<DetectedSource> {
        for (file, kind) in [
            ("bun.lock", SourceKind::BunLock),
            ("bun.lockb", SourceKind::BunLockBinary),
            ("package-lock.json", SourceKind::PackageLock),
            ("pnpm-lock.yaml", SourceKind::PnpmLock),
            ("yarn.lock", SourceKind::YarnLock),
        ] {
            if let Some(s) = source(root, file, kind) {
                return vec![s];
            }
        }
        source(root, "package.json", SourceKind::PackageJson)
            .into_iter()
            .collect()
    }
    fn parse(&self, source: &DetectedSource) -> Result<Vec<Package>, ParseError> {
        match source.kind {
            SourceKind::PackageLock => parse_package_lock(&source.path),
            SourceKind::PnpmLock => parse_pnpm_lock(&source.path),
            SourceKind::YarnLock => parse_yarn_lock(&source.path),
            SourceKind::BunLock => parse_bun_lock(&source.path),
            SourceKind::PackageJson => parse_package_json_project(&source.path),
            SourceKind::BunLockBinary => Err(invalid(
                &source.path,
                "bun.lockb is binary; rerun with --allow-tools and Bun on PATH, or commit bun.lock",
            )),
            _ => Err(invalid(&source.path, "unexpected source kind")),
        }
    }
}

#[derive(Default)]
struct NodeDirectDependencies {
    all: HashSet<String>,
    by_directory: BTreeMap<PathBuf, HashSet<String>>,
}

impl NodeDirectDependencies {
    fn includes(&self, name: &str) -> bool {
        self.all.contains(name)
    }

    fn includes_package_at(&self, install_parent: &Path, name: &str) -> bool {
        if install_parent.as_os_str().is_empty() {
            return self.includes(name);
        }

        self.by_directory
            .get(install_parent)
            .is_some_and(|names| names.contains(name))
    }
}

fn node_direct_dependencies(root: &Path) -> NodeDirectDependencies {
    let mut direct = NodeDirectDependencies::default();
    for path in sorted_project_files(root, &["json"])
        .into_iter()
        .filter(|p| p.file_name().and_then(|x| x.to_str()) == Some("package.json"))
    {
        if let Ok(text) = fs::read_to_string(&path)
            && let Ok(value) = serde_json::from_str::<Json>(&text)
        {
            let mut manifest_names = HashSet::new();
            for key in [
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ] {
                if let Some(obj) = value.get(key).and_then(Json::as_object) {
                    manifest_names.extend(obj.keys().cloned());
                }
            }
            if let Some(directory) = path
                .parent()
                .and_then(|parent| parent.strip_prefix(root).ok())
            {
                direct
                    .by_directory
                    .entry(directory.to_path_buf())
                    .or_default()
                    .extend(manifest_names.iter().cloned());
            }
            direct.all.extend(manifest_names);
        }
    }
    direct
}

fn node_direct_names(root: &Path) -> HashSet<String> {
    node_direct_dependencies(root).all
}

#[derive(Debug, Clone, Copy, Default)]
struct YarnDirectness {
    production: bool,
    development: bool,
}

fn yarn_direct_dependencies(root: &Path) -> HashMap<String, YarnDirectness> {
    let mut direct = HashMap::<String, YarnDirectness>::new();
    for path in sorted_project_files(root, &["json"])
        .into_iter()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some("package.json"))
    {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Json>(&text) else {
            continue;
        };
        for (group, is_development) in [
            ("dependencies", false),
            ("devDependencies", true),
            ("optionalDependencies", false),
            ("peerDependencies", false),
        ] {
            let Some(dependencies) = value.get(group).and_then(Json::as_object) else {
                continue;
            };
            for name in dependencies.keys() {
                let flags = direct.entry(name.clone()).or_default();
                if is_development {
                    flags.development = true;
                } else {
                    flags.production = true;
                }
            }
        }
    }
    direct
}

struct NpmPackageLocation {
    name: String,
    install_parent: PathBuf,
}

fn npm_package_location(location: &str) -> Option<NpmPackageLocation> {
    let segments: Vec<_> = location.split('/').collect();
    if segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }

    // npm records install locations, not package names. The final node_modules
    // component identifies nested resolutions without leaking parent paths into
    // the package identity. Root, workspace-target, and other local descriptors
    // have no node_modules component and are intentionally not registry-scanned.
    let node_modules = segments
        .iter()
        .rposition(|segment| *segment == "node_modules")?;
    let package_segments = &segments[node_modules + 1..];
    let name = match package_segments {
        [name] if valid_npm_package_segment(name) && !name.starts_with('@') => (*name).to_owned(),
        [scope, name]
            if scope.starts_with('@')
                && scope.len() > 1
                && valid_npm_package_segment(scope)
                && valid_npm_package_segment(name)
                && !name.starts_with('@') =>
        {
            format!("{scope}/{name}")
        }
        _ => return None,
    };

    Some(NpmPackageLocation {
        name,
        install_parent: segments[..node_modules].iter().collect(),
    })
}

fn valid_npm_package_segment(segment: &str) -> bool {
    !matches!(segment, "" | "." | ".." | "node_modules")
}

fn parse_package_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let root = path.parent().unwrap_or(Path::new("."));
    let direct = node_direct_dependencies(root);
    let value: Json = serde_json::from_str(&text).map_err(|e| invalid(path, e))?;
    let document = value.as_object().ok_or_else(|| {
        invalid(
            path,
            "detected a non-object JSON document; expected an npm package-lock.json object",
        )
    })?;
    let lockfile_version = document
        .get("lockfileVersion")
        .and_then(Json::as_u64)
        .ok_or_else(|| {
            invalid(
                path,
                "detected JSON without an integer lockfileVersion; expected npm package-lock.json version 1, 2, or 3",
            )
        })?;
    let mut packages = Vec::new();
    match lockfile_version {
        1 => {
            let dependencies = document
                .get("dependencies")
                .and_then(Json::as_object)
                .ok_or_else(|| {
                    invalid(
                        path,
                        "detected npm package-lock.json version 1 without a dependencies object; expected the legacy dependency tree",
                    )
                })?;
            parse_legacy_npm_tree(dependencies, path, &direct.all, true, &mut packages);
        }
        2 | 3 => {
            let package_entries = document
                .get("packages")
                .and_then(Json::as_object)
                .ok_or_else(|| {
                    invalid(
                        path,
                        format!(
                            "detected npm package-lock.json version {lockfile_version} without a packages object; expected the version 2/3 packages map"
                        ),
                    )
                })?;
            for (key, entry) in package_entries {
                let Some(entry) = entry.as_object() else {
                    continue;
                };
                if key.is_empty() || entry.get("link").and_then(Json::as_bool) == Some(true) {
                    continue;
                }
                let Some(location) = npm_package_location(key) else {
                    // Workspace targets and other local package descriptors do not
                    // represent registry resolutions in package-lock.json. DS-008
                    // also deliberately ignores malformed install-location keys.
                    continue;
                };
                let Some(version) = entry
                    .get("version")
                    .and_then(Json::as_str)
                    .filter(|version| !version.is_empty())
                else {
                    continue;
                };
                let mut package =
                    Package::new(Ecosystem::Npm, &location.name, version, path.to_path_buf());
                package.direct =
                    direct.includes_package_at(&location.install_parent, &location.name);
                package.dev = entry.get("dev").and_then(Json::as_bool).unwrap_or(false);
                packages.push(package);
            }
        }
        version => {
            return Err(invalid(
                path,
                format!(
                    "detected unsupported npm package-lock.json lockfileVersion {version}; expected version 1, 2, or 3"
                ),
            ));
        }
    }
    Ok(dedup(packages))
}
fn parse_legacy_npm_tree(
    dependencies: &serde_json::Map<String, Json>,
    path: &Path,
    direct: &HashSet<String>,
    top_level: bool,
    out: &mut Vec<Package>,
) {
    for (name, entry) in dependencies {
        let Some(entry) = entry.as_object() else {
            continue;
        };
        if let Some(version) = entry
            .get("version")
            .and_then(Json::as_str)
            .filter(|version| !version.is_empty())
        {
            let mut package = Package::new(Ecosystem::Npm, name, version, path.to_path_buf());
            package.direct = top_level && direct.contains(name);
            package.dev = entry.get("dev").and_then(Json::as_bool).unwrap_or(false);
            out.push(package);
        }
        if let Some(children) = entry.get("dependencies").and_then(Json::as_object) {
            parse_legacy_npm_tree(children, path, direct, false, out);
        }
    }
}

fn parse_bun_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let cleaned = strip_jsonc(&text).map_err(|error| invalid(path, error))?;
    let value: Json = serde_json::from_str(&cleaned).map_err(|e| invalid(path, e))?;
    value.as_object().ok_or_else(|| {
        invalid(
            path,
            "detected a non-object JSONC document; expected a Bun text lockfile object",
        )
    })?;
    let lockfile_version = value
        .get("lockfileVersion")
        .and_then(Json::as_u64)
        .ok_or_else(|| invalid(path, "Bun lockfile is missing an integer lockfileVersion"))?;
    if lockfile_version > 2 {
        return Err(invalid(
            path,
            format!(
                "unsupported Bun lockfileVersion {lockfile_version}; supported versions are 0, 1, and 2"
            ),
        ));
    }

    let workspace_metadata = parse_bun_workspaces(path, &value)?;
    let mut output = Vec::new();
    let packages = value
        .get("packages")
        .ok_or_else(|| {
            invalid(
                path,
                format!(
                    "detected Bun lockfileVersion {lockfile_version} without packages; expected a packages object"
                ),
            )
        })?
        .as_object()
        .ok_or_else(|| invalid(path, "Bun packages must be an object"))?;

    for (package_key, entry) in packages {
        let items = entry.as_array().ok_or_else(|| {
            invalid(
                path,
                format!("Bun package {package_key:?} must be a locator array"),
            )
        })?;
        let locator = items.first().and_then(Json::as_str).ok_or_else(|| {
            invalid(
                path,
                format!(
                    "Bun package {package_key:?} locator array must start with a string locator"
                ),
            )
        })?;
        let resolution = parse_bun_locator(locator).map_err(|error| {
            invalid(
                path,
                format!("Bun package {package_key:?} has invalid locator {locator:?}: {error}"),
            )
        })?;
        validate_bun_locator_array(
            path,
            package_key,
            items,
            resolution,
            lockfile_version,
            &workspace_metadata.names,
        )?;

        if let BunResolution::Registry { name, version } = resolution {
            let directness = workspace_metadata.direct.get(package_key).or_else(|| {
                (package_key == name)
                    .then(|| workspace_metadata.direct.get(name))
                    .flatten()
            });
            let mut package = Package::new(Ecosystem::Npm, name, version, path.to_path_buf());
            if workspace_metadata.direct.contains_key(package_key) && package_key != name {
                // The packages key is the installed alias while the locator name is the
                // registry identity that OSV and npm need.
                package.display_name = package_key.clone();
            }
            if let Some(directness) = directness {
                package.direct = true;
                package.dev = directness.development && !directness.production;
            }
            output.push(package);
        }
    }
    Ok(dedup(output))
}

#[derive(Debug, Clone, Copy, Default)]
struct BunDirectness {
    production: bool,
    development: bool,
}

struct BunWorkspaceMetadata {
    direct: HashMap<String, BunDirectness>,
    names: HashMap<String, String>,
}

fn parse_bun_workspaces(path: &Path, value: &Json) -> Result<BunWorkspaceMetadata, ParseError> {
    let workspaces = value
        .get("workspaces")
        .and_then(Json::as_object)
        .ok_or_else(|| invalid(path, "Bun lockfile is missing a workspaces object"))?;
    if !workspaces.contains_key("") {
        return Err(invalid(
            path,
            "Bun workspaces object is missing the root workspace entry",
        ));
    }

    let mut direct = HashMap::<String, BunDirectness>::new();
    let mut workspace_names = HashMap::new();
    for (workspace_path, workspace) in workspaces {
        let workspace = workspace.as_object().ok_or_else(|| {
            invalid(
                path,
                format!("Bun workspace {workspace_path:?} must be an object"),
            )
        })?;
        if !workspace_path.is_empty() {
            let name = workspace
                .get("name")
                .and_then(Json::as_str)
                .ok_or_else(|| {
                    invalid(
                        path,
                        format!("Bun workspace {workspace_path:?} must have a string name"),
                    )
                })?;
            if let Some(version) = workspace.get("version") {
                let version = version.as_str().ok_or_else(|| {
                    invalid(
                        path,
                        format!("Bun workspace {workspace_path:?} version must be a string"),
                    )
                })?;
                semver::Version::parse(version).map_err(|error| {
                    invalid(
                        path,
                        format!("Bun workspace {workspace_path:?} has invalid version: {error}"),
                    )
                })?;
            }
            workspace_names.insert(workspace_path.clone(), name.to_owned());
        }

        for (group, is_development) in [
            ("dependencies", false),
            ("devDependencies", true),
            ("optionalDependencies", false),
            ("peerDependencies", false),
        ] {
            let Some(dependencies) = workspace.get(group) else {
                continue;
            };
            let dependencies = dependencies.as_object().ok_or_else(|| {
                invalid(
                    path,
                    format!("Bun workspace {workspace_path:?} {group} must be an object"),
                )
            })?;
            for name in dependencies.keys() {
                let flags = direct.entry(name.clone()).or_default();
                if is_development {
                    flags.development = true;
                } else {
                    flags.production = true;
                }
            }
        }
    }
    Ok(BunWorkspaceMetadata {
        direct,
        names: workspace_names,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BunResolution<'a> {
    Registry { name: &'a str, version: &'a str },
    Workspace { name: &'a str, path: &'a str },
    Path,
    Git,
    Tarball,
    Root,
}

fn parse_bun_locator(locator: &str) -> Result<BunResolution<'_>, String> {
    if locator == "@root:" {
        return Ok(BunResolution::Root);
    }

    let separator = if locator.starts_with('@') {
        let slash = locator
            .find('/')
            .ok_or_else(|| "scoped package name is missing '/'".to_owned())?;
        locator[slash + 1..]
            .find('@')
            .map(|index| slash + 1 + index)
            .ok_or_else(|| "scoped package locator is missing '@resolution'".to_owned())?
    } else {
        locator
            .find('@')
            .ok_or_else(|| "package locator is missing '@resolution'".to_owned())?
    };
    let name = &locator[..separator];
    let resolution = &locator[separator + 1..];
    validate_bun_package_name(name)?;
    if resolution.is_empty() {
        return Err("package resolution is empty".to_owned());
    }

    if let Some(workspace_path) = resolution.strip_prefix("workspace:") {
        if workspace_path.is_empty() {
            return Err("workspace resolution path is empty".to_owned());
        }
        return Ok(BunResolution::Workspace {
            name,
            path: workspace_path,
        });
    }
    if resolution.starts_with("file:") || resolution.starts_with("link:") {
        if resolution
            .split_once(':')
            .is_none_or(|(_, value)| value.is_empty())
        {
            return Err("path resolution is empty".to_owned());
        }
        return Ok(BunResolution::Path);
    }
    if let Some(repository) = resolution
        .strip_prefix("git+")
        .or_else(|| resolution.strip_prefix("github:"))
    {
        if repository.is_empty() {
            return Err("git resolution is empty".to_owned());
        }
        return Ok(BunResolution::Git);
    }
    if resolution.starts_with("http://")
        || resolution.starts_with("https://")
        || is_bun_tarball(resolution)
    {
        return Ok(BunResolution::Tarball);
    }

    semver::Version::parse(resolution)
        .map_err(|error| format!("registry resolution is not valid SemVer: {error}"))?;
    Ok(BunResolution::Registry {
        name,
        version: resolution,
    })
}

fn is_bun_tarball(resolution: &str) -> bool {
    let lowercase = resolution.to_ascii_lowercase();
    [".tgz", ".tar.gz", ".tar"]
        .iter()
        .any(|suffix| lowercase.ends_with(suffix))
}

fn validate_bun_package_name(name: &str) -> Result<(), String> {
    let valid = if let Some(scoped) = name.strip_prefix('@') {
        let mut parts = scoped.split('/');
        parts.next().is_some_and(|scope| !scope.is_empty())
            && parts.next().is_some_and(|package| !package.is_empty())
            && parts.next().is_none()
    } else {
        !name.is_empty() && !name.contains('/')
    };
    if !valid
        || name.chars().any(char::is_whitespace)
        || name.contains('\\')
        || matches!(name, "." | "..")
    {
        return Err("package name is malformed".to_owned());
    }
    Ok(())
}

fn validate_bun_locator_array(
    path: &Path,
    package_key: &str,
    items: &[Json],
    resolution: BunResolution<'_>,
    lockfile_version: u64,
    workspaces: &HashMap<String, String>,
) -> Result<(), ParseError> {
    let error = |message: &str| {
        invalid(
            path,
            format!("Bun package {package_key:?} has malformed locator array: {message}"),
        )
    };
    let object_at = |index: usize| items.get(index).is_some_and(Json::is_object);
    let string_at = |index: usize| items.get(index).is_some_and(Json::is_string);

    match resolution {
        BunResolution::Registry { .. } => {
            if items.len() != 4 || !string_at(1) || !object_at(2) || !string_at(3) {
                return Err(error(
                    "registry entries must be [locator, registry, info, integrity]",
                ));
            }
        }
        BunResolution::Workspace {
            name,
            path: workspace_path,
        } => {
            let valid_shape = if lockfile_version == 0 {
                items.len() == 2 && object_at(1)
            } else {
                items.len() == 1
            };
            if !valid_shape {
                return Err(error(if lockfile_version == 0 {
                    "version 0 workspace entries must be [locator, info]"
                } else {
                    "version 1 and 2 workspace entries must contain only the locator"
                }));
            }
            let Some(workspace_name) = workspaces.get(workspace_path) else {
                return Err(error(
                    "workspace locator references an unknown workspace path",
                ));
            };
            if workspace_name != name {
                return Err(error(
                    "workspace locator package name does not match the referenced workspace",
                ));
            }
        }
        BunResolution::Path | BunResolution::Tarball => {
            if !(items.len() == 2 || items.len() == 3)
                || !object_at(1)
                || (items.len() == 3 && !string_at(2))
            {
                return Err(error(
                    "path and tarball entries must be [locator, info] with optional integrity",
                ));
            }
        }
        BunResolution::Git => {
            if !(items.len() == 3 || items.len() == 4)
                || !object_at(1)
                || !string_at(2)
                || (items.len() == 4 && !string_at(3))
            {
                return Err(error(
                    "git entries must be [locator, info, resolved] with optional integrity",
                ));
            }
        }
        BunResolution::Root => {
            if items.len() != 2 || !object_at(1) {
                return Err(error("root entries must be [\"@root:\", info]"));
            }
        }
    }
    Ok(())
}

fn strip_jsonc(input: &str) -> Result<String, String> {
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    let mut quoted = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if quoted {
            result.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
            continue;
        }
        if ch == '"' {
            quoted = true;
            result.push(ch);
        } else if ch == '/' && chars.peek() == Some(&'/') {
            let _ = chars.next();
            for comment in chars.by_ref() {
                if comment == '\n' {
                    result.push('\n');
                    break;
                }
            }
        } else if ch == '/' && chars.peek() == Some(&'*') {
            let _ = chars.next();
            // JSONC comments are whitespace. Preserve a separator so removing a
            // comment cannot accidentally join two otherwise-invalid tokens.
            result.push(' ');
            let mut closed = false;
            let mut previous = '\0';
            for comment in chars.by_ref() {
                if comment == '\n' {
                    result.push('\n');
                }
                if previous == '*' && comment == '/' {
                    closed = true;
                    break;
                }
                previous = comment;
            }
            if !closed {
                return Err("unterminated block comment in Bun lockfile".to_owned());
            }
            result.push(' ');
        } else {
            result.push(ch);
        }
    }
    if quoted {
        return Err("unterminated string in Bun lockfile".to_owned());
    }

    let mut out = String::new();
    let mut iter = result.chars().peekable();
    let mut quoted = false;
    let mut escaped = false;
    while let Some(ch) = iter.next() {
        if quoted {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
            out.push(ch);
        } else if ch == ',' {
            let mut spaces = String::new();
            while matches!(iter.peek(), Some(c) if c.is_whitespace()) {
                if let Some(space) = iter.next() {
                    spaces.push(space);
                }
            }
            if matches!(iter.peek(), Some('}' | ']')) {
                out.push_str(&spaces);
                continue;
            }
            out.push(',');
            out.push_str(&spaces);
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

fn parse_pnpm_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = read_yaml_text(path)?;
    let value = parse_yaml_document(path, &text)?;
    value.as_mapping().ok_or_else(|| {
        invalid(
            path,
            "detected a non-mapping YAML document; expected a pnpm-lock.yaml mapping",
        )
    })?;
    let lockfile_version = value.get("lockfileVersion").ok_or_else(|| {
        invalid(
            path,
            "detected YAML without lockfileVersion; expected pnpm lockfile version 6.0 or 9.0",
        )
    })?;
    let supported_version = lockfile_version
        .as_str()
        .is_some_and(|version| matches!(version, "6" | "6.0" | "9" | "9.0"))
        || lockfile_version
            .as_f64()
            .is_some_and(|version| version == 6.0 || version == 9.0);
    if !supported_version {
        let detected = lockfile_version.as_str().map_or_else(
            || {
                lockfile_version
                    .as_f64()
                    .map_or_else(|| "non-scalar".to_owned(), |version| version.to_string())
            },
            str::to_owned,
        );
        return Err(invalid(
            path,
            format!(
                "detected unsupported pnpm lockfileVersion {detected:?}; expected version 6.0 or 9.0"
            ),
        ));
    }
    let root = path.parent().unwrap_or(Path::new("."));
    let direct = node_direct_names(root);
    let mut out = Vec::new();
    let packages = value
        .get("packages")
        .and_then(Yaml::as_mapping)
        .ok_or_else(|| {
            invalid(
                path,
                "detected a supported pnpm lockfile without a packages mapping; expected the resolved package map",
            )
        })?;
    for (key, entry) in packages {
        let entry = entry.as_mapping().ok_or_else(|| {
            invalid(
                path,
                format!("pnpm package entry {key:?} must be a mapping"),
            )
        })?;
        let (name, version) = parse_pnpm_key(key).ok_or_else(|| {
            invalid(
                path,
                format!("pnpm package key {key:?} is not a supported package locator"),
            )
        })?;
        validate_bun_package_name(name).map_err(|error| {
            invalid(
                path,
                format!("pnpm package key {key:?} has an invalid package name: {error}"),
            )
        })?;
        if version.starts_with("file:")
            || version.starts_with("link:")
            || version.starts_with("workspace:")
            || version.starts_with("git+")
            || version.starts_with("github:")
            || version.starts_with("http://")
            || version.starts_with("https://")
        {
            continue;
        }
        semver::Version::parse(version).map_err(|error| {
            invalid(
                path,
                format!("pnpm package key {key:?} has an invalid npm version {version:?}: {error}"),
            )
        })?;
        let dev = entry
            .get("dev")
            .map(|value| {
                value.as_bool().ok_or_else(|| {
                    invalid(
                        path,
                        format!("pnpm package entry {key:?} dev must be a boolean"),
                    )
                })
            })
            .transpose()?
            .unwrap_or(false);
        let mut package = Package::new(Ecosystem::Npm, name, version, path.to_path_buf());
        package.direct = direct.contains(&package.name);
        package.dev = dev;
        out.push(package);
    }
    Ok(dedup(out))
}
fn parse_pnpm_key(raw: &str) -> Option<(&str, &str)> {
    let key = raw.trim_start_matches('/').split('(').next().unwrap_or(raw);
    let at = if let Some(stripped) = key.strip_prefix('@') {
        stripped.rfind('@').map(|i| i + 1)
    } else {
        key.rfind('@')
    }?;
    let (name, version) = key.split_at(at);
    let version = version.trim_start_matches('@');
    (!name.is_empty() && !version.is_empty()).then_some((name, version))
}

fn parse_yarn_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = read_yaml_text(path)?;
    parse_yarn_lock_text(path, &text)
}

fn parse_yarn_lock_text(path: &Path, text: &str) -> Result<Vec<Package>, ParseError> {
    let root = path.parent().unwrap_or(Path::new("."));
    let direct = yarn_direct_dependencies(root);
    let has_berry_metadata = text.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("__metadata:") || line.starts_with("\"__metadata\":")
    });
    if has_berry_metadata {
        parse_yarn_berry(path, text, &direct)
    } else if text.lines().any(|line| line.trim() == "# yarn lockfile v1") {
        parse_yarn_classic(path, text, &direct)
    } else {
        Err(invalid(
            path,
            "unrecognized Yarn lockfile; expected a Yarn Classic '# yarn lockfile v1' header or Berry __metadata",
        ))
    }
}

const YARN_BERRY_MIN_LOCKFILE_VERSION: u64 = 4;
const YARN_BERRY_MAX_LOCKFILE_VERSION: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum YarnSource {
    Registry,
    Workspace,
    Other,
}

#[derive(Debug, Clone, Copy)]
struct YarnLocator<'a> {
    name: &'a str,
    reference: &'a str,
}

fn parse_yarn_locator(locator: &str) -> Result<YarnLocator<'_>, String> {
    let separator = if locator.starts_with('@') {
        let slash = locator
            .find('/')
            .ok_or_else(|| "scoped package name is missing '/'".to_owned())?;
        locator[slash + 1..]
            .find('@')
            .map(|index| slash + 1 + index)
            .ok_or_else(|| "scoped package locator is missing '@reference'".to_owned())?
    } else {
        locator
            .find('@')
            .ok_or_else(|| "package locator is missing '@reference'".to_owned())?
    };
    let name = &locator[..separator];
    let reference = &locator[separator + 1..];
    validate_bun_package_name(name)?;
    if reference.is_empty() {
        return Err("package reference is empty".to_owned());
    }
    Ok(YarnLocator { name, reference })
}

fn split_yarn_descriptors(raw: &str) -> Result<Vec<String>, String> {
    let mut descriptors = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, ch) in raw.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
        } else if ch == ',' {
            descriptors.push(parse_yarn_scalar(&raw[start..index])?);
            start = index + ch.len_utf8();
        }
    }
    if quoted {
        return Err("unterminated quote in descriptor list".to_owned());
    }
    descriptors.push(parse_yarn_scalar(&raw[start..])?);
    if descriptors.iter().any(String::is_empty) {
        return Err("descriptor list contains an empty selector".to_owned());
    }
    Ok(descriptors)
}

fn parse_yarn_scalar(raw: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("value is empty".to_owned());
    }
    if value.starts_with('"') {
        serde_json::from_str::<String>(value).map_err(|error| error.to_string())
    } else if value.contains('"') || value.chars().any(char::is_whitespace) {
        Err("unquoted value contains quotes or whitespace".to_owned())
    } else {
        Ok(value.to_owned())
    }
}

fn yarn_reference_source(reference: &str) -> YarnSource {
    let reference_without_params = reference.split("::").next().unwrap_or(reference);
    if reference_without_params.starts_with("workspace:") {
        YarnSource::Workspace
    } else if reference_without_params.starts_with("npm:")
        || (!reference_without_params.contains(':')
            && semver::Version::parse(reference_without_params).is_ok())
    {
        YarnSource::Registry
    } else if let Some(inner) = reference_without_params
        .strip_prefix("virtual:")
        .and_then(|value| value.split_once('#').map(|(_, inner)| inner))
    {
        yarn_reference_source(inner)
    } else if reference_without_params.starts_with("patch:")
        && reference_without_params
            .to_ascii_lowercase()
            .contains("@npm%3a")
    {
        YarnSource::Registry
    } else {
        YarnSource::Other
    }
}

fn yarn_direct_metadata(
    descriptors: &[String],
    registry_name: &str,
    direct: &HashMap<String, YarnDirectness>,
) -> Result<(bool, bool, Option<String>), String> {
    let mut flags = YarnDirectness::default();
    let mut display_alias = None;
    for descriptor in descriptors {
        let locator = parse_yarn_locator(descriptor)?;
        if let Some(directness) = direct.get(locator.name) {
            flags.production |= directness.production;
            flags.development |= directness.development;
            if locator.name != registry_name {
                display_alias.get_or_insert_with(|| locator.name.to_owned());
            }
        }
    }
    Ok((
        flags.production || flags.development,
        flags.development && !flags.production,
        display_alias,
    ))
}

fn validate_yarn_registry_version(
    version: &str,
    reference: &str,
    context: &str,
) -> Result<(), String> {
    let parsed_version = semver::Version::parse(version)
        .map_err(|error| format!("{context} has an invalid npm version {version:?}: {error}"))?;
    let exact_reference = reference
        .strip_prefix("npm:")
        .unwrap_or(reference)
        .split("::")
        .next()
        .unwrap_or(reference);
    if reference.starts_with("npm:") || !reference.contains(':') {
        let parsed_reference = semver::Version::parse(exact_reference).map_err(|error| {
            format!("{context} has an invalid npm resolution {reference:?}: {error}")
        })?;
        if parsed_reference != parsed_version {
            return Err(format!(
                "{context} version {version:?} does not match npm resolution {reference:?}"
            ));
        }
    }
    Ok(())
}

fn parse_yarn_berry(
    path: &Path,
    text: &str,
    direct: &HashMap<String, YarnDirectness>,
) -> Result<Vec<Package>, ParseError> {
    let value = parse_yaml_document(path, text)?;
    let entries = value
        .as_mapping()
        .ok_or_else(|| invalid(path, "Yarn Berry lockfile root must be a mapping"))?;
    let metadata = value
        .get("__metadata")
        .and_then(Yaml::as_mapping)
        .ok_or_else(|| invalid(path, "Yarn Berry lockfile is missing a __metadata mapping"))?;
    let lockfile_version = metadata
        .get("version")
        .and_then(Yaml::as_u64)
        .ok_or_else(|| invalid(path, "Yarn Berry __metadata is missing an integer version"))?;
    if !(YARN_BERRY_MIN_LOCKFILE_VERSION..=YARN_BERRY_MAX_LOCKFILE_VERSION)
        .contains(&lockfile_version)
    {
        return Err(invalid(
            path,
            format!(
                "unsupported Yarn Berry lockfile version {lockfile_version}; supported released versions are {YARN_BERRY_MIN_LOCKFILE_VERSION} through {YARN_BERRY_MAX_LOCKFILE_VERSION}"
            ),
        ));
    }

    let mut packages = Vec::new();
    for (raw_key, raw_entry) in entries {
        let key = raw_key.as_str();
        if key == "__metadata" {
            continue;
        }
        let descriptors = split_yarn_descriptors(key).map_err(|error| {
            invalid(
                path,
                format!("invalid Yarn Berry descriptor list {key:?}: {error}"),
            )
        })?;
        for descriptor in &descriptors {
            parse_yarn_locator(descriptor).map_err(|error| {
                invalid(
                    path,
                    format!("invalid Yarn Berry descriptor {descriptor:?}: {error}"),
                )
            })?;
        }
        let entry = raw_entry
            .as_mapping()
            .ok_or_else(|| invalid(path, format!("Yarn Berry entry {key:?} must be a mapping")))?;
        let version = entry.get("version").and_then(Yaml::as_str).ok_or_else(|| {
            invalid(
                path,
                format!("Yarn Berry entry {key:?} is missing a string version"),
            )
        })?;
        let resolution = entry
            .get("resolution")
            .and_then(Yaml::as_str)
            .ok_or_else(|| {
                invalid(
                    path,
                    format!("Yarn Berry entry {key:?} is missing a string resolution"),
                )
            })?;
        let locator = parse_yarn_locator(resolution).map_err(|error| {
            invalid(
                path,
                format!("Yarn Berry entry {key:?} has invalid resolution {resolution:?}: {error}"),
            )
        })?;
        let source = yarn_reference_source(locator.reference);
        if source == YarnSource::Workspace {
            continue;
        }
        if source == YarnSource::Registry {
            validate_yarn_registry_version(
                version,
                locator.reference,
                &format!("Yarn Berry entry {key:?}"),
            )
            .map_err(|error| invalid(path, error))?;
        }
        let (is_direct, is_dev, display_alias) =
            yarn_direct_metadata(&descriptors, locator.name, direct).map_err(|error| {
                invalid(
                    path,
                    format!("Yarn Berry entry {key:?} has invalid descriptor: {error}"),
                )
            })?;
        let mut package = Package::new(Ecosystem::Npm, locator.name, version, path.to_path_buf());
        package.direct = is_direct;
        package.dev = is_dev;
        package.enrichable = source == YarnSource::Registry;
        if let Some(display_alias) = display_alias {
            package.display_name = display_alias;
        }
        packages.push(package);
    }
    Ok(dedup(packages))
}

#[derive(Debug)]
struct YarnClassicEntry {
    key: String,
    descriptors: Vec<String>,
    version: Option<String>,
    resolved: Option<String>,
}

fn parse_yarn_classic(
    path: &Path,
    text: &str,
    direct: &HashMap<String, YarnDirectness>,
) -> Result<Vec<Package>, ParseError> {
    let mut packages = Vec::new();
    let mut current: Option<YarnClassicEntry> = None;
    for (line_index, line) in text.lines().enumerate() {
        let line_number = line_index + 1;
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            if let Some(entry) = current.take() {
                push_yarn_classic_entry(path, entry, direct, &mut packages)?;
            }
            let key = line.strip_suffix(':').ok_or_else(|| {
                invalid(
                    path,
                    format!("invalid Yarn Classic entry header on line {line_number}"),
                )
            })?;
            let descriptors = split_yarn_descriptors(key).map_err(|error| {
                invalid(
                    path,
                    format!("invalid Yarn Classic descriptor list on line {line_number}: {error}"),
                )
            })?;
            for descriptor in &descriptors {
                parse_yarn_locator(descriptor).map_err(|error| {
                    invalid(
                        path,
                        format!(
                            "invalid Yarn Classic descriptor {descriptor:?} on line {line_number}: {error}"
                        ),
                    )
                })?;
            }
            current = Some(YarnClassicEntry {
                key: key.to_owned(),
                descriptors,
                version: None,
                resolved: None,
            });
            continue;
        }
        if line.starts_with('\t') {
            return Err(invalid(
                path,
                format!("Yarn Classic lockfile uses a tab for indentation on line {line_number}"),
            ));
        }
        let indentation = line.bytes().take_while(|byte| *byte == b' ').count();
        if indentation != 2 {
            continue;
        }
        let entry = current.as_mut().ok_or_else(|| {
            invalid(
                path,
                format!("Yarn Classic field appears before an entry on line {line_number}"),
            )
        })?;
        let field = &line[indentation..];
        if let Some(raw_version) = field.strip_prefix("version ") {
            if entry.version.is_some() {
                return Err(invalid(
                    path,
                    format!("Yarn Classic entry {:?} repeats version", entry.key),
                ));
            }
            entry.version = Some(parse_yarn_scalar(raw_version).map_err(|error| {
                invalid(
                    path,
                    format!("invalid Yarn Classic version on line {line_number}: {error}"),
                )
            })?);
        } else if let Some(raw_resolved) = field.strip_prefix("resolved ") {
            if entry.resolved.is_some() {
                return Err(invalid(
                    path,
                    format!("Yarn Classic entry {:?} repeats resolved", entry.key),
                ));
            }
            entry.resolved = Some(parse_yarn_scalar(raw_resolved).map_err(|error| {
                invalid(
                    path,
                    format!("invalid Yarn Classic resolution on line {line_number}: {error}"),
                )
            })?);
        }
    }
    if let Some(entry) = current {
        push_yarn_classic_entry(path, entry, direct, &mut packages)?;
    }
    Ok(dedup(packages))
}

fn push_yarn_classic_entry(
    path: &Path,
    entry: YarnClassicEntry,
    direct: &HashMap<String, YarnDirectness>,
    packages: &mut Vec<Package>,
) -> Result<(), ParseError> {
    let version = entry.version.ok_or_else(|| {
        invalid(
            path,
            format!("Yarn Classic entry {:?} is missing version", entry.key),
        )
    })?;
    let mut source = None;
    let mut package_name = None;
    for descriptor in &entry.descriptors {
        let locator = parse_yarn_locator(descriptor).map_err(|error| invalid(path, error))?;
        let (descriptor_name, descriptor_source) = yarn_classic_descriptor_source(locator)
            .map_err(|error| {
                invalid(
                    path,
                    format!(
                        "Yarn Classic entry {:?} has invalid source descriptor: {error}",
                        entry.key
                    ),
                )
            })?;
        if source.is_some_and(|previous| previous != descriptor_source)
            || package_name
                .as_deref()
                .is_some_and(|previous| previous != descriptor_name)
        {
            return Err(invalid(
                path,
                format!(
                    "Yarn Classic entry {:?} mixes package identities or source protocols",
                    entry.key
                ),
            ));
        }
        source = Some(descriptor_source);
        package_name = Some(descriptor_name.to_owned());
    }
    let source = source.ok_or_else(|| invalid(path, "Yarn Classic entry has no descriptors"))?;
    if source == YarnSource::Workspace {
        return Ok(());
    }
    let package_name =
        package_name.ok_or_else(|| invalid(path, "Yarn Classic entry has no package identity"))?;
    if source == YarnSource::Registry {
        semver::Version::parse(&version).map_err(|error| {
            invalid(
                path,
                format!(
                    "Yarn Classic entry {:?} has an invalid npm version {version:?}: {error}",
                    entry.key
                ),
            )
        })?;
    }
    let (is_direct, is_dev, display_alias) =
        yarn_direct_metadata(&entry.descriptors, &package_name, direct).map_err(|error| {
            invalid(
                path,
                format!(
                    "Yarn Classic entry {:?} has invalid descriptor: {error}",
                    entry.key
                ),
            )
        })?;
    let mut package = Package::new(Ecosystem::Npm, package_name, version, path.to_path_buf());
    package.direct = is_direct;
    package.dev = is_dev;
    package.enrichable = source == YarnSource::Registry;
    if let Some(display_alias) = display_alias {
        package.display_name = display_alias;
    }
    packages.push(package);
    Ok(())
}

fn yarn_classic_descriptor_source(locator: YarnLocator<'_>) -> Result<(&str, YarnSource), String> {
    if let Some(alias) = locator.reference.strip_prefix("npm:") {
        if alias.contains('@') {
            let target = parse_yarn_locator(alias)?;
            return Ok((target.name, YarnSource::Registry));
        }
        return Ok((locator.name, YarnSource::Registry));
    }
    let source = if locator.reference.starts_with("workspace:") {
        YarnSource::Workspace
    } else if locator.reference.contains(':') {
        YarnSource::Other
    } else {
        YarnSource::Registry
    };
    Ok((locator.name, source))
}

fn read_package_json(path: &Path) -> Result<Json, ParseError> {
    let text = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
    let value: Json = serde_json::from_str(&text).map_err(|error| invalid(path, error))?;
    if !value.is_object() {
        return Err(invalid(
            path,
            "package.json must contain a JSON object at the document root",
        ));
    }
    Ok(value)
}

fn npm_manifest_constraint_is_registry(range: &str) -> bool {
    let lower = range.to_ascii_lowercase();
    !lower.starts_with("workspace:")
        && !lower.starts_with("file:")
        && !lower.starts_with("link:")
        && !lower.starts_with("git:")
        && !lower.starts_with("git+")
        && !lower.starts_with("github:")
        && !lower.starts_with("http:")
        && !lower.starts_with("https:")
        && !lower.starts_with("ssh:")
        && !lower.starts_with("npm:")
        && !range.starts_with('/')
        && !range.starts_with("./")
        && !range.starts_with("../")
}

fn parse_package_json_value(path: &Path, value: &Json) -> Result<Vec<Package>, ParseError> {
    let mut out = Vec::new();
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(section) = value.get(key) else {
            continue;
        };
        let obj = section.as_object().ok_or_else(|| {
            invalid(
                path,
                format!("package.json field {key:?} must be an object"),
            )
        })?;
        for (name, range) in obj {
            if name.is_empty() {
                return Err(invalid(
                    path,
                    format!("package.json field {key:?} contains an empty dependency name"),
                ));
            }
            let range = range.as_str().filter(|range| !range.trim().is_empty()).ok_or_else(|| {
                invalid(
                    path,
                    format!(
                        "package.json dependency {name:?} in {key:?} must have a non-empty string constraint"
                    ),
                )
            })?;
            let mut package = Package::new(Ecosystem::Npm, name, range, path.to_path_buf());
            package.direct = true;
            package.dev = key == "devDependencies";
            package.enrichable = npm_manifest_constraint_is_registry(range);
            package.set_manifest_constraint(range);
            out.push(package);
        }
    }
    Ok(dedup(out))
}

fn workspace_patterns(path: &Path, value: &Json) -> Result<Vec<String>, ParseError> {
    let Some(workspaces) = value.get("workspaces") else {
        return Ok(Vec::new());
    };
    let entries = match workspaces {
        Json::Array(entries) => entries,
        Json::Object(object) => {
            object
                .get("packages")
                .and_then(Json::as_array)
                .ok_or_else(|| {
                    invalid(
                        path,
                        "package.json workspaces object must contain a packages array",
                    )
                })?
        }
        _ => {
            return Err(invalid(
                path,
                "package.json workspaces must be an array or an object containing a packages array",
            ));
        }
    };
    if entries.len() > 256 {
        return Err(invalid(
            path,
            "package.json workspaces exceeds the 256-pattern limit",
        ));
    }
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let pattern = entry.as_str().filter(|entry| !entry.is_empty()).ok_or_else(|| {
                invalid(
                    path,
                    format!(
                        "package.json workspace entry {index} must be a non-empty string"
                    ),
                )
            })?;
            let relative = Path::new(pattern);
            if pattern.starts_with('!')
                || relative.is_absolute()
                || relative.components().any(|component| {
                    matches!(
                        component,
                        Component::ParentDir | Component::RootDir | Component::Prefix(_)
                    )
                })
            {
                return Err(invalid(
                    path,
                    format!(
                        "package.json workspace pattern {pattern:?} must be a contained relative path pattern"
                    ),
                ));
            }
            Ok(pattern.to_owned())
        })
        .collect()
}

fn workspace_manifests(
    root_manifest: &Path,
    root_value: &Json,
) -> Result<Vec<PathBuf>, ParseError> {
    let root = nonempty_parent(root_manifest);
    let canonical_root = fs::canonicalize(root).map_err(|error| io_error(root, error))?;
    let canonical_manifest =
        fs::canonicalize(root_manifest).map_err(|error| io_error(root_manifest, error))?;
    if !canonical_manifest.starts_with(&canonical_root) || !canonical_manifest.is_file() {
        return Err(invalid(
            root_manifest,
            "root package.json must resolve to a regular file inside the project root",
        ));
    }
    let mut manifests = BTreeSet::from([root_manifest.to_path_buf()]);
    for workspace_pattern in workspace_patterns(root_manifest, root_value)? {
        let relative_pattern = Path::new(&workspace_pattern).join("package.json");
        let relative_pattern = relative_pattern.to_str().ok_or_else(|| {
            invalid(
                root_manifest,
                format!("workspace pattern {workspace_pattern:?} is not valid UTF-8"),
            )
        })?;
        let root_pattern = root
            .to_str()
            .ok_or_else(|| invalid(root_manifest, "package.json root path is not valid UTF-8"))?;
        let joined = format!(
            "{}{}{}",
            glob::Pattern::escape(root_pattern),
            std::path::MAIN_SEPARATOR,
            relative_pattern
        );
        let mut matched = false;
        for candidate in glob::glob(&joined).map_err(|error| {
            invalid(
                root_manifest,
                format!("invalid workspace pattern {workspace_pattern:?}: {error}"),
            )
        })? {
            let candidate = candidate.map_err(|error| {
                invalid(
                    root_manifest,
                    format!("reading workspace pattern {workspace_pattern:?}: {error}"),
                )
            })?;
            let canonical_candidate =
                fs::canonicalize(&candidate).map_err(|error| io_error(&candidate, error))?;
            if !canonical_candidate.starts_with(&canonical_root) {
                return Err(invalid(
                    root_manifest,
                    format!(
                        "workspace manifest {} resolves outside the project root",
                        candidate.display()
                    ),
                ));
            }
            if !canonical_candidate.is_file() {
                return Err(invalid(
                    root_manifest,
                    format!(
                        "workspace pattern {workspace_pattern:?} matched a non-file entry {}",
                        candidate.display()
                    ),
                ));
            }
            matched = true;
            manifests.insert(candidate);
            if manifests.len() > 10_000 {
                return Err(invalid(
                    root_manifest,
                    "package.json workspaces exceeds the 10000-manifest limit",
                ));
            }
        }
        if !matched {
            return Err(invalid(
                root_manifest,
                format!(
                    "package.json workspace pattern {workspace_pattern:?} matched no package.json files"
                ),
            ));
        }
    }
    Ok(manifests.into_iter().collect())
}

fn parse_package_json_project(root_manifest: &Path) -> Result<Vec<Package>, ParseError> {
    let root_value = read_package_json(root_manifest)?;
    let manifests = workspace_manifests(root_manifest, &root_value)?;
    let mut packages = Vec::new();
    for manifest in manifests {
        let value = if manifest == root_manifest {
            root_value.clone()
        } else {
            read_package_json(&manifest)?
        };
        packages.extend(parse_package_json_value(&manifest, &value)?);
    }
    Ok(dedup(packages))
}

pub struct PythonParser;
impl EcosystemParser for PythonParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::PyPI
    }
    fn detect(&self, root: &Path) -> Vec<DetectedSource> {
        for (file, kind) in [
            ("uv.lock", SourceKind::UvLock),
            ("poetry.lock", SourceKind::PoetryLock),
            ("Pipfile.lock", SourceKind::PipfileLock),
            ("requirements.txt", SourceKind::RequirementsTxt),
            ("pyproject.toml", SourceKind::PyProject),
        ] {
            if let Some(s) = source(root, file, kind) {
                return vec![s];
            }
        }
        Vec::new()
    }
    fn parse(&self, source: &DetectedSource) -> Result<Vec<Package>, ParseError> {
        match source.kind {
            SourceKind::UvLock => python_locks::parse_uv_lock(&source.path),
            SourceKind::PoetryLock => python_locks::parse_poetry_lock(&source.path),
            SourceKind::PipfileLock => parse_pipfile_lock(&source.path),
            SourceKind::RequirementsTxt => requirements::parse(&source.path),
            SourceKind::PyProject => parse_pyproject(&source.path),
            _ => Err(invalid(&source.path, "unexpected source kind")),
        }
    }
}
fn parse_pipfile_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let value: Json = serde_json::from_str(&text).map_err(|e| invalid(path, e))?;
    let document = value.as_object().ok_or_else(|| {
        invalid(
            path,
            "detected a non-object JSON document; expected a Pipfile.lock object",
        )
    })?;
    let metadata = document
        .get("_meta")
        .and_then(Json::as_object)
        .ok_or_else(|| {
            invalid(
                path,
                "detected JSON without a _meta object; expected Pipfile.lock metadata",
            )
        })?;
    let pipfile_spec = metadata
        .get("pipfile-spec")
        .and_then(Json::as_u64)
        .ok_or_else(|| {
            invalid(
                path,
                "detected Pipfile.lock metadata without an integer pipfile-spec; expected spec 6",
            )
        })?;
    if pipfile_spec != 6 {
        return Err(invalid(
            path,
            format!(
                "detected unsupported Pipfile.lock pipfile-spec {pipfile_spec}; expected spec 6"
            ),
        ));
    }
    let directness = pipfile_direct_dependencies(path);
    let mut out = Vec::new();
    for section in ["default", "develop"] {
        let dependencies = document
            .get(section)
            .and_then(Json::as_object)
            .ok_or_else(|| {
                invalid(
                    path,
                    format!(
                        "detected Pipfile.lock spec 6 without a {section} object; expected both default and develop dependency maps"
                    ),
                )
            })?;
        for (name, item) in dependencies {
            let item = item.as_object().ok_or_else(|| {
                invalid(
                    path,
                    format!("Pipfile.lock {section} package {name:?} must be an object"),
                )
            })?;
            let Some(version) = item.get("version") else {
                if ["git", "path", "file"]
                    .iter()
                    .any(|source| item.contains_key(*source))
                {
                    // Pipenv can lock non-index sources without a PyPI version.
                    continue;
                }
                return Err(invalid(
                    path,
                    format!(
                        "Pipfile.lock {section} package {name:?} is missing a resolved version or supported non-index source"
                    ),
                ));
            };
            let version = version
                .as_str()
                .filter(|version| !version.trim_start_matches("==").is_empty())
                .ok_or_else(|| {
                    invalid(
                        path,
                        format!(
                            "Pipfile.lock {section} package {name:?} version must be a non-empty string"
                        ),
                    )
                })?;
            let mut package = Package::new(
                Ecosystem::PyPI,
                name,
                version.trim_start_matches("=="),
                path.to_path_buf(),
            );
            match directness.for_lock_section(section) {
                Some(direct) => {
                    package.direct = direct.contains(&package.name);
                    package.direct_known = true;
                }
                None => {
                    package.direct = false;
                    package.direct_known = false;
                }
            }
            package.dev = section == "develop";
            out.push(package);
        }
    }
    Ok(dedup(out))
}

#[derive(Debug, Default)]
struct PipfileDirectDependencies {
    default: Option<HashSet<String>>,
    develop: Option<HashSet<String>>,
}

impl PipfileDirectDependencies {
    fn for_lock_section(&self, section: &str) -> Option<&HashSet<String>> {
        match section {
            "default" => self.default.as_ref(),
            "develop" => self.develop.as_ref(),
            _ => None,
        }
    }
}

fn pipfile_direct_dependencies(lock_path: &Path) -> PipfileDirectDependencies {
    let Some(path) = lock_path.parent().map(|parent| parent.join("Pipfile")) else {
        return PipfileDirectDependencies::default();
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return PipfileDirectDependencies::default();
    };
    let Ok(value) = toml::from_str::<Toml>(&text) else {
        return PipfileDirectDependencies::default();
    };

    let default = pipfile_section_names(&value, "packages");
    let develop = pipfile_section_names(&value, "dev-packages");
    if default.is_none() || develop.is_none() {
        return PipfileDirectDependencies::default();
    }
    PipfileDirectDependencies { default, develop }
}

fn pipfile_section_names(value: &Toml, section: &str) -> Option<HashSet<String>> {
    let root = value.as_table()?;
    let Some(section_value) = root.get(section) else {
        return Some(HashSet::new());
    };
    let dependencies = section_value.as_table()?;
    dependencies
        .iter()
        .map(|(name, declaration)| {
            if !matches!(declaration, Toml::String(_) | Toml::Table(_)) {
                return None;
            }
            let base_name = name.split_once('[').map_or(name.as_str(), |(base, _)| base);
            let normalized = normalize_name(Ecosystem::PyPI, base_name.trim());
            (!normalized.is_empty()).then_some(normalized)
        })
        .collect()
}
fn parse_pyproject(path: &Path) -> Result<Vec<Package>, ParseError> {
    python_manifest::parse_pyproject(path)
}

pub struct NugetParser;
impl EcosystemParser for NugetParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::NuGet
    }
    fn detect(&self, root: &Path) -> Vec<DetectedSource> {
        let files = sorted_dotnet_files(root);
        let locks: HashSet<_> = files
            .iter()
            .filter(|path| is_nuget_lock_file(path))
            .cloned()
            .collect();
        let mut sources: Vec<_> = locks
            .iter()
            .cloned()
            .map(|path| DetectedSource {
                path,
                kind: SourceKind::PackagesLock,
            })
            .collect();

        for path in files.iter().filter(|path| is_dotnet_project(path)) {
            if project_lock_file(path).is_none_or(|lock| !locks.contains(&lock)) {
                sources.push(DetectedSource {
                    path: path.clone(),
                    kind: SourceKind::ProjectFile,
                });
            }
        }

        for path in files.iter().filter(|path| is_packages_config(path)) {
            let covered_by_lock = path
                .parent()
                .is_some_and(|directory| directory.join("packages.lock.json").is_file());
            if !covered_by_lock {
                sources.push(DetectedSource {
                    path: path.clone(),
                    kind: SourceKind::PackagesConfig,
                });
            }
        }

        sources.sort_by(|left, right| left.path.cmp(&right.path));
        sources
    }
    fn parse(&self, source: &DetectedSource) -> Result<Vec<Package>, ParseError> {
        match source.kind {
            SourceKind::PackagesLock => parse_packages_lock(&source.path),
            SourceKind::ProjectFile => parse_nuget_project(&source.path),
            SourceKind::DirectoryPackagesProps => parse_directory_packages_props(&source.path),
            SourceKind::PackagesConfig => parse_packages_config(&source.path),
            _ => Err(invalid(&source.path, "unexpected source kind")),
        }
    }
}

fn sorted_dotnet_files(root: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| {
            !matches!(
                entry.file_name().to_str(),
                Some(".git" | ".vs" | "bin" | "node_modules" | "obj" | "target" | ".venv")
            )
        })
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_file()
                && (is_dotnet_project(entry.path())
                    || is_nuget_lock_file(entry.path())
                    || is_packages_config(entry.path()))
        })
        .map(|entry| entry.into_path())
        .collect();
    paths.sort();
    paths
}

fn is_dotnet_project(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            ["csproj", "fsproj", "vbproj"]
                .iter()
                .any(|expected| extension.eq_ignore_ascii_case(expected))
        })
}

fn is_nuget_lock_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    file_name == "packages.lock.json"
        || (file_name.starts_with("packages.") && file_name.ends_with(".lock.json"))
}

fn is_packages_config(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some("packages.config")
}

fn project_lock_file(project: &Path) -> Option<PathBuf> {
    let directory = project.parent()?;
    if let Some(stem) = project.file_stem().and_then(|stem| stem.to_str()) {
        let project_specific = directory.join(format!("packages.{stem}.lock.json"));
        if project_specific.is_file() {
            return Some(project_specific);
        }
    }
    let default = directory.join("packages.lock.json");
    default.is_file().then_some(default)
}

fn parse_packages_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let value: Json = serde_json::from_str(&text).map_err(|e| invalid(path, e))?;
    let document = value.as_object().ok_or_else(|| {
        invalid(
            path,
            "detected a non-object JSON document; expected a NuGet packages.lock.json object",
        )
    })?;
    let version = document
        .get("version")
        .and_then(Json::as_u64)
        .ok_or_else(|| {
            invalid(
                path,
                "detected JSON without an integer version; expected NuGet packages.lock.json version 1, 2, or 3",
            )
        })?;
    if !(1..=3).contains(&version) {
        return Err(invalid(
            path,
            format!(
                "detected unsupported NuGet lockfile version {version}; expected version 1, 2, or 3"
            ),
        ));
    }
    let frameworks = document
        .get("dependencies")
        .and_then(Json::as_object)
        .ok_or_else(|| {
            invalid(
                path,
                format!(
                    "detected NuGet lockfile version {version} without a dependencies object; expected target-framework dependency maps"
                ),
            )
        })?;
    let mut out = Vec::new();
    for (framework_name, framework) in frameworks {
        let items = framework.as_object().ok_or_else(|| {
            invalid(
                path,
                format!("NuGet framework {framework_name:?} must be an object"),
            )
        })?;
        for (name, item) in items {
            let item = item.as_object().ok_or_else(|| {
                invalid(
                    path,
                    format!("NuGet package {name:?} in {framework_name:?} must be an object"),
                )
            })?;
            let dependency_type = item.get("type").and_then(Json::as_str).ok_or_else(|| {
                invalid(
                    path,
                    format!("NuGet package {name:?} in {framework_name:?} is missing type"),
                )
            })?;
            if dependency_type.eq_ignore_ascii_case("Project") {
                continue;
            }
            let direct = if dependency_type.eq_ignore_ascii_case("Direct")
                || dependency_type.eq_ignore_ascii_case("CentralTransitive")
            {
                true
            } else if dependency_type.eq_ignore_ascii_case("Transitive") {
                false
            } else {
                return Err(invalid(
                    path,
                    format!(
                        "NuGet package {name:?} in {framework_name:?} has unsupported type {dependency_type:?}"
                    ),
                ));
            };
            let resolved = item.get("resolved").and_then(Json::as_str).ok_or_else(|| {
                invalid(
                    path,
                    format!(
                        "NuGet package {name:?} in {framework_name:?} is missing resolved version"
                    ),
                )
            })?;
            if resolved.trim().is_empty() {
                return Err(invalid(
                    path,
                    format!(
                        "NuGet package {name:?} in {framework_name:?} has an empty resolved version"
                    ),
                ));
            }
            let mut package = Package::new(Ecosystem::NuGet, name, resolved, path.to_path_buf());
            package.direct = direct;
            out.push(package);
        }
    }
    Ok(dedup(out))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NugetXmlItemKind {
    PackageReference,
    PackageVersion,
    GlobalPackageReference,
    LegacyPackage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NugetXmlIdentityKind {
    Include,
    Update,
    Id,
}

#[derive(Debug)]
struct NugetXmlItem {
    kind: NugetXmlItemKind,
    identity_kind: Option<NugetXmlIdentityKind>,
    name: Option<String>,
    version: Option<String>,
    version_override: Option<String>,
    development_dependency: bool,
    removed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NugetMetadataKind {
    Version,
    VersionOverride,
    DevelopmentDependency,
}

#[derive(Debug)]
struct CapturedMetadata {
    kind: NugetMetadataKind,
    depth: usize,
    value: String,
}

#[derive(Debug)]
struct OpenNugetXmlItem {
    depth: usize,
    item: NugetXmlItem,
    captured: Option<CapturedMetadata>,
}

#[derive(Debug)]
struct NugetXmlDocument {
    root: String,
    items: Vec<NugetXmlItem>,
}

#[derive(Debug, Clone)]
struct CentralPackageVersion {
    display_name: String,
    version: String,
}

fn xml_local_name(bytes: &[u8]) -> Result<&str, String> {
    let name = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    Ok(name.rsplit(':').next().unwrap_or(name))
}

fn nuget_item_kind(name: &str) -> Option<NugetXmlItemKind> {
    if name.eq_ignore_ascii_case("PackageReference") {
        Some(NugetXmlItemKind::PackageReference)
    } else if name.eq_ignore_ascii_case("PackageVersion") {
        Some(NugetXmlItemKind::PackageVersion)
    } else if name.eq_ignore_ascii_case("GlobalPackageReference") {
        Some(NugetXmlItemKind::GlobalPackageReference)
    } else if name.eq_ignore_ascii_case("package") {
        Some(NugetXmlItemKind::LegacyPackage)
    } else {
        None
    }
}

fn nuget_metadata_kind(name: &str) -> Option<NugetMetadataKind> {
    if name.eq_ignore_ascii_case("Version") {
        Some(NugetMetadataKind::Version)
    } else if name.eq_ignore_ascii_case("VersionOverride") {
        Some(NugetMetadataKind::VersionOverride)
    } else if name.eq_ignore_ascii_case("DevelopmentDependency") {
        Some(NugetMetadataKind::DevelopmentDependency)
    } else {
        None
    }
}

fn parse_nuget_xml_attributes(
    path: &Path,
    reader: &Reader<&[u8]>,
    element: &BytesStart<'_>,
) -> Result<HashMap<String, String>, ParseError> {
    let mut attributes = HashMap::new();
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|error| invalid(path, error))?;
        let key = xml_local_name(attribute.key.as_ref()).map_err(|error| invalid(path, error))?;
        let key = key.to_ascii_lowercase();
        let value = attribute
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
            .map_err(|error| invalid(path, error))?
            .into_owned();
        if attributes.insert(key.clone(), value).is_some() {
            return Err(invalid(path, format!("duplicated XML attribute {key:?}")));
        }
    }
    Ok(attributes)
}

fn new_nuget_xml_item(
    path: &Path,
    reader: &Reader<&[u8]>,
    element: &BytesStart<'_>,
    kind: NugetXmlItemKind,
) -> Result<NugetXmlItem, ParseError> {
    let mut attributes = parse_nuget_xml_attributes(path, reader, element)?;
    let identities: Vec<_> = ["include", "update", "id"]
        .into_iter()
        .filter_map(|key| attributes.remove(key).map(|value| (key, value)))
        .collect();
    if identities.len() > 1 {
        return Err(invalid(
            path,
            "NuGet package item has more than one of Include, Update, and id",
        ));
    }
    let identity = identities.into_iter().next();
    let identity_kind = identity.as_ref().map(|(key, _)| match *key {
        "include" => NugetXmlIdentityKind::Include,
        "update" => NugetXmlIdentityKind::Update,
        "id" => NugetXmlIdentityKind::Id,
        _ => unreachable!("identity keys are statically constrained"),
    });
    let name = identity.map(|(_, value)| value);
    let removed = attributes.contains_key("remove");
    let development_dependency = attributes
        .remove("developmentdependency")
        .map(|value| parse_xml_bool(path, "developmentDependency", &value))
        .transpose()?
        .unwrap_or(false);
    Ok(NugetXmlItem {
        kind,
        identity_kind,
        name,
        version: attributes.remove("version"),
        version_override: attributes.remove("versionoverride"),
        development_dependency,
        removed,
    })
}

fn parse_xml_bool(path: &Path, field: &str, value: &str) -> Result<bool, ParseError> {
    if value.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(invalid(
            path,
            format!("NuGet {field} must be true or false, got {value:?}"),
        ))
    }
}

fn append_xml_text(
    path: &Path,
    open: &mut Option<OpenNugetXmlItem>,
    text: &str,
) -> Result<(), ParseError> {
    if let Some(captured) = open.as_mut().and_then(|open| open.captured.as_mut()) {
        let text = unescape(text).map_err(|error| invalid(path, error))?;
        captured.value.push_str(&text);
    }
    Ok(())
}

fn set_nuget_metadata(
    path: &Path,
    item: &mut NugetXmlItem,
    kind: NugetMetadataKind,
    value: String,
) -> Result<(), ParseError> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(invalid(path, "NuGet package metadata cannot be empty"));
    }
    match kind {
        NugetMetadataKind::Version => {
            if item.version.replace(value).is_some() {
                return Err(invalid(
                    path,
                    "NuGet package item defines Version more than once",
                ));
            }
        }
        NugetMetadataKind::VersionOverride => {
            if item.version_override.replace(value).is_some() {
                return Err(invalid(
                    path,
                    "NuGet package item defines VersionOverride more than once",
                ));
            }
        }
        NugetMetadataKind::DevelopmentDependency => {
            item.development_dependency = parse_xml_bool(path, "DevelopmentDependency", &value)?;
        }
    }
    Ok(())
}

fn finish_nuget_xml_item(
    path: &Path,
    mut item: NugetXmlItem,
) -> Result<Option<NugetXmlItem>, ParseError> {
    if item.removed {
        if item.name.is_some() {
            return Err(invalid(
                path,
                "NuGet package item cannot combine Remove with Include, Update, or id",
            ));
        }
        return Ok(None);
    }
    item.name = item.name.map(|name| name.trim().to_owned());
    item.version = item.version.map(|version| version.trim().to_owned());
    item.version_override = item
        .version_override
        .map(|version| version.trim().to_owned());
    if item
        .name
        .as_deref()
        .is_none_or(|name| name.trim().is_empty())
    {
        return Err(invalid(
            path,
            "NuGet package item is missing its package name",
        ));
    }
    if item.version.as_deref().is_some_and(str::is_empty)
        || item.version_override.as_deref().is_some_and(str::is_empty)
    {
        return Err(invalid(path, "NuGet package version cannot be empty"));
    }
    if item.kind != NugetXmlItemKind::PackageReference
        && item
            .version_override
            .as_ref()
            .or(item.version.as_ref())
            .is_none_or(|version| version.trim().is_empty())
    {
        return Err(invalid(
            path,
            "NuGet package item is missing its package version",
        ));
    }
    Ok(Some(item))
}

fn parse_nuget_xml_document(path: &Path) -> Result<NugetXmlDocument, ParseError> {
    let content = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
    let mut reader = Reader::from_str(&content);
    reader.config_mut().trim_text(true);
    let mut root = None;
    let mut items = Vec::new();
    let mut open: Option<OpenNugetXmlItem> = None;
    let mut depth = 0_usize;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(element)) => {
                let qualified_name = element.name();
                let name = xml_local_name(qualified_name.as_ref())
                    .map_err(|error| invalid(path, error))?;
                if depth == 0 {
                    root = Some(name.to_owned());
                }
                if open
                    .as_ref()
                    .is_some_and(|open_item| open_item.captured.is_some())
                {
                    return Err(invalid(
                        path,
                        "NuGet package metadata cannot contain nested XML elements",
                    ));
                }
                if let Some(kind) = nuget_item_kind(name) {
                    if open.is_some() {
                        return Err(invalid(path, "NuGet package items cannot be nested"));
                    }
                    open = Some(OpenNugetXmlItem {
                        depth,
                        item: new_nuget_xml_item(path, &reader, &element, kind)?,
                        captured: None,
                    });
                } else if let Some(kind) = nuget_metadata_kind(name)
                    && let Some(open_item) = open.as_mut()
                    && depth == open_item.depth + 1
                {
                    if open_item.captured.is_some() {
                        return Err(invalid(path, "NuGet package metadata cannot be nested"));
                    }
                    open_item.captured = Some(CapturedMetadata {
                        kind,
                        depth,
                        value: String::new(),
                    });
                    parse_nuget_xml_attributes(path, &reader, &element)?;
                } else {
                    parse_nuget_xml_attributes(path, &reader, &element)?;
                }
                depth += 1;
            }
            Ok(Event::Empty(element)) => {
                let qualified_name = element.name();
                let name = xml_local_name(qualified_name.as_ref())
                    .map_err(|error| invalid(path, error))?;
                if depth == 0 {
                    root = Some(name.to_owned());
                }
                if open
                    .as_ref()
                    .is_some_and(|open_item| open_item.captured.is_some())
                {
                    return Err(invalid(
                        path,
                        "NuGet package metadata cannot contain nested XML elements",
                    ));
                }
                if let Some(kind) = nuget_item_kind(name) {
                    if open.is_some() {
                        return Err(invalid(path, "NuGet package items cannot be nested"));
                    }
                    let item = new_nuget_xml_item(path, &reader, &element, kind)?;
                    if let Some(item) = finish_nuget_xml_item(path, item)? {
                        items.push(item);
                    }
                } else if nuget_metadata_kind(name).is_some()
                    && open
                        .as_ref()
                        .is_some_and(|open_item| depth == open_item.depth + 1)
                {
                    return Err(invalid(path, "NuGet package metadata cannot be empty"));
                } else {
                    parse_nuget_xml_attributes(path, &reader, &element)?;
                }
            }
            Ok(Event::Text(text)) => {
                let text = text.xml10_content().map_err(|error| invalid(path, error))?;
                append_xml_text(path, &mut open, &text)?;
            }
            Ok(Event::CData(text)) => {
                let text = text.xml10_content().map_err(|error| invalid(path, error))?;
                if let Some(captured) = open.as_mut().and_then(|open| open.captured.as_mut()) {
                    captured.value.push_str(&text);
                }
            }
            Ok(Event::End(element)) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| invalid(path, "unexpected closing XML element"))?;
                let qualified_name = element.name();
                let name = xml_local_name(qualified_name.as_ref())
                    .map_err(|error| invalid(path, error))?;
                if let Some(open_item) = open.as_mut()
                    && let Some(captured) = open_item.captured.as_ref()
                    && depth == captured.depth
                {
                    if nuget_metadata_kind(name) != Some(captured.kind) {
                        return Err(invalid(path, "mismatched NuGet package metadata"));
                    }
                    let captured = open_item.captured.take().expect("capture checked above");
                    set_nuget_metadata(path, &mut open_item.item, captured.kind, captured.value)?;
                }
                if open
                    .as_ref()
                    .is_some_and(|open_item| depth == open_item.depth)
                {
                    let open_item = open.take().expect("open item checked above");
                    if nuget_item_kind(name) != Some(open_item.item.kind) {
                        return Err(invalid(path, "mismatched NuGet package item"));
                    }
                    if let Some(item) = finish_nuget_xml_item(path, open_item.item)? {
                        items.push(item);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(invalid(path, error)),
            _ => {}
        }
        buf.clear();
    }

    let root = root.ok_or_else(|| invalid(path, "NuGet XML document has no root element"))?;
    Ok(NugetXmlDocument { root, items })
}

fn require_xml_root(path: &Path, actual: &str, expected: &str) -> Result<(), ParseError> {
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(invalid(
            path,
            format!("expected NuGet XML root {expected:?}, found {actual:?}"),
        ))
    }
}

fn nearest_directory_packages_props(project: &Path) -> Option<PathBuf> {
    project.parent()?.ancestors().find_map(|directory| {
        let candidate = directory.join("Directory.Packages.props");
        candidate.is_file().then_some(candidate)
    })
}

fn central_package_versions(
    path: &Path,
) -> Result<BTreeMap<String, CentralPackageVersion>, ParseError> {
    let document = parse_nuget_xml_document(path)?;
    require_xml_root(path, &document.root, "Project")?;
    let mut versions = BTreeMap::new();
    for item in document
        .items
        .into_iter()
        .filter(|item| item.kind == NugetXmlItemKind::PackageVersion)
    {
        let display_name = item.name.expect("validated package name");
        let version = item
            .version_override
            .or(item.version)
            .expect("validated package version");
        versions.insert(
            display_name.to_ascii_lowercase(),
            CentralPackageVersion {
                display_name,
                version,
            },
        );
    }
    Ok(versions)
}

fn package_from_manifest(name: String, version: String, source: &Path, dev: bool) -> Package {
    let mut package = Package::new(
        Ecosystem::NuGet,
        name,
        version.clone(),
        source.to_path_buf(),
    );
    package.direct = true;
    package.dev = dev;
    package.set_manifest_constraint(version);
    package
}

fn parse_nuget_project(path: &Path) -> Result<Vec<Package>, ParseError> {
    if let Some(lock) = project_lock_file(path) {
        return parse_packages_lock(&lock);
    }
    let document = parse_nuget_xml_document(path)?;
    require_xml_root(path, &document.root, "Project")?;
    let central_path = nearest_directory_packages_props(path);
    let central = central_path
        .as_deref()
        .map(central_package_versions)
        .transpose()?
        .unwrap_or_default();
    let mut references: Vec<NugetXmlItem> = Vec::new();
    for reference in document
        .items
        .into_iter()
        .filter(|item| item.kind == NugetXmlItemKind::PackageReference)
    {
        if reference.identity_kind == Some(NugetXmlIdentityKind::Update) {
            let normalized_name = reference
                .name
                .as_deref()
                .expect("validated package name")
                .to_ascii_lowercase();
            let mut updated = false;
            for existing in references.iter_mut().filter(|existing| {
                existing
                    .name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&normalized_name))
            }) {
                if reference.version.is_some() {
                    existing.version.clone_from(&reference.version);
                }
                if reference.version_override.is_some() {
                    existing
                        .version_override
                        .clone_from(&reference.version_override);
                }
                existing.development_dependency |= reference.development_dependency;
                updated = true;
            }
            if updated {
                continue;
            }
        }
        references.push(reference);
    }

    let mut packages = Vec::new();
    for reference in references {
        let display_name = reference.name.expect("validated package name");
        let central_version = central.get(&display_name.to_ascii_lowercase());
        let version = reference
            .version_override
            .or(reference.version)
            .or_else(|| central_version.map(|central| central.version.clone()))
            .ok_or_else(|| {
                let props = central_path
                    .as_ref()
                    .map_or_else(|| "no Directory.Packages.props was found".to_owned(), |path| {
                        format!("{} has no matching PackageVersion", path.display())
                    });
                invalid(
                    path,
                    format!(
                        "PackageReference {display_name:?} has no inline, override, or central version ({props})"
                    ),
                )
            })?;
        let name = central_version.map_or(display_name, |central| central.display_name.clone());
        packages.push(package_from_manifest(
            name,
            version,
            path,
            reference.development_dependency,
        ));
    }
    Ok(dedup(packages))
}

fn parse_directory_packages_props(path: &Path) -> Result<Vec<Package>, ParseError> {
    Ok(central_package_versions(path)?
        .into_values()
        .map(|central| package_from_manifest(central.display_name, central.version, path, false))
        .collect())
}

fn parse_packages_config(path: &Path) -> Result<Vec<Package>, ParseError> {
    let document = parse_nuget_xml_document(path)?;
    require_xml_root(path, &document.root, "packages")?;
    let packages = document
        .items
        .into_iter()
        .filter(|item| item.kind == NugetXmlItemKind::LegacyPackage)
        .map(|item| {
            let mut package = Package::new(
                Ecosystem::NuGet,
                item.name.expect("validated package name"),
                item.version.expect("validated package version"),
                path.to_path_buf(),
            );
            package.direct = true;
            package.dev = item.development_dependency;
            package
        })
        .collect();
    Ok(dedup(packages))
}

pub struct CargoParser;
impl EcosystemParser for CargoParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::CratesIo
    }
    fn detect(&self, root: &Path) -> Vec<DetectedSource> {
        source(root, "Cargo.lock", SourceKind::CargoLock)
            .or_else(|| source(root, "Cargo.toml", SourceKind::CargoToml))
            .into_iter()
            .collect()
    }
    fn parse(&self, source: &DetectedSource) -> Result<Vec<Package>, ParseError> {
        match source.kind {
            SourceKind::CargoLock => parse_cargo_lock(&source.path),
            SourceKind::CargoToml => parse_cargo_toml(&source.path),
            _ => Err(invalid(&source.path, "unexpected source kind")),
        }
    }
}
#[derive(Clone, Debug)]
struct CargoDependencySpec {
    package_name: String,
    version: Option<String>,
    enrichable: bool,
    local_path: Option<PathBuf>,
}

#[derive(Debug)]
struct CargoDeclaration {
    dependency: CargoDependencySpec,
    declaring_manifest: PathBuf,
    dev: bool,
}

#[derive(Debug)]
struct CargoManifest {
    path: PathBuf,
    value: Toml,
}

fn read_cargo_manifest(path: &Path) -> Result<Toml, ParseError> {
    let text = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
    toml::from_str(&text).map_err(|error| invalid(path, error))
}

fn dependency_field<'a>(
    manifest: &Path,
    alias: &str,
    table: &'a toml::Table,
    field: &str,
) -> Result<Option<&'a str>, ParseError> {
    table
        .get(field)
        .map(|value| {
            value.as_str().ok_or_else(|| {
                invalid(
                    manifest,
                    format!("Cargo dependency {alias:?} field {field:?} must be a string"),
                )
            })
        })
        .transpose()
}

fn parse_cargo_dependency(
    manifest: &Path,
    alias: &str,
    entry: &Toml,
    workspace_dependencies: Option<&BTreeMap<String, CargoDependencySpec>>,
) -> Result<CargoDependencySpec, ParseError> {
    if alias.is_empty() {
        return Err(invalid(manifest, "Cargo dependency name cannot be empty"));
    }
    if let Some(version) = entry.as_str() {
        return Ok(CargoDependencySpec {
            package_name: alias.to_owned(),
            version: Some(version.to_owned()),
            enrichable: true,
            local_path: None,
        });
    }

    let table = entry.as_table().ok_or_else(|| {
        invalid(
            manifest,
            format!("Cargo dependency {alias:?} must be a string or table"),
        )
    })?;
    let package = dependency_field(manifest, alias, table, "package")?;
    if package.is_some_and(str::is_empty) {
        return Err(invalid(
            manifest,
            format!("Cargo dependency {alias:?} field \"package\" cannot be empty"),
        ));
    }

    if let Some(workspace) = table.get("workspace") {
        if workspace.as_bool() != Some(true) {
            return Err(invalid(
                manifest,
                format!("Cargo dependency {alias:?} field \"workspace\" must be true"),
            ));
        }
        for forbidden in [
            "version",
            "path",
            "git",
            "branch",
            "tag",
            "rev",
            "registry",
            "registry-index",
            "package",
            "default-features",
        ] {
            if table.contains_key(forbidden) {
                return Err(invalid(
                    manifest,
                    format!(
                        "inherited Cargo dependency {alias:?} cannot override field {forbidden:?}"
                    ),
                ));
            }
        }
        return workspace_dependencies
            .and_then(|dependencies| dependencies.get(alias))
            .cloned()
            .ok_or_else(|| {
                invalid(
                    manifest,
                    format!(
                        "Cargo dependency {alias:?} inherits from a missing [workspace.dependencies] entry"
                    ),
                )
            });
    }

    let version = dependency_field(manifest, alias, table, "version")?.map(str::to_owned);
    let path = dependency_field(manifest, alias, table, "path")?;
    let git = dependency_field(manifest, alias, table, "git")?;
    let registry = dependency_field(manifest, alias, table, "registry")?;
    let registry_index = dependency_field(manifest, alias, table, "registry-index")?;
    for selector in ["branch", "tag", "rev"] {
        let value = dependency_field(manifest, alias, table, selector)?;
        if value.is_some() && git.is_none() {
            return Err(invalid(
                manifest,
                format!("Cargo dependency {alias:?} field {selector:?} requires a \"git\" source"),
            ));
        }
    }
    let source_count = [
        path.is_some(),
        git.is_some(),
        registry.is_some() || registry_index.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if source_count > 1 || (registry.is_some() && registry_index.is_some()) {
        return Err(invalid(
            manifest,
            format!("Cargo dependency {alias:?} declares conflicting sources"),
        ));
    }
    if version.is_none() && path.is_none() && git.is_none() {
        return Err(invalid(
            manifest,
            format!("Cargo dependency {alias:?} has no version, path, or git source"),
        ));
    }
    let local_path = path.map(|dependency_path| {
        manifest
            .parent()
            .unwrap_or(Path::new("."))
            .join(dependency_path)
    });
    Ok(CargoDependencySpec {
        package_name: package.unwrap_or(alias).to_owned(),
        version,
        enrichable: path.is_none()
            && git.is_none()
            && registry.is_none()
            && registry_index.is_none(),
        local_path,
    })
}

fn cargo_dependency_tables(value: &Toml) -> Result<Vec<(&toml::Table, bool)>, String> {
    let mut tables = Vec::new();
    for (section, dev) in [
        ("dependencies", false),
        ("dev-dependencies", true),
        ("build-dependencies", false),
    ] {
        if let Some(entry) = value.get(section) {
            let table = entry
                .as_table()
                .ok_or_else(|| format!("Cargo section [{section}] must be a table"))?;
            tables.push((table, dev));
        }
    }
    if let Some(targets) = value.get("target") {
        let targets = targets
            .as_table()
            .ok_or_else(|| "Cargo section [target] must be a table".to_owned())?;
        for (target, target_value) in targets {
            let target_table = target_value.as_table().ok_or_else(|| {
                format!("Cargo target section [target.{target:?}] must be a table")
            })?;
            for (section, dev) in [
                ("dependencies", false),
                ("dev-dependencies", true),
                ("build-dependencies", false),
            ] {
                if let Some(entry) = target_table.get(section) {
                    let table = entry.as_table().ok_or_else(|| {
                        format!("Cargo section [target.{target:?}.{section}] must be a table")
                    })?;
                    tables.push((table, dev));
                }
            }
        }
    }
    Ok(tables)
}

fn cargo_manifest_declarations(
    manifest: &CargoManifest,
    workspace_dependencies: &BTreeMap<String, CargoDependencySpec>,
) -> Result<Vec<CargoDeclaration>, ParseError> {
    let tables = cargo_dependency_tables(&manifest.value)
        .map_err(|message| invalid(&manifest.path, message))?;
    let mut declarations = Vec::new();
    for (table, dev) in tables {
        for (alias, entry) in table {
            declarations.push(CargoDeclaration {
                dependency: parse_cargo_dependency(
                    &manifest.path,
                    alias,
                    entry,
                    Some(workspace_dependencies),
                )?,
                declaring_manifest: manifest.path.clone(),
                dev,
            });
        }
    }
    Ok(declarations)
}

fn workspace_dependency_definitions(
    workspace_manifest: &Path,
    value: &Toml,
) -> Result<BTreeMap<String, CargoDependencySpec>, ParseError> {
    let Some(dependencies) = value
        .get("workspace")
        .and_then(Toml::as_table)
        .and_then(|workspace| workspace.get("dependencies"))
    else {
        return Ok(BTreeMap::new());
    };
    let dependencies = dependencies.as_table().ok_or_else(|| {
        invalid(
            workspace_manifest,
            "Cargo section [workspace.dependencies] must be a table",
        )
    })?;
    dependencies
        .iter()
        .map(|(alias, entry)| {
            parse_cargo_dependency(workspace_manifest, alias, entry, None)
                .map(|dependency| (alias.clone(), dependency))
        })
        .collect()
}

fn workspace_path_list(
    workspace_manifest: &Path,
    workspace: &toml::Table,
    field: &str,
) -> Result<Vec<String>, ParseError> {
    let Some(value) = workspace.get(field) else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or_else(|| {
        invalid(
            workspace_manifest,
            format!("Cargo workspace field {field:?} must be an array"),
        )
    })?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    invalid(
                        workspace_manifest,
                        format!(
                            "Cargo workspace field {field:?} entries must be non-empty strings"
                        ),
                    )
                })
        })
        .collect()
}

fn workspace_member_manifest(path: PathBuf) -> Option<PathBuf> {
    if path.is_dir() {
        Some(path.join("Cargo.toml"))
    } else if path.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml") {
        Some(path)
    } else {
        None
    }
}

fn workspace_member_matches(
    workspace_manifest: &Path,
    workspace_root: &Path,
    member: &str,
) -> Result<Vec<PathBuf>, ParseError> {
    let joined = workspace_root.join(member);
    let pattern = joined.to_str().ok_or_else(|| {
        invalid(
            workspace_manifest,
            format!("Cargo workspace member pattern {member:?} is not valid UTF-8"),
        )
    })?;
    let mut matches = Vec::new();
    for matched in glob::glob(pattern).map_err(|error| {
        invalid(
            workspace_manifest,
            format!("invalid Cargo workspace member pattern {member:?}: {error}"),
        )
    })? {
        let matched = matched.map_err(|error| {
            invalid(
                workspace_manifest,
                format!("reading Cargo workspace member pattern {member:?}: {error}"),
            )
        })?;
        if let Some(manifest) = workspace_member_manifest(matched) {
            let manifest = fs::canonicalize(&manifest).map_err(|error| {
                invalid(
                    workspace_manifest,
                    format!(
                        "Cargo workspace member {} has no readable Cargo.toml: {error}",
                        manifest.display()
                    ),
                )
            })?;
            matches.push(manifest);
        }
    }
    matches.sort();
    matches.dedup();
    if matches.is_empty() {
        return Err(invalid(
            workspace_manifest,
            format!("Cargo workspace member pattern {member:?} matched no packages"),
        ));
    }
    Ok(matches)
}

fn relative_workspace_path(workspace_root: &Path, path: &Path) -> Option<PathBuf> {
    let canonical_root = fs::canonicalize(workspace_root).ok()?;
    let canonical_path = fs::canonicalize(path).ok()?;
    canonical_path
        .strip_prefix(canonical_root)
        .ok()
        .map(Path::to_path_buf)
}

fn excluded_workspace_member(
    workspace_root: &Path,
    manifest: &Path,
    excludes: &[glob::Pattern],
) -> bool {
    manifest
        .parent()
        .and_then(|directory| relative_workspace_path(workspace_root, directory))
        .is_some_and(|relative| {
            excludes
                .iter()
                .any(|pattern| pattern.matches_path(&relative))
        })
}

fn cargo_workspace_manifests(
    workspace_manifest: &Path,
    workspace_value: Toml,
) -> Result<(Vec<CargoManifest>, BTreeMap<String, CargoDependencySpec>), ParseError> {
    let workspace = workspace_value
        .get("workspace")
        .and_then(Toml::as_table)
        .ok_or_else(|| {
            invalid(
                workspace_manifest,
                "Cargo workspace root is missing a [workspace] table",
            )
        })?;
    let workspace_root = workspace_manifest.parent().unwrap_or(Path::new("."));
    let member_patterns = workspace_path_list(workspace_manifest, workspace, "members")?;
    let exclude_patterns = workspace_path_list(workspace_manifest, workspace, "exclude")?
        .into_iter()
        .map(|pattern| {
            glob::Pattern::new(&pattern).map_err(|error| {
                invalid(
                    workspace_manifest,
                    format!("invalid Cargo workspace exclude pattern {pattern:?}: {error}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let workspace_dependencies =
        workspace_dependency_definitions(workspace_manifest, &workspace_value)?;

    let mut pending = VecDeque::new();
    let mut queued = BTreeSet::new();
    if workspace_value.get("package").is_some() {
        queued.insert(workspace_manifest.to_path_buf());
        pending.push_back(workspace_manifest.to_path_buf());
    }
    for member in member_patterns {
        for manifest in workspace_member_matches(workspace_manifest, workspace_root, &member)? {
            if !excluded_workspace_member(workspace_root, &manifest, &exclude_patterns)
                && queued.insert(manifest.clone())
            {
                pending.push_back(manifest);
            }
        }
    }
    for dependency in workspace_dependencies.values() {
        if let Some(local_path) = &dependency.local_path
            && relative_workspace_path(workspace_root, local_path).is_some()
        {
            let manifest = local_path.join("Cargo.toml");
            if !manifest.is_file() {
                return Err(invalid(
                    workspace_manifest,
                    format!(
                        "Cargo path dependency {} has no Cargo.toml",
                        local_path.display()
                    ),
                ));
            }
            let manifest =
                fs::canonicalize(&manifest).map_err(|error| io_error(&manifest, error))?;
            if !excluded_workspace_member(workspace_root, &manifest, &exclude_patterns)
                && queued.insert(manifest.clone())
            {
                pending.push_back(manifest);
            }
        }
    }

    let mut manifests = Vec::new();
    while let Some(path) = pending.pop_front() {
        let value = if path == workspace_manifest {
            workspace_value.clone()
        } else {
            read_cargo_manifest(&path)?
        };
        if value.get("package").and_then(Toml::as_table).is_none() {
            return Err(invalid(
                &path,
                "Cargo workspace member is missing a [package] table",
            ));
        }
        let manifest = CargoManifest {
            path: path.clone(),
            value,
        };
        let declarations = cargo_manifest_declarations(&manifest, &workspace_dependencies)?;
        for declaration in &declarations {
            let Some(local_path) = &declaration.dependency.local_path else {
                continue;
            };
            if relative_workspace_path(workspace_root, local_path).is_none() {
                continue;
            }
            let local_manifest = local_path.join("Cargo.toml");
            if !local_manifest.is_file() {
                return Err(invalid(
                    &declaration.declaring_manifest,
                    format!(
                        "Cargo path dependency {} has no Cargo.toml",
                        local_path.display()
                    ),
                ));
            }
            let local_manifest = fs::canonicalize(&local_manifest)
                .map_err(|error| io_error(&local_manifest, error))?;
            if !excluded_workspace_member(workspace_root, &local_manifest, &exclude_patterns)
                && queued.insert(local_manifest.clone())
            {
                pending.push_back(local_manifest);
            }
        }
        manifests.push(manifest);
    }
    manifests.sort_by(|left, right| left.path.cmp(&right.path));
    if manifests.is_empty() {
        return Err(invalid(
            workspace_manifest,
            "Cargo workspace contains no package members",
        ));
    }
    Ok((manifests, workspace_dependencies))
}

fn cargo_project_manifests(
    source_manifest: &Path,
) -> Result<(Vec<CargoManifest>, BTreeMap<String, CargoDependencySpec>), ParseError> {
    let source_value = read_cargo_manifest(source_manifest)?;
    if source_value.get("workspace").is_some() {
        return cargo_workspace_manifests(source_manifest, source_value);
    }
    let explicit_workspace = source_value
        .get("package")
        .and_then(Toml::as_table)
        .and_then(|package| package.get("workspace"));
    if let Some(explicit_workspace) = explicit_workspace {
        let explicit_workspace = explicit_workspace.as_str().ok_or_else(|| {
            invalid(
                source_manifest,
                "Cargo package field \"workspace\" must be a path string",
            )
        })?;
        let workspace_manifest = source_manifest
            .parent()
            .unwrap_or(Path::new("."))
            .join(explicit_workspace)
            .join("Cargo.toml");
        let workspace_manifest = fs::canonicalize(&workspace_manifest)
            .map_err(|error| io_error(&workspace_manifest, error))?;
        let workspace_value = read_cargo_manifest(&workspace_manifest)?;
        let (manifests, workspace_dependencies) =
            cargo_workspace_manifests(&workspace_manifest, workspace_value)?;
        let canonical_source =
            fs::canonicalize(source_manifest).map_err(|error| io_error(source_manifest, error))?;
        if !manifests.iter().any(|manifest| {
            fs::canonicalize(&manifest.path).ok().as_ref() == Some(&canonical_source)
        }) {
            return Err(invalid(
                source_manifest,
                "Cargo package points to a workspace that does not include it",
            ));
        }
        return Ok((manifests, workspace_dependencies));
    }
    let canonical_source =
        fs::canonicalize(source_manifest).map_err(|error| io_error(source_manifest, error))?;
    let mut ancestor = source_manifest.parent().and_then(Path::parent);
    while let Some(directory) = ancestor {
        let candidate = directory.join("Cargo.toml");
        if candidate.is_file() {
            let value = read_cargo_manifest(&candidate)?;
            if value.get("workspace").is_some() {
                let candidate =
                    fs::canonicalize(&candidate).map_err(|error| io_error(&candidate, error))?;
                let (manifests, workspace_dependencies) =
                    cargo_workspace_manifests(&candidate, value)?;
                if manifests.iter().any(|manifest| {
                    fs::canonicalize(&manifest.path).ok().as_ref() == Some(&canonical_source)
                }) {
                    return Ok((manifests, workspace_dependencies));
                }
                return Err(invalid(
                    source_manifest,
                    format!(
                        "Cargo package is under workspace {} but is not included as a member",
                        candidate.display()
                    ),
                ));
            }
        }
        ancestor = directory.parent();
    }
    if source_value
        .get("package")
        .and_then(Toml::as_table)
        .is_none()
    {
        return Err(invalid(
            source_manifest,
            "Cargo manifest is missing a [package] or [workspace] table",
        ));
    }
    Ok((
        vec![CargoManifest {
            path: source_manifest.to_path_buf(),
            value: source_value,
        }],
        BTreeMap::new(),
    ))
}

fn cargo_project_declarations(path: &Path) -> Result<Vec<CargoDeclaration>, ParseError> {
    let (manifests, workspace_dependencies) = cargo_project_manifests(path)?;
    manifests
        .iter()
        .map(|manifest| cargo_manifest_declarations(manifest, &workspace_dependencies))
        .collect::<Result<Vec<_>, _>>()
        .map(|declarations| declarations.into_iter().flatten().collect())
}

fn cargo_direct_dependencies(root: &Path) -> Result<BTreeMap<String, bool>, ParseError> {
    let manifest = root.join("Cargo.toml");
    if !manifest.is_file() {
        return Ok(BTreeMap::new());
    }
    let mut direct = BTreeMap::new();
    for declaration in cargo_project_declarations(&manifest)? {
        direct
            .entry(declaration.dependency.package_name)
            .and_modify(|dev_only| *dev_only &= declaration.dev)
            .or_insert(declaration.dev);
    }
    Ok(direct)
}

fn parse_cargo_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let value: Toml = toml::from_str(&text).map_err(|e| invalid(path, e))?;
    let document = value.as_table().ok_or_else(|| {
        invalid(
            path,
            "detected a non-table TOML document; expected a Cargo.lock table",
        )
    })?;
    let lockfile_version = match document.get("version") {
        Some(version) => version.as_integer().ok_or_else(|| {
            invalid(
                path,
                "detected Cargo.lock with a non-integer version; expected lockfile version 1 through 4",
            )
        })?,
        None => 1,
    };
    if !(1..=4).contains(&lockfile_version) {
        return Err(invalid(
            path,
            format!(
                "detected unsupported Cargo.lock version {lockfile_version}; expected version 1 through 4"
            ),
        ));
    }
    let package_entries = document
        .get("package")
        .and_then(Toml::as_array)
        .ok_or_else(|| {
            invalid(
                path,
                format!(
                    "detected Cargo.lock version {lockfile_version} without a package array; expected resolved package entries"
                ),
            )
        })?;
    let direct = cargo_direct_dependencies(path.parent().unwrap_or(Path::new(".")))?;
    let mut out = Vec::new();
    for (index, item) in package_entries.iter().enumerate() {
        let item = item.as_table().ok_or_else(|| {
            invalid(
                path,
                format!("Cargo.lock package entry {index} must be a table"),
            )
        })?;
        let name = item
            .get("name")
            .and_then(Toml::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                invalid(
                    path,
                    format!("Cargo.lock package entry {index} is missing a non-empty string name"),
                )
            })?;
        let version = item
            .get("version")
            .and_then(Toml::as_str)
            .filter(|version| !version.is_empty())
            .ok_or_else(|| {
                invalid(
                    path,
                    format!(
                        "Cargo.lock package entry {index} is missing a non-empty string version"
                    ),
                )
            })?;
        semver::Version::parse(version).map_err(|error| {
            invalid(
                path,
                format!(
                    "Cargo.lock package entry {index} has invalid SemVer version {version:?}: {error}"
                ),
            )
        })?;
        let source = item
            .get("source")
            .map(|source| {
                source
                    .as_str()
                    .filter(|source| !source.is_empty())
                    .ok_or_else(|| {
                        invalid(
                            path,
                            format!(
                                "Cargo.lock package entry {index} source must be a non-empty string"
                            ),
                        )
                    })
            })
            .transpose()?;
        let mut package = Package::new(Ecosystem::CratesIo, name, version, path.to_path_buf());
        if let Some(dev) = direct.get(name) {
            package.direct = true;
            package.dev = *dev;
        }
        if !source.is_some_and(|source| {
            source.starts_with("registry+https://github.com/rust-lang/crates.io-index")
        }) {
            package.enrichable = false;
        }
        out.push(package);
    }
    Ok(dedup(out))
}
fn parse_cargo_toml(path: &Path) -> Result<Vec<Package>, ParseError> {
    let mut packages = BTreeMap::new();
    for declaration in cargo_project_declarations(path)? {
        let Some(version) = declaration.dependency.version else {
            continue;
        };
        let mut package = Package::new(
            Ecosystem::CratesIo,
            declaration.dependency.package_name,
            version,
            declaration.declaring_manifest,
        );
        package.direct = true;
        package.dev = declaration.dev;
        package.enrichable = declaration.dependency.enrichable;
        let constraint = package.version.clone();
        package.set_manifest_constraint(constraint);
        let key = (package.key(), package.source_file.clone());
        packages
            .entry(key)
            .and_modify(|existing: &mut Package| {
                existing.dev &= package.dev;
                existing.enrichable &= package.enrichable;
            })
            .or_insert(package);
    }
    Ok(packages.into_values().collect())
}

fn dedup(packages: Vec<Package>) -> Vec<Package> {
    let mut map: BTreeMap<String, Package> = BTreeMap::new();
    for p in packages {
        let key = p.key();
        map.entry(key)
            .and_modify(|old| old.merge_metadata(&p))
            .or_insert(p);
    }
    map.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    fn npm_fixture_packages(fixture: &str) -> Vec<Package> {
        let lock = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture)
            .join("package-lock.json");
        let packages = parse_package_lock(&lock).unwrap();
        assert!(packages.iter().all(|package| package.source_file == lock));
        packages
    }

    fn normalized_npm_packages(packages: &[Package]) -> Json {
        Json::Array(
            packages
                .iter()
                .map(|package| {
                    json!({
                        "name": package.name,
                        "version": package.version,
                        "direct": package.direct,
                        "dev": package.dev,
                        "source": package
                            .source_file
                            .file_name()
                            .and_then(|name| name.to_str()),
                    })
                })
                .collect(),
        )
    }

    #[test]
    fn parses_nested_npm_v2_packages_and_workspace_dependencies() {
        let packages = npm_fixture_packages("npm-v2-nested");

        insta::assert_json_snapshot!(normalized_npm_packages(&packages), @r#"
        [
          {
            "dev": false,
            "direct": false,
            "name": "@nested/tool",
            "source": "package-lock.json",
            "version": "1.5.0"
          },
          {
            "dev": false,
            "direct": true,
            "name": "@scope/root",
            "source": "package-lock.json",
            "version": "3.0.0"
          },
          {
            "dev": false,
            "direct": true,
            "name": "alpha",
            "source": "package-lock.json",
            "version": "2.0.0"
          },
          {
            "dev": true,
            "direct": false,
            "name": "dev-child",
            "source": "package-lock.json",
            "version": "1.0.0"
          },
          {
            "dev": true,
            "direct": true,
            "name": "dev-tool",
            "source": "package-lock.json",
            "version": "4.0.0"
          },
          {
            "dev": false,
            "direct": false,
            "name": "duplicate",
            "source": "package-lock.json",
            "version": "1.0.0"
          },
          {
            "dev": false,
            "direct": true,
            "name": "duplicate",
            "source": "package-lock.json",
            "version": "2.0.0"
          },
          {
            "dev": false,
            "direct": false,
            "name": "duplicate",
            "source": "package-lock.json",
            "version": "3.0.0"
          },
          {
            "dev": false,
            "direct": false,
            "name": "shared",
            "source": "package-lock.json",
            "version": "5.0.0"
          },
          {
            "dev": true,
            "direct": true,
            "name": "workspace-dev",
            "source": "package-lock.json",
            "version": "6.0.0"
          },
          {
            "dev": false,
            "direct": true,
            "name": "workspace-direct",
            "source": "package-lock.json",
            "version": "5.0.0"
          }
        ]
        "#);
    }

    #[test]
    fn parses_nested_npm_v3_packages_and_skips_local_descriptors() {
        let packages = npm_fixture_packages("npm-v3-nested");

        insta::assert_json_snapshot!(normalized_npm_packages(&packages), @r#"
        [
          {
            "dev": false,
            "direct": false,
            "name": "@nested/scoped",
            "source": "package-lock.json",
            "version": "2.1.0"
          },
          {
            "dev": false,
            "direct": true,
            "name": "@scope/direct",
            "source": "package-lock.json",
            "version": "2.0.0"
          },
          {
            "dev": false,
            "direct": true,
            "name": "producer",
            "source": "package-lock.json",
            "version": "1.0.0"
          },
          {
            "dev": false,
            "direct": false,
            "name": "repeated",
            "source": "package-lock.json",
            "version": "0.8.0"
          },
          {
            "dev": false,
            "direct": false,
            "name": "repeated",
            "source": "package-lock.json",
            "version": "0.9.0"
          },
          {
            "dev": false,
            "direct": true,
            "name": "repeated",
            "source": "package-lock.json",
            "version": "1.5.0"
          },
          {
            "dev": false,
            "direct": true,
            "name": "workspace-only",
            "source": "package-lock.json",
            "version": "7.0.0"
          }
        ]
        "#);
    }

    #[test]
    fn keeps_legacy_npm_v1_nested_packages_best_effort() {
        let packages = npm_fixture_packages("npm-v1-nested");

        insta::assert_json_snapshot!(normalized_npm_packages(&packages), @r#"
        [
          {
            "dev": false,
            "direct": false,
            "name": "@scope/child",
            "source": "package-lock.json",
            "version": "1.1.0"
          },
          {
            "dev": true,
            "direct": false,
            "name": "dev-child",
            "source": "package-lock.json",
            "version": "1.0.0"
          },
          {
            "dev": true,
            "direct": true,
            "name": "direct-dev",
            "source": "package-lock.json",
            "version": "3.0.0"
          },
          {
            "dev": false,
            "direct": true,
            "name": "direct-one",
            "source": "package-lock.json",
            "version": "1.0.0"
          },
          {
            "dev": false,
            "direct": false,
            "name": "duplicate",
            "source": "package-lock.json",
            "version": "0.5.0"
          },
          {
            "dev": false,
            "direct": false,
            "name": "duplicate",
            "source": "package-lock.json",
            "version": "2.0.0"
          },
          {
            "dev": false,
            "direct": false,
            "name": "retained-child",
            "source": "package-lock.json",
            "version": "4.0.0"
          }
        ]
        "#);
    }

    #[test]
    fn parses_cargo_lock() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("Cargo.lock");
        fs::write(&lock, "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n").unwrap();
        let result = CargoParser
            .parse(&DetectedSource {
                path: lock,
                kind: SourceKind::CargoLock,
            })
            .unwrap();
        assert_eq!(result[0].name, "serde");
    }

    #[test]
    fn package_json_preserves_the_original_npm_range() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        fs::write(
            &manifest,
            r#"{"dependencies":{"range-package":"^1.2 || 3.x"}}"#,
        )
        .unwrap();

        let packages = parse_package_json_project(&manifest).unwrap();

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].version, "^1.2 || 3.x");
        let constraint = packages[0].manifest_constraint.as_ref().unwrap();
        assert_eq!(constraint.raw(), "^1.2 || 3.x");
        assert_eq!(constraint.normalized(), constraint.raw());
    }

    #[test]
    fn parses_nuget_lock_with_normalized_identity_and_preserved_case() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("packages.lock.json");
        fs::write(
            &lock,
            r#"{
                "version": 1,
                "dependencies": {
                    "net8.0": {
                        "Newtonsoft.Json": {
                            "type": "Direct",
                            "resolved": "12.0.1"
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        let result = parse_packages_lock(&lock).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "newtonsoft.json");
        assert_eq!(result[0].display_name, "Newtonsoft.Json");
        assert_eq!(result[0].key(), "NuGet:newtonsoft.json:12.0.1");
        assert!(result[0].direct);
    }

    #[test]
    fn parses_nuget_project_with_normalized_identity_and_preserved_case() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("sample.csproj");
        fs::write(
            &project,
            r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>"#,
        )
        .unwrap();

        let result = parse_nuget_project(&project).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "newtonsoft.json");
        assert_eq!(result[0].display_name, "Newtonsoft.Json");
    }

    #[test]
    fn rejects_duplicate_nuget_attributes_after_large_attribute_set() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("duplicate-attributes.csproj");
        let mut attributes = String::from(r#"Include="First.Package" Version="1.2.3""#);
        // quick-xml 0.41 switches duplicate detection to its linear-time hash path
        // after 32 attributes. Keep the duplicate beyond that boundary so this
        // exercises depscan's real `attributes()` call through the patched path.
        for index in 0..40 {
            attributes.push_str(&format!(r#" data-{index}="value""#));
        }
        attributes.push_str(r#" Include="Second.Package""#);
        fs::write(
            &project,
            format!("<Project><ItemGroup><PackageReference {attributes} /></ItemGroup></Project>"),
        )
        .unwrap();

        let error = parse_nuget_project(&project).unwrap_err();

        assert!(error.to_string().contains("duplicated attribute"));
    }

    #[test]
    fn plain_nuget_reader_accepts_more_than_namespace_resolver_limit() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("namespace-declarations.csproj");
        let mut namespaces = String::new();
        // RUSTSEC-2026-0195 affects NsReader's namespace resolver. depscan uses
        // plain Reader, so even an element above NsReader's 256-declaration cap
        // is handled as ordinary attributes without a resolver-side allocation.
        for index in 0..300 {
            namespaces.push_str(&format!(r#" xmlns:p{index}="urn:test:{index}""#));
        }
        fs::write(
            &project,
            format!(
                "<Project{namespaces}><ItemGroup><PackageReference Include=\"Safe.Package\" Version=\"4.5.6\" /></ItemGroup></Project>"
            ),
        )
        .unwrap();

        let result = parse_nuget_project(&project).unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].display_name, "Safe.Package");
        assert_eq!(result[0].version, "4.5.6");
    }

    #[test]
    fn deduplicates_nuget_identifiers_case_insensitively() {
        let packages = vec![
            Package::new(
                Ecosystem::NuGet,
                "Newtonsoft.Json",
                "12.0.1",
                PathBuf::from("one.csproj"),
            ),
            Package::new(
                Ecosystem::NuGet,
                "NEWTONSOFT.JSON",
                "12.0.1",
                PathBuf::from("two.csproj"),
            ),
        ];

        let result = dedup(packages);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].key(), "NuGet:newtonsoft.json:12.0.1");
    }

    #[test]
    fn parses_pnpm_scoped_key() {
        assert_eq!(
            parse_pnpm_key("/@scope/pkg@1.2.3(peer@2)"),
            Some(("@scope/pkg", "1.2.3"))
        );
    }
}
