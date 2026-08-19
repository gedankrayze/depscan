//! Offline, filesystem-only dependency parsers.

use depscan_core::{DetectedSource, Ecosystem, EcosystemParser, Package, ParseError, SourceKind};
use quick_xml::Reader;
use quick_xml::events::Event;
use serde_json::Value as Json;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
};
use toml::Value as Toml;
use walkdir::WalkDir;

mod requirements;

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
            SourceKind::PackageJson => parse_package_json_manifest(&source.path),
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
    let mut packages = Vec::new();
    if let Some(map) = value.get("packages").and_then(Json::as_object) {
        for (key, entry) in map {
            if key.is_empty() || entry.get("link").and_then(Json::as_bool) == Some(true) {
                continue;
            }
            if let Some(version) = entry.get("version").and_then(Json::as_str)
                && let Some(location) = npm_package_location(key)
            {
                let mut pkg =
                    Package::new(Ecosystem::Npm, &location.name, version, path.to_path_buf());
                pkg.direct = direct.includes_package_at(&location.install_parent, &location.name);
                pkg.dev = entry.get("dev").and_then(Json::as_bool).unwrap_or(false);
                packages.push(pkg);
            }
        }
    } else if let Some(deps) = value.get("dependencies") {
        parse_legacy_npm_tree(deps, path, &direct.all, true, &mut packages);
    }
    Ok(dedup(packages))
}
fn parse_legacy_npm_tree(
    node: &Json,
    path: &Path,
    direct: &HashSet<String>,
    top_level: bool,
    out: &mut Vec<Package>,
) {
    if let Some(map) = node.as_object() {
        for (name, entry) in map {
            if let Some(version) = entry.get("version").and_then(Json::as_str) {
                let mut p = Package::new(Ecosystem::Npm, name, version, path.to_path_buf());
                p.direct = top_level && direct.contains(name);
                p.dev = entry.get("dev").and_then(Json::as_bool).unwrap_or(false);
                out.push(p);
            }
            if let Some(children) = entry.get("dependencies") {
                parse_legacy_npm_tree(children, path, direct, false, out);
            }
        }
    }
}

fn parse_bun_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let cleaned = strip_jsonc(&text).map_err(|error| invalid(path, error))?;
    let value: Json = serde_json::from_str(&cleaned).map_err(|e| invalid(path, e))?;
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
    let Some(packages) = value.get("packages") else {
        return Ok(output);
    };
    let packages = packages
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
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let value: serde_yaml::Value = serde_yaml::from_str(&text).map_err(|e| invalid(path, e))?;
    let root = path.parent().unwrap_or(Path::new("."));
    let direct = node_direct_names(root);
    let mut out = Vec::new();
    if let Some(packages) = value
        .get("packages")
        .and_then(serde_yaml::Value::as_mapping)
    {
        for (key, entry) in packages {
            if let Some(raw) = key.as_str()
                && let Some((name, version)) = parse_pnpm_key(raw)
            {
                let mut p = Package::new(Ecosystem::Npm, name, version, path.to_path_buf());
                p.direct = direct.contains(&p.name);
                p.dev = entry
                    .get("dev")
                    .and_then(serde_yaml::Value::as_bool)
                    .unwrap_or(false);
                out.push(p);
            }
        }
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
    Some((name, version.trim_start_matches('@')))
}

fn parse_yarn_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let root = path.parent().unwrap_or(Path::new("."));
    let direct = node_direct_names(root);
    let mut out = Vec::new();
    let mut selectors: Vec<String> = Vec::new();
    let mut version: Option<String> = None;
    let flush = |selectors: &mut Vec<String>,
                 version: &mut Option<String>,
                 out: &mut Vec<Package>| {
        if let Some(v) = version.take() {
            for s in selectors.drain(..) {
                let name = yarn_selector_name(&s);
                if !name.is_empty() {
                    let mut p = Package::new(Ecosystem::Npm, name, v.clone(), path.to_path_buf());
                    p.direct = direct.contains(&p.name);
                    out.push(p);
                }
            }
        }
    };
    for line in text.lines() {
        if !line.starts_with(' ') && line.ends_with(':') {
            flush(&mut selectors, &mut version, &mut out);
            selectors = line
                .trim_end_matches(':')
                .split(',')
                .map(|s| s.trim().trim_matches('"').to_owned())
                .collect();
        } else if let Some(v) = line.trim().strip_prefix("version ") {
            version = Some(v.trim_matches('"').to_owned());
        }
    }
    flush(&mut selectors, &mut version, &mut out);
    Ok(dedup(out))
}
fn yarn_selector_name(selector: &str) -> &str {
    let s = selector.trim_matches('"');
    if s.starts_with('@') {
        let slash = s.find('/').unwrap_or(0);
        s[slash + 1..]
            .find('@')
            .map(|i| &s[..slash + 1 + i])
            .unwrap_or(s)
    } else {
        s.find('@').map(|i| &s[..i]).unwrap_or(s)
    }
}

fn parse_package_json_manifest(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let value: Json = serde_json::from_str(&text).map_err(|e| invalid(path, e))?;
    let mut out = Vec::new();
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(obj) = value.get(key).and_then(Json::as_object) {
            for (name, range) in obj {
                if let Some(range) = range.as_str() {
                    let mut p = Package::new(Ecosystem::Npm, name, range, path.to_path_buf());
                    p.direct = true;
                    p.dev = key == "devDependencies";
                    p.resolved_from_range = true;
                    out.push(p);
                }
            }
        }
    }
    Ok(dedup(out))
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
            SourceKind::UvLock | SourceKind::PoetryLock => parse_python_lock(&source.path),
            SourceKind::PipfileLock => parse_pipfile_lock(&source.path),
            SourceKind::RequirementsTxt => requirements::parse(&source.path),
            SourceKind::PyProject => parse_pyproject(&source.path),
            _ => Err(invalid(&source.path, "unexpected source kind")),
        }
    }
}
fn parse_python_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let value: Toml = toml::from_str(&text).map_err(|e| invalid(path, e))?;
    let mut out = Vec::new();
    for item in value
        .get("package")
        .and_then(Toml::as_array)
        .into_iter()
        .flatten()
    {
        if let (Some(name), Some(version)) = (
            item.get("name").and_then(Toml::as_str),
            item.get("version").and_then(Toml::as_str),
        ) {
            let mut p = Package::new(Ecosystem::PyPI, name, version, path.to_path_buf());
            let source_type = item
                .get("source")
                .and_then(Toml::as_table)
                .and_then(|t| t.get("type"))
                .and_then(Toml::as_str);
            if matches!(source_type, Some("git" | "directory" | "url" | "path")) {
                p.enrichable = false;
            }
            out.push(p);
        }
    }
    Ok(dedup(out))
}
fn parse_pipfile_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let value: Json = serde_json::from_str(&text).map_err(|e| invalid(path, e))?;
    let mut out = Vec::new();
    for section in ["default", "develop"] {
        if let Some(map) = value.get(section).and_then(Json::as_object) {
            for (name, item) in map {
                if let Some(version) = item.get("version").and_then(Json::as_str) {
                    let mut p = Package::new(
                        Ecosystem::PyPI,
                        name,
                        version.trim_start_matches("=="),
                        path.to_path_buf(),
                    );
                    p.direct = true;
                    p.dev = section == "develop";
                    out.push(p);
                }
            }
        }
    }
    Ok(dedup(out))
}
fn parse_pyproject(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let value: Toml = toml::from_str(&text).map_err(|e| invalid(path, e))?;
    let mut deps = Vec::new();
    if let Some(arr) = value
        .get("project")
        .and_then(Toml::as_table)
        .and_then(|t| t.get("dependencies"))
        .and_then(Toml::as_array)
    {
        deps.extend(arr.iter().filter_map(Toml::as_str).map(str::to_owned));
    }
    if let Some(tbl) = value
        .get("tool")
        .and_then(Toml::as_table)
        .and_then(|t| t.get("poetry"))
        .and_then(Toml::as_table)
        .and_then(|t| t.get("dependencies"))
        .and_then(Toml::as_table)
    {
        deps.extend(
            tbl.iter()
                .filter_map(|(k, v)| v.as_str().map(|x| format!("{k}{x}"))),
        );
    }
    let mut out = Vec::new();
    for spec in deps {
        let name = spec
            .split(['<', '>', '~', '!', '=', ';', '['])
            .next()
            .unwrap_or("")
            .trim();
        if !name.is_empty() {
            let mut p = Package::new(
                Ecosystem::PyPI,
                name,
                spec[name.len()..].trim(),
                path.to_path_buf(),
            );
            p.direct = true;
            p.resolved_from_range = true;
            out.push(p);
        }
    }
    Ok(dedup(out))
}

pub struct NugetParser;
impl EcosystemParser for NugetParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::NuGet
    }
    fn detect(&self, root: &Path) -> Vec<DetectedSource> {
        if let Some(s) = source(root, "packages.lock.json", SourceKind::PackagesLock) {
            return vec![s];
        }
        let projects = sorted_project_files(root, &["csproj", "fsproj", "vbproj"]);
        if let Some(path) = projects.into_iter().next() {
            return vec![DetectedSource {
                path,
                kind: SourceKind::ProjectFile,
            }];
        }
        source(root, "packages.config", SourceKind::PackagesConfig)
            .into_iter()
            .collect()
    }
    fn parse(&self, source: &DetectedSource) -> Result<Vec<Package>, ParseError> {
        match source.kind {
            SourceKind::PackagesLock => parse_packages_lock(&source.path),
            SourceKind::ProjectFile
            | SourceKind::DirectoryPackagesProps
            | SourceKind::PackagesConfig => parse_xml_packages(&source.path),
            _ => Err(invalid(&source.path, "unexpected source kind")),
        }
    }
}
fn parse_packages_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let value: Json = serde_json::from_str(&text).map_err(|e| invalid(path, e))?;
    let mut out = Vec::new();
    if let Some(frameworks) = value.get("dependencies").and_then(Json::as_object) {
        for framework in frameworks.values() {
            if let Some(items) = framework.as_object() {
                for (name, item) in items {
                    if let Some(version) = item.get("resolved").and_then(Json::as_str) {
                        let mut p =
                            Package::new(Ecosystem::NuGet, name, version, path.to_path_buf());
                        p.direct = item.get("type").and_then(Json::as_str) == Some("Direct");
                        out.push(p);
                    }
                }
            }
        }
    }
    Ok(dedup(out))
}
fn parse_xml_packages(path: &Path) -> Result<Vec<Package>, ParseError> {
    let content = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let mut reader = Reader::from_str(&content);
    reader.config_mut().trim_text(true);
    let mut out = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if matches!(
                    tag.as_str(),
                    "PackageReference" | "PackageVersion" | "package"
                ) {
                    let mut name = None;
                    let mut version = None;
                    for attr in e.attributes() {
                        let attr = attr.map_err(|error| invalid(path, error))?;
                        let key = String::from_utf8_lossy(attr.key.as_ref());
                        let val = String::from_utf8_lossy(&attr.value).to_string();
                        match key.as_ref() {
                            "Include" | "Update" | "id" => name = Some(val),
                            "Version" | "version" => version = Some(val),
                            _ => {}
                        }
                    }
                    if let (Some(name), Some(version)) = (name, version) {
                        let mut p = Package::new(
                            Ecosystem::NuGet,
                            name,
                            version.clone(),
                            path.to_path_buf(),
                        );
                        p.direct = true;
                        p.resolved_from_range = version.contains('*')
                            || version.starts_with('[')
                            || version.starts_with('(');
                        out.push(p);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(invalid(path, e)),
            _ => {}
        }
        buf.clear();
    }
    Ok(dedup(out))
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
    let direct = cargo_direct_dependencies(path.parent().unwrap_or(Path::new(".")))?;
    let mut out = Vec::new();
    for item in value
        .get("package")
        .and_then(Toml::as_array)
        .into_iter()
        .flatten()
    {
        if let (Some(name), Some(version)) = (
            item.get("name").and_then(Toml::as_str),
            item.get("version").and_then(Toml::as_str),
        ) {
            let mut p = Package::new(Ecosystem::CratesIo, name, version, path.to_path_buf());
            if let Some(dev) = direct.get(name) {
                p.direct = true;
                p.dev = *dev;
            }
            if !item.get("source").and_then(Toml::as_str).is_some_and(|s| {
                s.starts_with("registry+https://github.com/rust-lang/crates.io-index")
            }) {
                p.enrichable = false;
            }
            out.push(p);
        }
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
        package.resolved_from_range = true;
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
            .and_modify(|old| {
                old.direct |= p.direct;
                old.dev &= p.dev;
                old.enrichable |= p.enrichable;
            })
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

        let result = parse_xml_packages(&project).unwrap();

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

        let error = parse_xml_packages(&project).unwrap_err();

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

        let result = parse_xml_packages(&project).unwrap();

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
