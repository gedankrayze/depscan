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
    complete: bool,
}

impl NodeDirectDependencies {
    fn directness(&self, name: &str) -> Option<bool> {
        self.all
            .contains(name)
            .then_some(true)
            .or_else(|| self.complete.then_some(false))
    }
}

struct NodeProjectDependency {
    name: String,
    constraint: String,
    development: bool,
}

#[derive(Default)]
struct NodeProjectDependencies {
    declarations: Vec<NodeProjectDependency>,
    complete: bool,
}

fn append_node_manifest_dependencies(
    path: &Path,
    value: &Json,
    dependencies: &mut NodeProjectDependencies,
) -> Result<(), ParseError> {
    dependencies
        .declarations
        .extend(
            parse_package_json_value(path, value)?
                .into_iter()
                .map(|package| {
                    let constraint = package
                        .manifest_constraint
                        .expect("package.json dependency has a manifest constraint")
                        .raw()
                        .to_owned();
                    NodeProjectDependency {
                        name: package.display_name,
                        constraint,
                        development: package.dev,
                    }
                }),
        );
    Ok(())
}

fn node_project_dependencies(root: &Path) -> NodeProjectDependencies {
    let root_manifest = root.join("package.json");
    let Ok(root_value) = read_validated_root_package_json(&root_manifest) else {
        return NodeProjectDependencies::default();
    };

    let mut dependencies = NodeProjectDependencies::default();
    if append_node_manifest_dependencies(&root_manifest, &root_value, &mut dependencies).is_err() {
        return dependencies;
    }

    let Ok(manifests) = workspace_manifests(&root_manifest, &root_value) else {
        return dependencies;
    };
    let mut complete = true;
    for manifest in manifests {
        if manifest == root_manifest {
            continue;
        }
        let parsed = read_package_json(&manifest).and_then(|value| {
            append_node_manifest_dependencies(&manifest, &value, &mut dependencies)
        });
        if parsed.is_err() {
            complete = false;
        }
    }
    dependencies.complete = complete;
    dependencies
}

fn node_direct_dependencies(root: &Path) -> NodeDirectDependencies {
    let dependencies = node_project_dependencies(root);
    let mut direct = NodeDirectDependencies {
        complete: dependencies.complete,
        ..NodeDirectDependencies::default()
    };
    for declaration in dependencies.declarations {
        direct.all.insert(declaration.name);
    }
    direct
}

#[derive(Debug, Clone, Copy, Default)]
struct YarnDirectness {
    production: bool,
    development: bool,
}

#[derive(Clone)]
struct YarnDirectSelector {
    constraint: String,
    directness: YarnDirectness,
    matching_entries: usize,
}

#[derive(Default)]
struct YarnDirectDependencies {
    by_name: HashMap<String, Vec<YarnDirectSelector>>,
}

fn yarn_direct_dependencies(root: &Path) -> YarnDirectDependencies {
    let dependencies = node_project_dependencies(root);
    let mut direct = YarnDirectDependencies::default();
    for declaration in dependencies.declarations {
        let selectors = direct.by_name.entry(declaration.name).or_default();
        let selector_index = selectors
            .iter()
            .position(|selector| selector.constraint == declaration.constraint)
            .unwrap_or_else(|| {
                selectors.push(YarnDirectSelector {
                    constraint: declaration.constraint,
                    directness: YarnDirectness::default(),
                    matching_entries: 0,
                });
                selectors.len() - 1
            });
        let flags = &mut selectors[selector_index].directness;
        if declaration.development {
            flags.development = true;
        } else {
            flags.production = true;
        }
    }
    direct
}

struct NpmPackageLocation {
    name: String,
    install_parent_key: String,
}

fn npm_package_location(location: &str) -> Option<NpmPackageLocation> {
    let segments: Vec<_> = location.split('/').collect();
    if segments
        .iter()
        .any(|segment| matches!(*segment, "" | "." | ".."))
    {
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
        install_parent_key: segments[..node_modules].join("/"),
    })
}

fn valid_npm_package_segment(segment: &str) -> bool {
    !matches!(segment, "" | "." | ".." | "node_modules")
}

fn npm_lock_optional_bool(
    path: &Path,
    location: &str,
    entry: &serde_json::Map<String, Json>,
    field: &str,
) -> Result<Option<bool>, ParseError> {
    entry
        .get(field)
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                invalid(
                    path,
                    format!("npm package entry {location:?} field {field:?} must be a boolean"),
                )
            })
        })
        .transpose()
}

fn npm_lock_source_locator(version: &str) -> bool {
    let lower = version.to_ascii_lowercase();
    lower.starts_with("workspace:")
        || lower.starts_with("file:")
        || lower.starts_with("link:")
        || lower.starts_with("git:")
        || lower.starts_with("git+")
        || lower.starts_with("git@")
        || lower.starts_with("github:")
        || lower.starts_with("gitlab:")
        || lower.starts_with("bitbucket:")
        || lower.starts_with("gist:")
        || lower.starts_with("http:")
        || lower.starts_with("https:")
        || lower.starts_with("ssh:")
        || lower.starts_with("npm:")
        || version.starts_with('/')
        || version.starts_with("./")
        || version.starts_with("../")
}

fn npm_lock_declared_nonregistry(specification: &str) -> bool {
    npm_lock_source_locator(specification) && npm_alias_reference(specification).is_none()
}

fn npm_alias_reference(specification: &str) -> Option<&str> {
    specification
        .get(..4)
        .filter(|prefix| prefix.eq_ignore_ascii_case("npm:"))
        .map(|_| &specification[4..])
}

fn npm_alias_parts(reference: &str) -> Result<(&str, &str), String> {
    if reference.is_empty() {
        return Err("alias target is empty".to_owned());
    }
    let separator = if reference.starts_with('@') {
        let slash = reference
            .find('/')
            .ok_or_else(|| "scoped alias target is missing '/'".to_owned())?;
        reference[slash + 1..]
            .find('@')
            .map(|index| slash + 1 + index)
    } else {
        reference.find('@')
    };
    let (name, version) = separator.map_or((reference, None), |separator| {
        (&reference[..separator], Some(&reference[separator + 1..]))
    });
    validate_bun_package_name(name)?;
    if version.is_some_and(|version| !version.is_empty() && npm_lock_source_locator(version)) {
        return Err("alias target version must be a registry version, range, or tag".to_owned());
    }
    Ok((
        name,
        version.filter(|version| !version.is_empty()).unwrap_or("*"),
    ))
}

#[cfg(test)]
fn npm_alias_target(reference: &str) -> Result<&str, String> {
    npm_alias_parts(reference).map(|(name, _)| name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NpmResolvedSource {
    PublicRegistry,
    Nonregistry,
    OmittedRegistryResolution,
    ConfiguredRegistry,
}

fn npm_lock_resolved_source(resolved: Option<&str>) -> Result<NpmResolvedSource, String> {
    let Some(resolved) = resolved else {
        return Ok(NpmResolvedSource::OmittedRegistryResolution);
    };
    if resolved == "registry.npmjs.org" || resolved.starts_with("registry.npmjs.org/") {
        // npm documents this as a magic reference to the configured registry,
        // which is not necessarily the public registry used by this scanner.
        return Ok(NpmResolvedSource::ConfiguredRegistry);
    }
    if resolved.starts_with('/') || resolved.starts_with("./") || resolved.starts_with("../") {
        return Ok(NpmResolvedSource::Nonregistry);
    }
    if resolved.starts_with("git@") {
        let Some((authority, repository)) = resolved.split_once(':') else {
            return Err("SCP-style Git source is missing ':'".to_owned());
        };
        let repository = repository
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
            .trim();
        if authority.trim_start_matches("git@").is_empty() || repository.is_empty() {
            return Err("SCP-style Git source must contain a host and repository path".to_owned());
        }
        return Ok(NpmResolvedSource::Nonregistry);
    }
    if resolved.ends_with(".tgz")
        && resolved.contains('/')
        && !resolved.contains("://")
        && !resolved.contains([':', '?', '#', '@'])
        && !resolved.contains(char::is_whitespace)
        && !resolved.contains('\\')
    {
        return Ok(NpmResolvedSource::Nonregistry);
    }

    if let Some((scheme, suffix)) = resolved.split_once(':')
        && matches!(
            scheme.to_ascii_lowercase().as_str(),
            "bitbucket"
                | "file"
                | "gist"
                | "git"
                | "git+file"
                | "git+http"
                | "git+https"
                | "git+ssh"
                | "github"
                | "gitlab"
                | "link"
                | "npm"
                | "ssh"
                | "workspace"
        )
    {
        let payload = suffix.split(['?', '#']).next().unwrap_or_default().trim();
        if payload.trim_matches('/').is_empty() {
            return Err("source URL has no package or repository path".to_owned());
        }
    }

    let parsed = Url::parse(resolved).map_err(|_| "source is not a supported URL or path")?;
    match parsed.scheme() {
        "http" | "https" => {
            let host = parsed
                .host_str()
                .ok_or_else(|| "HTTP source has no host".to_owned())?;
            let canonical_public = host.eq_ignore_ascii_case("registry.npmjs.org")
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.port().is_none();
            Ok(if canonical_public {
                NpmResolvedSource::PublicRegistry
            } else {
                NpmResolvedSource::Nonregistry
            })
        }
        "bitbucket" | "file" | "gist" | "git" | "git+file" | "git+http" | "git+https"
        | "git+ssh" | "github" | "gitlab" | "link" | "npm" | "ssh" | "workspace" => {
            if parsed.path().is_empty() {
                Err("source URL has no path".to_owned())
            } else {
                Ok(NpmResolvedSource::Nonregistry)
            }
        }
        _ => Err("source uses an unsupported URL scheme".to_owned()),
    }
}

fn npm_percent_decode_path_component(component: &str) -> Option<String> {
    let bytes = component.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            let hex = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            decoded.push(hex(high)? * 16 + hex(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn npm_public_tarball_matches(resolved: &str, package_name: &str, version: &str) -> bool {
    let Ok(parsed) = Url::parse(resolved) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed
            .host_str()
            .is_none_or(|host| !host.eq_ignore_ascii_case("registry.npmjs.org"))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return false;
    }
    let Some(segments) = parsed.path_segments() else {
        return false;
    };
    let Some(segments) = segments
        .map(npm_percent_decode_path_component)
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let tarball_name = package_name
        .rsplit_once('/')
        .map_or(package_name, |(_, name)| name);
    let expected_tarball = format!("{tarball_name}-{version}.tgz");
    match segments.as_slice() {
        [name, separator, tarball] => {
            name == package_name && separator == "-" && tarball == &expected_tarball
        }
        [scope, name, separator, tarball] => {
            package_name == format!("{scope}/{name}")
                && separator == "-"
                && tarball == &expected_tarball
        }
        _ => false,
    }
}

fn npm_lock_report_coordinate(resolved: &str) -> String {
    let credential_shaped = |value: &str| {
        value.split('/').any(|segment| {
            let decoded =
                npm_percent_decode_path_component(segment).unwrap_or_else(|| segment.to_owned());
            decoded
                .rsplit_once('@')
                .is_some_and(|(userinfo, host)| userinfo.contains(':') && !host.is_empty())
        })
    };
    let raw_without_secrets = || {
        let secret = resolved.find(['?', '#']).unwrap_or(resolved.len());
        let sanitized = &resolved[..secret];
        if sanitized.trim().is_empty() || credential_shaped(sanitized) {
            "[redacted-source]".to_owned()
        } else {
            sanitized.to_owned()
        }
    };
    if resolved.starts_with("git@") && resolved.contains(':') {
        return raw_without_secrets();
    }
    let Ok(mut parsed) = Url::parse(resolved) else {
        return raw_without_secrets();
    };
    if credential_shaped(parsed.path())
        || (parsed.cannot_be_a_base() && parsed.path().contains('@'))
    {
        return "[redacted-source]".to_owned();
    }
    if !parsed.username().is_empty() {
        let _ = parsed.set_username("");
    }
    if parsed.password().is_some() {
        let _ = parsed.set_password(None);
    }
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

fn npm_declared_local_target(descriptor: &str, specification: &str) -> Option<String> {
    let local = ["file:", "link:"]
        .into_iter()
        .find_map(|prefix| {
            specification
                .get(..prefix.len())
                .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
                .map(|_| &specification[prefix.len()..])
        })
        .or_else(|| {
            specification
                .starts_with(['.', '/'])
                .then_some(specification)
        })?;
    let local = local.replace('\\', "/");
    if local.is_empty()
        || local.starts_with('/')
        || local.contains(['?', '#', '\0'])
        || local.contains("://")
    {
        return None;
    }

    let mut segments = descriptor
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for segment in local.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.last().is_some_and(|segment| segment != "..") {
                    segments.pop();
                } else {
                    segments.push("..".to_owned());
                }
            }
            value => segments.push(value.to_owned()),
        }
    }
    (!segments.is_empty()).then(|| segments.join("/"))
}

#[derive(Default)]
struct NpmDependencyDeclaration {
    nonregistry: bool,
    nonregistry_specification: Option<String>,
    registry_identity: Option<String>,
    registry_constraint: Option<String>,
}

#[derive(Default)]
struct NpmDependencyDeclarations {
    nonregistry: bool,
    nonregistry_specifications: BTreeMap<String, String>,
    registry_identities: BTreeMap<String, String>,
    registry_constraints: BTreeMap<String, String>,
}

impl NpmDependencyDeclarations {
    fn has_registry_declaration(&self) -> bool {
        !self.registry_identities.is_empty()
    }

    fn registry_identity_matches(&self, package_name: &str) -> bool {
        self.registry_identities
            .values()
            .all(|identity| identity == package_name)
    }

    fn non_root_registry_identity_matches(&self, package_name: &str) -> bool {
        self.registry_identities
            .iter()
            .filter(|(descriptor, _)| !descriptor.is_empty())
            .all(|(_, identity)| identity == package_name)
    }

    fn validate_non_root_registry_constraints(&self, version: &str) -> Result<(), String> {
        for (descriptor, constraint) in self
            .registry_constraints
            .iter()
            .filter(|(descriptor, _)| !descriptor.is_empty())
        {
            match latest_matching_version(Ecosystem::Npm, constraint, [version]) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Err(format!(
                        "dependency constraint {constraint:?} from descriptor {descriptor:?} does not accept linked workspace version {version:?}"
                    ));
                }
                Err(error) => {
                    return Err(format!(
                        "dependency constraint {constraint:?} from descriptor {descriptor:?} cannot safely validate linked workspace version {version:?}: {error}"
                    ));
                }
            }
        }
        Ok(())
    }

    fn has_non_root_registry_constraints(&self) -> bool {
        self.registry_constraints
            .keys()
            .any(|descriptor| !descriptor.is_empty())
    }

    fn validate_nonregistry_sources(
        &self,
        target: &str,
        proven_workspace_identity: bool,
    ) -> Result<(), String> {
        for (descriptor, specification) in &self.nonregistry_specifications {
            if descriptor.is_empty() && proven_workspace_identity {
                continue;
            }
            if specification
                .get(..10)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("workspace:"))
            {
                if proven_workspace_identity {
                    continue;
                }
                return Err(format!(
                    "workspace dependency source {specification:?} from descriptor {descriptor:?} cannot resolve to non-workspace link target {target:?}"
                ));
            }
            if npm_declared_local_target(descriptor, specification).as_deref() == Some(target) {
                continue;
            }
            return Err(format!(
                "non-registry dependency source {specification:?} from descriptor {descriptor:?} does not resolve to linked target {target:?}"
            ));
        }
        Ok(())
    }

    fn merge(&mut self, descriptor: &str, other: NpmDependencyDeclaration) {
        self.nonregistry |= other.nonregistry;
        if let Some(specification) = other.nonregistry_specification {
            self.nonregistry_specifications
                .insert(descriptor.to_owned(), specification);
        }
        if let Some(identity) = other.registry_identity {
            self.registry_identities
                .insert(descriptor.to_owned(), identity);
        }
        if let Some(constraint) = other.registry_constraint {
            self.registry_constraints
                .insert(descriptor.to_owned(), constraint);
        }
    }
}

#[derive(Default)]
struct NpmLockDeclarations {
    by_install_location: HashMap<String, NpmDependencyDeclarations>,
    direct_locations: BTreeSet<String>,
    reachable_locations: BTreeSet<String>,
}

impl NpmLockDeclarations {
    fn selected(&self, install_location: &str) -> Option<&NpmDependencyDeclarations> {
        self.by_install_location.get(install_location)
    }

    fn directness(&self, install_location: &str) -> Option<bool> {
        if self.direct_locations.contains(install_location) {
            Some(true)
        } else if self.reachable_locations.contains(install_location) {
            Some(false)
        } else {
            None
        }
    }
}

fn npm_dependency_install_location<'a>(
    descriptor: &str,
    name: &str,
    package_entries: &'a serde_json::Map<String, Json>,
) -> Option<&'a str> {
    let mut segments = if descriptor.is_empty() {
        Vec::new()
    } else {
        let segments = descriptor.split('/').collect::<Vec<_>>();
        if segments.iter().any(|segment| segment.is_empty()) {
            return None;
        }
        segments
    };

    loop {
        if segments.last().copied() != Some("node_modules") {
            let candidate = if segments.is_empty() {
                format!("node_modules/{name}")
            } else {
                format!("{}/node_modules/{name}", segments.join("/"))
            };
            if let Some((location, _)) = package_entries.get_key_value(&candidate) {
                return Some(location);
            }
        }
        segments.pop()?;
    }
}

struct NpmWorkspacePattern {
    source: String,
    matcher: NpmMinimatch,
}

#[derive(Default)]
struct NpmWorkspacePatterns {
    included: Vec<NpmWorkspacePattern>,
    excluded: Vec<NpmWorkspacePattern>,
}

fn npm_lock_workspace_patterns(
    path: &Path,
    package_entries: &serde_json::Map<String, Json>,
) -> Result<NpmWorkspacePatterns, ParseError> {
    let Some(root) = package_entries.get("").and_then(Json::as_object) else {
        return Ok(NpmWorkspacePatterns::default());
    };
    let Some(workspaces) = root.get("workspaces") else {
        return Ok(NpmWorkspacePatterns::default());
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
                        "npm lock root workspaces object must contain a packages array",
                    )
                })?
        }
        _ => {
            return Err(invalid(
                path,
                "npm lock root workspaces must be an array or object containing a packages array",
            ));
        }
    };
    if entries.len() > MAX_WORKSPACE_PATTERNS {
        return Err(invalid(
            path,
            format!("npm lock root workspaces exceeds the {MAX_WORKSPACE_PATTERNS}-pattern limit"),
        ));
    }
    let mut patterns = NpmWorkspacePatterns::default();
    for (index, entry) in entries.iter().enumerate() {
        let raw = entry
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                invalid(
                    path,
                    format!("npm lock root workspace entry {index} must be a non-empty string"),
                )
            })?;
        let bang_count = raw.bytes().take_while(|byte| *byte == b'!').count();
        let excluded = bang_count % 2 == 1;
        let normalized_separators = raw[bang_count..].replace('\\', "/");
        // npm map-workspaces applies exactly `/^\.?\/+/'` once. In
        // particular, `.//packages/*` becomes `packages/*`, while
        // `././packages/*` becomes `./packages/*` and must not be simplified
        // again into a broader workspace proof.
        let normalized = normalized_separators
            .strip_prefix('.')
            .filter(|suffix| suffix.starts_with('/'))
            .map_or_else(
                || normalized_separators.trim_start_matches('/'),
                |suffix| suffix.trim_start_matches('/'),
            );
        let normalized = normalized.trim_end_matches('/');
        let relative = Path::new(normalized);
        if normalized.is_empty()
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
                format!("npm lock root workspace pattern {raw:?} must remain within the project"),
            ));
        }
        let matcher = NpmMinimatch::compile(normalized).map_err(|error| {
            invalid(
                path,
                format!("invalid npm workspace pattern {raw:?}: {error}"),
            )
        })?;
        let pattern = NpmWorkspacePattern {
            source: normalized.to_owned(),
            matcher,
        };
        if excluded {
            patterns.excluded.push(pattern);
        } else {
            // npm removes an earlier exclusion only when this positive
            // pattern is itself selected by that exclusion. A later
            // broad include therefore does not accidentally re-include
            // a specifically excluded workspace.
            let mut negative_index = 0usize;
            while negative_index < patterns.excluded.len() {
                let negative = &patterns.excluded[negative_index];
                let selected = negative.matcher.is_match(normalized).map_err(|error| {
                    invalid(
                        path,
                        format!(
                            "npm workspace pattern {:?} could not evaluate positive pattern {normalized:?}: {error}",
                            negative.source
                        ),
                    )
                })?;
                if selected {
                    // npm's map-workspaces mutates the negative list with
                    // splice while incrementing the loop index. Preserve
                    // that observable ordering: the entry shifted into this
                    // slot is intentionally not reconsidered.
                    patterns.excluded.remove(negative_index);
                }
                negative_index += 1;
            }
            patterns.included.push(pattern);
        }
    }
    for negative in &patterns.excluded {
        let mut retained = Vec::with_capacity(patterns.included.len());
        for positive in patterns.included.drain(..) {
            let selected = negative
                .matcher
                .is_match(positive.source.as_str())
                .map_err(|error| {
                    invalid(
                        path,
                        format!(
                            "npm workspace exclusion {:?} could not evaluate positive pattern {:?}: {error}",
                            negative.source, positive.source
                        ),
                    )
                })?;
            if !selected {
                retained.push(positive);
            }
        }
        patterns.included = retained;
    }
    Ok(patterns)
}

fn npm_is_workspace_descriptor(
    path: &Path,
    location: &str,
    patterns: &NpmWorkspacePatterns,
) -> Result<bool, ParseError> {
    if location.is_empty()
        || location
            .split('/')
            .any(|segment| matches!(segment, "" | "." | ".." | "node_modules"))
    {
        return Ok(false);
    }
    let mut excluded = false;
    for pattern in &patterns.excluded {
        if pattern.matcher.is_match(location).map_err(|error| {
            invalid(
                path,
                format!(
                    "npm workspace exclusion {:?} could not evaluate package location {location:?}: {error}",
                    pattern.source
                ),
            )
        })? {
            excluded = true;
            break;
        }
    }
    let mut included = false;
    for pattern in &patterns.included {
        if pattern.matcher.is_match(location).map_err(|error| {
            invalid(
                path,
                format!(
                    "npm workspace pattern {:?} could not evaluate package location {location:?}: {error}",
                    pattern.source
                ),
            )
        })? {
            included = true;
            break;
        }
    }
    Ok(!excluded && included)
}

fn parse_npm_lock_declaration(
    path: &Path,
    location: &str,
    name: &str,
    specification: &str,
) -> Result<NpmDependencyDeclaration, ParseError> {
    let mut declaration = NpmDependencyDeclaration::default();
    if let Some(alias) = npm_alias_reference(specification) {
        let (target, constraint) = npm_alias_parts(alias).map_err(|error| {
            invalid(
                path,
                format!(
                    "npm package entry {location:?} dependency alias {name:?} has an invalid npm target: {error}"
                ),
            )
        })?;
        declaration.registry_identity = Some(target.to_owned());
        declaration.registry_constraint = Some(constraint.to_owned());
    } else if npm_lock_declared_nonregistry(specification) {
        declaration.nonregistry = true;
        declaration.nonregistry_specification = Some(specification.to_owned());
    } else {
        declaration.registry_identity = Some(name.to_owned());
        declaration.registry_constraint = Some(specification.to_owned());
    }
    Ok(declaration)
}

fn npm_lock_declarations(
    path: &Path,
    package_entries: &serde_json::Map<String, Json>,
    workspace_patterns: &NpmWorkspacePatterns,
) -> Result<NpmLockDeclarations, ParseError> {
    let mut declarations = NpmLockDeclarations::default();
    let mut dependency_edges = BTreeMap::<String, BTreeSet<String>>::new();
    for (location, entry) in package_entries {
        let entry = entry.as_object().ok_or_else(|| {
            invalid(
                path,
                format!("npm package entry {location:?} must be an object"),
            )
        })?;
        if npm_lock_optional_bool(path, location, entry, "link")? == Some(true) {
            continue;
        }
        if !location.is_empty()
            && npm_package_location(location).is_none()
            && !npm_is_workspace_descriptor(path, location, workspace_patterns)?
        {
            // npm may snapshot an external file/link target's package metadata,
            // but its dependency graph is not installed into the scanned root.
            continue;
        }
        let project_descriptor =
            location.is_empty() || npm_is_workspace_descriptor(path, location, workspace_patterns)?;
        let mut effective = BTreeMap::new();
        // npm Arborist loads peer, production, optional, then development
        // edges; a later group replaces an earlier same-name edge. Development
        // edges are active only for the root and workspace project nodes.
        for group in [
            "peerDependencies",
            "dependencies",
            "optionalDependencies",
            "devDependencies",
        ] {
            if group == "devDependencies" && !project_descriptor {
                continue;
            }
            let Some(dependencies) = entry.get(group) else {
                continue;
            };
            let dependencies = dependencies.as_object().ok_or_else(|| {
                invalid(
                    path,
                    format!("npm package entry {location:?} field {group:?} must be an object"),
                )
            })?;
            for (name, specification) in dependencies {
                validate_bun_package_name(name).map_err(|error| {
                    invalid(
                        path,
                        format!(
                            "npm package entry {location:?} has an invalid dependency name {name:?}: {error}"
                        ),
                    )
                })?;
                let specification = specification
                    .as_str()
                    .filter(|specification| !specification.trim().is_empty())
                    .ok_or_else(|| {
                        invalid(
                            path,
                            format!(
                                "npm package entry {location:?} dependency {name:?} in {group:?} must have a non-empty string specification"
                            ),
                        )
                })?;
                let parsed = parse_npm_lock_declaration(path, location, name, specification)?;
                effective.insert(
                    name.clone(),
                    (
                        parsed,
                        matches!(group, "dependencies" | "devDependencies"),
                        group,
                    ),
                );
            }
        }
        for (name, (parsed, required, group)) in effective {
            if let Some(install_location) =
                npm_dependency_install_location(location, &name, package_entries)
            {
                declarations
                    .by_install_location
                    .entry(install_location.to_owned())
                    .or_default()
                    .merge(location, parsed);
                if project_descriptor {
                    declarations
                        .direct_locations
                        .insert(install_location.to_owned());
                } else {
                    dependency_edges
                        .entry(location.to_owned())
                        .or_default()
                        .insert(install_location.to_owned());
                }
            } else if required {
                return Err(invalid(
                    path,
                    format!(
                        "npm package entry {location:?} required dependency {name:?} in {group:?} has no installed package record"
                    ),
                ));
            }
        }
    }

    let mut pending = declarations
        .direct_locations
        .iter()
        .cloned()
        .collect::<VecDeque<_>>();
    declarations
        .reachable_locations
        .clone_from(&declarations.direct_locations);
    while let Some(location) = pending.pop_front() {
        let Some(children) = dependency_edges.get(&location) else {
            continue;
        };
        for child in children {
            if declarations.reachable_locations.insert(child.clone()) {
                pending.push_back(child.clone());
            }
        }
    }
    Ok(declarations)
}

fn npm_lock_link_target(
    path: &Path,
    location: &str,
    entry: &serde_json::Map<String, Json>,
) -> Result<String, ParseError> {
    let target = entry
        .get("resolved")
        .and_then(Json::as_str)
        .filter(|target| !target.trim().is_empty())
        .ok_or_else(|| {
            invalid(
                path,
                format!(
                    "npm link package entry {location:?} must have a non-empty string resolved target"
                ),
            )
        })?;
    let target = target.strip_prefix("./").unwrap_or(target);
    if target.is_empty() || target == "." {
        return Err(invalid(
            path,
            format!(
                "npm link package entry {location:?} resolved target {target:?} must identify a local descriptor or installed package record"
            ),
        ));
    }
    Ok(target.to_owned())
}

fn npm_descriptor_fallback_name(target: &str) -> Option<String> {
    let segments = target.split('/').collect::<Vec<_>>();
    if segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }
    let name = *segments.last()?;
    if matches!(name, "." | ".." | "node_modules") {
        return None;
    }
    let fallback = match segments.iter().rev().nth(1) {
        Some(scope) if scope.starts_with('@') => format!("{scope}/{name}"),
        _ => name.to_owned(),
    };
    validate_bun_package_name(&fallback).ok()?;
    Some(fallback)
}

fn parse_package_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
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
            let root = path.parent().unwrap_or(Path::new("."));
            let direct = node_direct_dependencies(root);
            let dependencies = document
                .get("dependencies")
                .and_then(Json::as_object)
                .ok_or_else(|| {
                    invalid(
                        path,
                        "detected npm package-lock.json version 1 without a dependencies object; expected the legacy dependency tree",
                    )
                })?;
            parse_legacy_npm_tree(dependencies, path, &direct, true, &mut packages);
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

            // First validate link records without using them to suppress any
            // installed package. Declaration provenance is resolved only after
            // every concrete link target has been validated.
            let mut link_targets = BTreeMap::new();
            for (key, value) in package_entries {
                let entry = value.as_object().ok_or_else(|| {
                    invalid(path, format!("npm package entry {key:?} must be an object"))
                })?;
                npm_lock_optional_bool(path, key, entry, "dev")?;
                if let Some(resolved) = entry.get("resolved")
                    && resolved
                        .as_str()
                        .filter(|resolved| !resolved.trim().is_empty())
                        .is_none()
                {
                    return Err(invalid(
                        path,
                        format!(
                            "npm package entry {key:?} field \"resolved\" must be a non-empty string"
                        ),
                    ));
                }
                if npm_lock_optional_bool(path, key, entry, "link")? == Some(true) {
                    if let Some(field) = [
                        "name",
                        "version",
                        "dependencies",
                        "optionalDependencies",
                        "peerDependencies",
                        "devDependencies",
                    ]
                    .into_iter()
                    .find(|field| entry.contains_key(*field))
                    {
                        return Err(invalid(
                            path,
                            format!(
                                "npm link package entry {key:?} must not contain package metadata field {field:?}; metadata belongs on its resolved descriptor"
                            ),
                        ));
                    }
                    let location = npm_package_location(key).ok_or_else(|| {
                        invalid(
                            path,
                            format!(
                                "npm link package entry {key:?} is not a valid node_modules install location"
                            ),
                        )
                    })?;
                    if !location.install_parent_key.is_empty()
                        && package_entries
                            .get(&location.install_parent_key)
                            .and_then(Json::as_object)
                            .is_none()
                    {
                        return Err(invalid(
                            path,
                            format!(
                                "npm link package entry {key:?} has unproven install prefix {:?}; the parent package or workspace descriptor is missing",
                                location.install_parent_key
                            ),
                        ));
                    }
                    validate_bun_package_name(&location.name).map_err(|error| {
                        invalid(
                            path,
                            format!("npm link package entry {key:?} has an invalid name: {error}"),
                        )
                    })?;
                    let target = npm_lock_link_target(path, key, entry)?;
                    let Some(target_entry) = package_entries.get(&target).and_then(Json::as_object)
                    else {
                        return Err(invalid(
                            path,
                            format!(
                                "npm link package entry {key:?} resolved target {target:?} does not name an existing package descriptor object"
                            ),
                        ));
                    };
                    if target == key.as_str()
                        || npm_lock_optional_bool(path, &target, target_entry, "link")?
                            == Some(true)
                    {
                        return Err(invalid(
                            path,
                            format!(
                                "npm link package entry {key:?} resolved target {target:?} must not be itself or another link record"
                            ),
                        ));
                    }
                    if npm_package_location(&target).is_none()
                        && target.split('/').any(|segment| segment == "node_modules")
                    {
                        return Err(invalid(
                            path,
                            format!(
                                "npm link package entry {key:?} resolved target {target:?} is not a valid installed package location"
                            ),
                        ));
                    }
                    link_targets.insert(key.clone(), target);
                }
            }
            let workspace_patterns = npm_lock_workspace_patterns(path, package_entries)?;
            let declarations = npm_lock_declarations(path, package_entries, &workspace_patterns)?;
            let mut local_descriptors = BTreeSet::new();
            for (key, target) in &link_targets {
                let location = npm_package_location(key).expect("validated npm link location");
                let target_entry = package_entries
                    .get(target)
                    .and_then(Json::as_object)
                    .expect("validated npm link target object");
                let target_name = match target_entry.get("name") {
                    None => npm_descriptor_fallback_name(target).ok_or_else(|| {
                        invalid(
                            path,
                            format!(
                                "npm local descriptor {target:?} has no valid fallback package identity"
                            ),
                        )
                    })?,
                    Some(Json::String(name)) if !name.trim().is_empty() => name.clone(),
                    Some(_) => {
                        return Err(invalid(
                            path,
                            format!(
                                "npm workspace descriptor {target:?} field \"name\" must be a non-empty string when present"
                            ),
                        ));
                    }
                };
                validate_bun_package_name(&target_name).map_err(|error| {
                    invalid(
                        path,
                        format!(
                            "npm workspace descriptor {target:?} has invalid package name {target_name:?}: {error}"
                        ),
                    )
                })?;
                let target_version = match target_entry.get("version") {
                    None => None,
                    Some(Json::String(version)) if !version.trim().is_empty() => {
                        Some(version.as_str())
                    }
                    Some(_) => {
                        return Err(invalid(
                            path,
                            format!(
                                "npm workspace descriptor {target:?} field \"version\" must be a non-empty string when present"
                            ),
                        ));
                    }
                };
                let target_is_installed = npm_package_location(target).is_some();
                let proven_workspace_identity = !target_is_installed
                    && npm_is_workspace_descriptor(path, target, &workspace_patterns)?
                    && target_name == location.name;
                let declaration = declarations.selected(key);
                if let Some(declaration) = declaration {
                    declaration
                        .validate_nonregistry_sources(target, proven_workspace_identity)
                        .map_err(|error| {
                            invalid(
                                path,
                                format!(
                                    "npm link package entry {key:?} cannot satisfy its non-registry declaration with target {target:?}: {error}"
                                ),
                            )
                        })?;
                }
                if let Some(declaration) = declaration
                    && declaration.has_registry_declaration()
                    && !(proven_workspace_identity
                        && declaration.non_root_registry_identity_matches(&target_name))
                {
                    return Err(invalid(
                        path,
                        format!(
                            "npm link package entry {key:?} replaces a registry declaration with unproven local target {target:?}"
                        ),
                    ));
                }
                if proven_workspace_identity
                    && let Some(declaration) = declaration
                    && declaration.has_non_root_registry_constraints()
                {
                    let target_version = target_version.ok_or_else(|| {
                            invalid(
                                path,
                                format!(
                                    "npm workspace descriptor {target:?} must have a non-empty string version to satisfy non-root registry declarations"
                                ),
                            )
                        })?;
                    declaration
                        .validate_non_root_registry_constraints(target_version)
                        .map_err(|error| {
                            invalid(
                                path,
                                format!(
                                    "npm link package entry {key:?} cannot satisfy its registry declaration with workspace target {target:?}: {error}"
                                ),
                            )
                        })?;
                }
                if !target_is_installed
                    && !proven_workspace_identity
                    && declaration.is_none_or(|declaration| !declaration.nonregistry)
                {
                    return Err(invalid(
                        path,
                        format!(
                            "npm link package entry {key:?} has no matching workspace identity or explicit non-registry declaration for target {target:?}"
                        ),
                    ));
                }
                if npm_package_location(target).is_none() {
                    local_descriptors.insert(target.clone());
                }
            }

            for (key, entry) in package_entries {
                let entry = entry.as_object().expect("packages map validated above");
                if key.is_empty() || local_descriptors.contains(key) {
                    continue;
                }
                if npm_lock_optional_bool(path, key, entry, "link")? == Some(true) {
                    continue;
                }

                let location = npm_package_location(key).ok_or_else(|| {
                    invalid(
                        path,
                        format!(
                            "npm package entry {key:?} is neither a linked local descriptor nor a valid node_modules install location"
                        ),
                    )
                })?;
                if !location.install_parent_key.is_empty()
                    && package_entries
                        .get(&location.install_parent_key)
                        .and_then(Json::as_object)
                        .is_none()
                {
                    return Err(invalid(
                        path,
                        format!(
                            "npm package entry {key:?} has unproven install prefix {:?}; the parent package or workspace descriptor is missing",
                            location.install_parent_key
                        ),
                    ));
                }
                validate_bun_package_name(&location.name).map_err(|error| {
                    invalid(
                        path,
                        format!("npm package entry {key:?} has an invalid name: {error}"),
                    )
                })?;

                let resolved = entry.get("resolved");
                if let Some(resolved) = resolved
                    && resolved
                        .as_str()
                        .filter(|resolved| !resolved.trim().is_empty())
                        .is_none()
                {
                    return Err(invalid(
                        path,
                        format!(
                            "npm package entry {key:?} field \"resolved\" must be a non-empty string"
                        ),
                    ));
                }
                let resolved = resolved.and_then(Json::as_str);
                let resolved_source = npm_lock_resolved_source(resolved).map_err(|error| {
                    invalid(
                        path,
                        format!(
                            "npm package entry {key:?} has an unsupported or malformed resolved source: {error}"
                        ),
                    )
                })?;
                let declaration = declarations.selected(key);
                let version_source_locator = entry
                    .get("version")
                    .and_then(Json::as_str)
                    .is_some_and(npm_lock_source_locator);
                if version_source_locator {
                    let version_source = entry
                        .get("version")
                        .and_then(Json::as_str)
                        .expect("version source locator came from a string version");
                    npm_lock_resolved_source(Some(version_source)).map_err(|error| {
                        invalid(
                            path,
                            format!(
                                "npm package entry {key:?} has an unsupported or malformed version source: {error}"
                            ),
                        )
                    })?;
                }
                let explicit_nonregistry = resolved_source == NpmResolvedSource::Nonregistry
                    || version_source_locator
                    || declaration.is_some_and(|declaration| declaration.nonregistry);
                let dev = npm_lock_optional_bool(path, key, entry, "dev")?.unwrap_or(false);
                let package_name = entry.get("name").map_or(Ok(location.name.as_str()), |name| {
                    name.as_str()
                        .filter(|name| !name.trim().is_empty())
                        .ok_or_else(|| {
                            invalid(
                                path,
                                format!(
                                    "npm package entry {key:?} field \"name\" must be a non-empty string"
                                ),
                            )
                        })
                })?;
                validate_bun_package_name(package_name).map_err(|error| {
                    invalid(
                        path,
                        format!("npm package entry {key:?} has an invalid name: {error}"),
                    )
                })?;
                let identity_declared = declaration
                    .map_or(package_name == location.name, |value| {
                        value.registry_identity_matches(package_name)
                    });
                let identity_must_match = !explicit_nonregistry
                    || declaration.is_some_and(|value| value.has_registry_declaration());
                if identity_must_match && !identity_declared {
                    let registry_identities = declaration.map(|value| &value.registry_identities);
                    return Err(invalid(
                        path,
                        format!(
                            "npm alias package entry {key:?} has identity {package_name:?}, which is inconsistent with its registry declarations {registry_identities:?}"
                        ),
                    ));
                }

                let publicly_enrichable_origin =
                    matches!(resolved_source, NpmResolvedSource::PublicRegistry)
                        && !version_source_locator
                        && declaration.is_none_or(|value| {
                            !value.nonregistry
                                || (value.has_registry_declaration()
                                    && value.registry_identity_matches(package_name))
                        });

                let version = match entry.get("version") {
                    Some(Json::String(version)) if !version.is_empty() => {
                        if version_source_locator
                            || (explicit_nonregistry && semver::Version::parse(version).is_err())
                        {
                            npm_lock_report_coordinate(version)
                        } else {
                            version.clone()
                        }
                    }
                    Some(_) => {
                        return Err(invalid(
                            path,
                            format!(
                                "npm package entry {key:?} field \"version\" must be a non-empty string"
                            ),
                        ));
                    }
                    None if explicit_nonregistry => {
                        npm_lock_report_coordinate(resolved.ok_or_else(|| {
                            invalid(
                                path,
                                format!(
                                    "npm non-registry package entry {key:?} has neither a version nor a resolved source coordinate"
                                ),
                            )
                        })?)
                    }
                    None => {
                        return Err(invalid(
                            path,
                            format!(
                                "npm package entry {key:?} must have a non-empty string version"
                            ),
                        ));
                    }
                };

                let enrichable = match semver::Version::parse(&version) {
                    Ok(_) if publicly_enrichable_origin => {
                        let resolved = resolved.expect("public npm origin has a resolved URL");
                        if !npm_public_tarball_matches(resolved, package_name, &version) {
                            return Err(invalid(
                                path,
                                format!(
                                    "npm package entry {key:?} public registry tarball URL does not match package {package_name:?} version {version:?}"
                                ),
                            ));
                        }
                        true
                    }
                    Ok(_) => false,
                    Err(_) if explicit_nonregistry => false,
                    Err(_) if npm_lock_source_locator(&version) => false,
                    Err(error) => {
                        return Err(invalid(
                            path,
                            format!(
                                "npm package entry {key:?} has invalid registry SemVer version {version:?}: {error}"
                            ),
                        ));
                    }
                };
                let mut package =
                    Package::new(Ecosystem::Npm, package_name, &version, path.to_path_buf());
                if let Some(direct) = declarations.directness(key) {
                    package.direct = direct;
                    package.direct_known = true;
                } else {
                    package.direct_known = false;
                }
                package.dev = dev;
                package.enrichable = enrichable;
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
    direct: &NodeDirectDependencies,
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
            let parsed_version = semver::Version::parse(version);
            let report_version = if parsed_version.is_err() {
                npm_lock_report_coordinate(version)
            } else {
                version.to_owned()
            };
            let mut package =
                Package::new(Ecosystem::Npm, name, &report_version, path.to_path_buf());
            if top_level {
                match direct.directness(name) {
                    Some(is_direct) => package.direct = is_direct,
                    None => package.direct_known = false,
                }
            }
            package.dev = entry.get("dev").and_then(Json::as_bool).unwrap_or(false);
            package.enrichable = parsed_version.is_ok()
                && !npm_lock_source_locator(version)
                && matches!(
                    npm_lock_resolved_source(entry.get("resolved").and_then(Json::as_str)),
                    Ok(NpmResolvedSource::PublicRegistry)
                );
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
    let direct_references = pnpm_direct_references(&value, packages);
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
            .transpose()?;
        let exact_locator = key.trim_start_matches('/');
        let mut package = Package::new(Ecosystem::Npm, name, version, path.to_path_buf());
        package.dev = dev.unwrap_or(false);
        package.dev_known = dev.is_some();
        if let Some(direct) = direct_references.get(exact_locator) {
            package.direct = true;
            package.direct_known = true;
            package.dev = direct.development && !direct.production;
            package.dev_known = true;
            if let Some(display_alias) = direct.display_alias() {
                package.display_name = display_alias.to_owned();
            }
        } else {
            package.direct_known = false;
        }
        out.push(package);
    }
    Ok(dedup(out))
}

#[derive(Default)]
struct PnpmDirectReference {
    production: bool,
    development: bool,
    canonical: bool,
    aliases: BTreeSet<String>,
}

impl PnpmDirectReference {
    fn display_alias(&self) -> Option<&str> {
        (!self.canonical && self.aliases.len() == 1)
            .then(|| self.aliases.first().map(String::as_str))
            .flatten()
    }

    fn merge(&mut self, other: Self) {
        self.production |= other.production;
        self.development |= other.development;
        self.canonical |= other.canonical;
        self.aliases.extend(other.aliases);
    }
}

fn pnpm_direct_references(
    value: &Yaml,
    packages: &noyalib::Mapping,
) -> BTreeMap<String, PnpmDirectReference> {
    let mut requested = BTreeMap::new();
    if let Some(importers) = value.get("importers").and_then(Yaml::as_mapping) {
        for importer in importers.values().filter_map(Yaml::as_mapping) {
            append_pnpm_importer_references(importer, &mut requested);
        }
    }

    // pnpm v6 uses these document-level dependency groups for a non-workspace project.
    if value.get("importers").is_none()
        && let Some(root) = value.as_mapping()
    {
        append_pnpm_importer_references(root, &mut requested);
    }

    let package_locators = packages
        .keys()
        .map(|locator| locator.trim_start_matches('/').to_owned())
        .collect::<BTreeSet<_>>();
    let snapshot_locators = value
        .get("snapshots")
        .and_then(Yaml::as_mapping)
        .into_iter()
        .flat_map(|snapshots| snapshots.iter())
        .filter(|(_, snapshot)| snapshot.as_mapping().is_some())
        .map(|(locator, _)| locator.trim_start_matches('/').to_owned())
        .collect::<BTreeSet<_>>();

    let mut direct = BTreeMap::<String, PnpmDirectReference>::new();
    for (resolved_locator, reference) in requested {
        let package_locator = if package_locators.contains(&resolved_locator) {
            Some(resolved_locator)
        } else if snapshot_locators.contains(&resolved_locator) {
            parse_pnpm_key(&resolved_locator).map(|(name, version)| format!("{name}@{version}"))
        } else {
            None
        };
        let Some(package_locator) =
            package_locator.filter(|locator| package_locators.contains(locator))
        else {
            continue;
        };
        direct.entry(package_locator).or_default().merge(reference);
    }
    direct
}

fn append_pnpm_importer_references(
    importer: &noyalib::Mapping,
    direct: &mut BTreeMap<String, PnpmDirectReference>,
) {
    for (group, development) in [
        ("dependencies", false),
        ("optionalDependencies", false),
        ("peerDependencies", false),
        ("devDependencies", true),
    ] {
        let Some(dependencies) = importer.get(group).and_then(Yaml::as_mapping) else {
            continue;
        };
        for (declared_name, dependency) in dependencies {
            let Some(version) = pnpm_importer_version(dependency) else {
                continue;
            };
            let Some((locator, package_name)) = pnpm_resolved_locator(declared_name, version)
            else {
                continue;
            };
            let reference = direct.entry(locator).or_default();
            if development {
                reference.development = true;
            } else {
                reference.production = true;
            }
            if package_name != declared_name.as_str() {
                reference.aliases.insert(declared_name.clone());
            } else {
                reference.canonical = true;
            }
        }
    }
}

fn pnpm_importer_version(dependency: &Yaml) -> Option<&str> {
    dependency.as_str().or_else(|| {
        dependency
            .as_mapping()
            .and_then(|entry| entry.get("version"))
            .and_then(Yaml::as_str)
    })
}

fn pnpm_resolved_locator(declared_name: &str, resolved: &str) -> Option<(String, String)> {
    let resolved = resolved.trim_start_matches('/');
    if resolved.is_empty()
        || resolved.starts_with("file:")
        || resolved.starts_with("link:")
        || resolved.starts_with("workspace:")
        || resolved.starts_with("git+")
        || resolved.starts_with("github:")
        || resolved.starts_with("http://")
        || resolved.starts_with("https://")
    {
        return None;
    }

    let locator = if parse_pnpm_key(resolved).is_some() {
        resolved.to_owned()
    } else {
        format!("{declared_name}@{resolved}")
    };
    let (package_name, version) = parse_pnpm_key(&locator)?;
    validate_bun_package_name(package_name).ok()?;
    semver::Version::parse(version).ok()?;
    let package_name = package_name.to_owned();
    Some((locator, package_name))
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

type YarnSemverBounds = ((u64, u64, u64), (u64, u64, u64));

fn yarn_caret_bounds(selector: &str) -> Option<YarnSemverBounds> {
    let raw = selector.strip_prefix('^')?;
    let parts = raw
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let major = parts[0];
    let minor = parts.get(1).copied().unwrap_or(0);
    let patch = parts.get(2).copied().unwrap_or(0);
    let upper = if parts.len() == 1 || major > 0 {
        (major.checked_add(1)?, 0, 0)
    } else if parts.len() == 2 || minor > 0 {
        (0, minor.checked_add(1)?, 0)
    } else {
        (0, 0, patch.checked_add(1)?)
    };
    Some(((major, minor, patch), upper))
}

fn yarn_semver_selector_equivalent(left: &str, right: &str) -> bool {
    left == right
        || yarn_caret_bounds(left)
            .zip(yarn_caret_bounds(right))
            .is_some_and(|(left, right)| left == right)
}

fn yarn_npm_selector_equivalent(left: &str, right: &str) -> bool {
    if yarn_semver_selector_equivalent(left, right) {
        return true;
    }
    let (Ok(left), Ok(right)) = (parse_yarn_locator(left), parse_yarn_locator(right)) else {
        return false;
    };
    left.name == right.name && yarn_semver_selector_equivalent(left.reference, right.reference)
}

fn yarn_dependency_selector_matches(reference: &str, constraint: &str) -> bool {
    let reference = reference.split("::").next().unwrap_or(reference);
    if reference == constraint || reference.strip_prefix("npm:") == Some(constraint) {
        return true;
    }
    match (
        reference.strip_prefix("npm:"),
        constraint.strip_prefix("npm:"),
    ) {
        (Some(reference), Some(constraint)) => yarn_npm_selector_equivalent(reference, constraint),
        (Some(reference), None) => yarn_semver_selector_equivalent(reference, constraint),
        (None, Some(_)) => false,
        (None, None) => yarn_semver_selector_equivalent(reference, constraint),
    }
}

fn bind_yarn_direct_dependencies(
    direct: &YarnDirectDependencies,
    descriptor_groups: &[Vec<String>],
) -> Result<YarnDirectDependencies, String> {
    let mut bound = YarnDirectDependencies {
        by_name: direct.by_name.clone(),
    };
    for descriptors in descriptor_groups {
        let parsed = descriptors
            .iter()
            .map(|descriptor| parse_yarn_locator(descriptor))
            .collect::<Result<Vec<_>, _>>()?;
        let mut entry_matches = BTreeSet::new();
        for locator in parsed {
            if let Some(selectors) = bound.by_name.get(locator.name) {
                for (index, selector) in selectors.iter().enumerate() {
                    if yarn_dependency_selector_matches(locator.reference, &selector.constraint) {
                        entry_matches.insert((locator.name.to_owned(), index));
                    }
                }
            }
        }
        for (name, index) in entry_matches {
            bound
                .by_name
                .get_mut(&name)
                .expect("Yarn selector match came from an existing direct dependency")[index]
                .matching_entries += 1;
        }
    }
    Ok(bound)
}

fn yarn_direct_metadata(
    descriptors: &[String],
    registry_name: &str,
    direct: &YarnDirectDependencies,
) -> Result<(bool, bool, bool, bool, Option<String>), String> {
    let mut flags = YarnDirectness::default();
    let mut display_alias = None;
    for descriptor in descriptors {
        let locator = parse_yarn_locator(descriptor)?;
        if let Some(selectors) = direct.by_name.get(locator.name) {
            for selector in selectors {
                let selected = selector.matching_entries == 1
                    && yarn_dependency_selector_matches(locator.reference, &selector.constraint);
                if selected {
                    flags.production |= selector.directness.production;
                    flags.development |= selector.directness.development;
                    if locator.name != registry_name {
                        display_alias.get_or_insert_with(|| locator.name.to_owned());
                    }
                }
            }
        }
    }
    let is_direct = flags.production || flags.development;
    Ok((
        is_direct,
        is_direct,
        flags.development && !flags.production,
        is_direct,
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
    direct: &YarnDirectDependencies,
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

    let mut descriptor_groups = Vec::new();
    for (raw_key, _) in entries {
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
        descriptor_groups.push(descriptors);
    }
    let direct = bind_yarn_direct_dependencies(direct, &descriptor_groups)
        .map_err(|error| invalid(path, format!("invalid Yarn Berry descriptor: {error}")))?;

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
        let (is_direct, direct_known, is_dev, dev_known, display_alias) =
            yarn_direct_metadata(&descriptors, locator.name, &direct).map_err(|error| {
                invalid(
                    path,
                    format!("Yarn Berry entry {key:?} has invalid descriptor: {error}"),
                )
            })?;
        let mut package = Package::new(Ecosystem::Npm, locator.name, version, path.to_path_buf());
        package.direct = is_direct;
        package.direct_known = direct_known;
        package.dev = is_dev;
        package.dev_known = dev_known;
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
    direct: &YarnDirectDependencies,
) -> Result<Vec<Package>, ParseError> {
    let mut entries = Vec::new();
    let mut current: Option<YarnClassicEntry> = None;
    for (line_index, line) in text.lines().enumerate() {
        let line_number = line_index + 1;
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            if let Some(entry) = current.take() {
                entries.push(entry);
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
        entries.push(entry);
    }
    let descriptor_groups = entries
        .iter()
        .map(|entry| entry.descriptors.clone())
        .collect::<Vec<_>>();
    let direct = bind_yarn_direct_dependencies(direct, &descriptor_groups)
        .map_err(|error| invalid(path, format!("invalid Yarn Classic descriptor: {error}")))?;
    let mut packages = Vec::new();
    for entry in entries {
        push_yarn_classic_entry(path, entry, &direct, &mut packages)?;
    }
    Ok(dedup(packages))
}

fn push_yarn_classic_entry(
    path: &Path,
    entry: YarnClassicEntry,
    direct: &YarnDirectDependencies,
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
    let (is_direct, direct_known, is_dev, dev_known, display_alias) =
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
    package.direct_known = direct_known;
    package.dev = is_dev;
    package.dev_known = dev_known;
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

fn parse_package_json_text(path: &Path, text: &str) -> Result<Json, ParseError> {
    let value: Json = serde_json::from_str(text).map_err(|error| invalid(path, error))?;
    if !value.is_object() {
        return Err(invalid(
            path,
            "package.json must contain a JSON object at the document root",
        ));
    }
    Ok(value)
}

fn read_package_json(path: &Path) -> Result<Json, ParseError> {
    let text = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
    parse_package_json_text(path, &text)
}

fn validated_package_json_root(root_manifest: &Path) -> Result<(PathBuf, PathBuf), ParseError> {
    let metadata =
        fs::symlink_metadata(root_manifest).map_err(|error| io_error(root_manifest, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid(
            root_manifest,
            "root package.json must be a non-symlink regular file",
        ));
    }
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
    Ok((canonical_root, canonical_manifest))
}

fn read_validated_root_package_json(path: &Path) -> Result<Json, ParseError> {
    let (_, canonical_manifest) = validated_package_json_root(path)?;
    let mut file = fs::File::open(&canonical_manifest).map_err(|error| io_error(path, error))?;
    if !file
        .metadata()
        .map_err(|error| io_error(path, error))?
        .is_file()
    {
        return Err(invalid(path, "root package.json is not a regular file"));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| io_error(path, error))?;
    parse_package_json_text(path, &text)
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
    let (canonical_root, canonical_manifest) = validated_package_json_root(root_manifest)?;
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
            let metadata =
                fs::symlink_metadata(&candidate).map_err(|error| io_error(&candidate, error))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(invalid(
                    root_manifest,
                    format!(
                        "workspace manifest {} must be a non-symlink regular file",
                        candidate.display()
                    ),
                ));
            }
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
            if canonical_candidate != canonical_manifest {
                manifests.insert(canonical_candidate);
            }
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
    let root_value = read_validated_root_package_json(root_manifest)?;
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

const CARGO_CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[derive(Clone, Debug)]
enum CargoDependencySource {
    CratesIo,
    RegistryName,
    RegistryIndex(String),
    Git {
        url: String,
        selector: Option<(String, String)>,
    },
    Path,
}

#[derive(Clone, Debug)]
struct CargoDependencySpec {
    package_name: String,
    version: Option<String>,
    enrichable: bool,
    local_path: Option<PathBuf>,
    source: CargoDependencySource,
}

#[derive(Debug)]
struct CargoDeclaration {
    dependency: CargoDependencySpec,
    declaring_manifest: PathBuf,
    declaring_package: CargoProjectPackageId,
    dev: bool,
}

#[derive(Debug)]
struct CargoManifest {
    path: PathBuf,
    value: Toml,
    package: CargoProjectPackageId,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CargoProjectPackageId {
    name: String,
    version: String,
}

fn read_cargo_manifest(path: &Path) -> Result<Toml, ParseError> {
    let text = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
    toml::from_str(&text).map_err(|error| invalid(path, error))
}

fn cargo_workspace_package_version(
    path: &Path,
    value: &Toml,
) -> Result<Option<String>, ParseError> {
    let Some(version) = value
        .get("workspace")
        .and_then(Toml::as_table)
        .and_then(|workspace| workspace.get("package"))
        .and_then(Toml::as_table)
        .and_then(|package| package.get("version"))
    else {
        return Ok(None);
    };
    let version = version
        .as_str()
        .filter(|version| !version.is_empty())
        .ok_or_else(|| {
            invalid(
                path,
                "Cargo workspace package version must be a non-empty string",
            )
        })?;
    semver::Version::parse(version).map_err(|error| {
        invalid(
            path,
            format!("Cargo workspace package version {version:?} is invalid SemVer: {error}"),
        )
    })?;
    Ok(Some(version.to_owned()))
}

fn cargo_manifest_package_id(
    path: &Path,
    value: &Toml,
    workspace_version: Option<&str>,
) -> Result<CargoProjectPackageId, ParseError> {
    let package = value
        .get("package")
        .and_then(Toml::as_table)
        .ok_or_else(|| invalid(path, "Cargo workspace member is missing a [package] table"))?;
    let name = package
        .get("name")
        .and_then(Toml::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid(path, "Cargo package name must be a non-empty string"))?;
    let version = match package.get("version") {
        Some(Toml::String(version)) if !version.is_empty() => version.as_str(),
        Some(Toml::Table(version))
            if version.get("workspace").and_then(Toml::as_bool) == Some(true) =>
        {
            workspace_version.ok_or_else(|| {
                invalid(
                    path,
                    "Cargo package inherits version from missing [workspace.package].version",
                )
            })?
        }
        Some(_) => {
            return Err(invalid(
                path,
                "Cargo package version must be a non-empty string or inherit from the workspace",
            ));
        }
        None => "0.0.0",
    };
    semver::Version::parse(version).map_err(|error| {
        invalid(
            path,
            format!("Cargo package version {version:?} is invalid SemVer: {error}"),
        )
    })?;
    Ok(CargoProjectPackageId {
        name: name.to_owned(),
        version: version.to_owned(),
    })
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
            source: CargoDependencySource::CratesIo,
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
    let mut git_selector = None;
    for selector in ["branch", "tag", "rev"] {
        let value = dependency_field(manifest, alias, table, selector)?;
        if value.is_some() && git.is_none() {
            return Err(invalid(
                manifest,
                format!("Cargo dependency {alias:?} field {selector:?} requires a \"git\" source"),
            ));
        }
        if let Some(value) = value {
            if git_selector.is_some() {
                return Err(invalid(
                    manifest,
                    format!("Cargo dependency {alias:?} declares conflicting Git selectors"),
                ));
            }
            git_selector = Some((selector.to_owned(), value.to_owned()));
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
    let source = if local_path.is_some() {
        CargoDependencySource::Path
    } else if let Some(git) = git {
        CargoDependencySource::Git {
            url: git.to_owned(),
            selector: git_selector,
        }
    } else if let Some(registry_index) = registry_index {
        CargoDependencySource::RegistryIndex(registry_index.to_owned())
    } else if registry.is_some() {
        CargoDependencySource::RegistryName
    } else {
        CargoDependencySource::CratesIo
    };
    Ok(CargoDependencySpec {
        package_name: package.unwrap_or(alias).to_owned(),
        version,
        enrichable: path.is_none()
            && git.is_none()
            && registry.is_none()
            && registry_index.is_none(),
        local_path,
        source,
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
                declaring_package: manifest.package.clone(),
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
    let workspace_version = cargo_workspace_package_version(workspace_manifest, &workspace_value)?;

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
            package: cargo_manifest_package_id(&path, &value, workspace_version.as_deref())?,
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
            package: cargo_manifest_package_id(source_manifest, &source_value, None)?,
            value: source_value,
        }],
        BTreeMap::new(),
    ))
}

struct CargoProjectEvidence {
    packages: BTreeSet<CargoProjectPackageId>,
    declarations: Vec<CargoDeclaration>,
}

fn cargo_project_evidence(path: &Path) -> Result<CargoProjectEvidence, ParseError> {
    let (manifests, workspace_dependencies) = cargo_project_manifests(path)?;
    let mut packages = BTreeSet::new();
    for manifest in &manifests {
        if !packages.insert(manifest.package.clone()) {
            return Err(invalid(
                &manifest.path,
                format!(
                    "Cargo project repeats package identity {} {}",
                    manifest.package.name, manifest.package.version
                ),
            ));
        }
    }
    let declarations = manifests
        .iter()
        .map(|manifest| cargo_manifest_declarations(manifest, &workspace_dependencies))
        .collect::<Result<Vec<_>, _>>()
        .map(|declarations| declarations.into_iter().flatten().collect())?;
    Ok(CargoProjectEvidence {
        packages,
        declarations,
    })
}

fn cargo_project_declarations(path: &Path) -> Result<Vec<CargoDeclaration>, ParseError> {
    cargo_project_evidence(path).map(|evidence| evidence.declarations)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CargoLockId {
    name: String,
    version: String,
    source: Option<String>,
}

struct CargoRawLockNode {
    id: CargoLockId,
    dependency_references: Vec<String>,
    replacement_reference: Option<String>,
    emit: bool,
    context: String,
}

struct CargoLockNode {
    id: CargoLockId,
    dependencies: Vec<usize>,
    replacement: Option<usize>,
    emit: bool,
}

struct CargoLockReference {
    name: String,
    version: Option<String>,
    source: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CargoScope {
    Production,
    Development,
    Unknown,
}

fn cargo_lock_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn cargo_normalize_lock_source(source: &str) -> Result<String, String> {
    if source.starts_with("sparse+") {
        return Url::parse(source)
            .map(|url| url.to_string())
            .map_err(|error| format!("invalid sparse registry source URL: {error}"));
    }
    let (prefix, kind, url) = if let Some(url) = source.strip_prefix("git+") {
        ("git+", "Git", url)
    } else if let Some(url) = source.strip_prefix("registry+") {
        ("registry+", "registry", url)
    } else if let Some(url) = source.strip_prefix("path+") {
        ("path+", "path", url)
    } else {
        return Err(format!("unsupported source identity {source:?}"));
    };
    let url = Url::parse(url).map_err(|error| format!("invalid {kind} source URL: {error}"))?;
    Ok(format!("{prefix}{url}"))
}

fn cargo_lock_node(
    path: &Path,
    context: &str,
    item: &toml::Table,
    emit: bool,
) -> Result<CargoRawLockNode, ParseError> {
    let name = item
        .get("name")
        .and_then(Toml::as_str)
        .filter(|name| cargo_lock_name_valid(name))
        .ok_or_else(|| invalid(path, format!("{context} is missing a valid package name")))?;
    let version = item
        .get("version")
        .and_then(Toml::as_str)
        .filter(|version| !version.is_empty())
        .ok_or_else(|| {
            invalid(
                path,
                format!("{context} is missing a non-empty string version"),
            )
        })?;
    semver::Version::parse(version).map_err(|error| {
        invalid(
            path,
            format!("{context} has invalid SemVer version {version:?}: {error}"),
        )
    })?;
    let source = item
        .get("source")
        .map(|source| {
            let source = source
                .as_str()
                .filter(|source| !source.is_empty())
                .ok_or_else(|| {
                    invalid(path, format!("{context} source must be a non-empty string"))
                })?;
            cargo_normalize_lock_source(source)
                .map_err(|error| invalid(path, format!("{context} has {error}")))
        })
        .transpose()?;
    let replacement_reference = item
        .get("replace")
        .map(|replacement| {
            replacement
                .as_str()
                .filter(|replacement| !replacement.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    invalid(
                        path,
                        format!("{context} replace must be a non-empty package ID string"),
                    )
                })
        })
        .transpose()?;
    if item.contains_key("dependencies") && replacement_reference.is_some() {
        return Err(invalid(
            path,
            format!("{context} cannot define both dependencies and replace"),
        ));
    }
    let dependency_references = match item.get("dependencies") {
        None => Vec::new(),
        Some(dependencies) => dependencies
            .as_array()
            .ok_or_else(|| invalid(path, format!("{context} dependencies must be an array")))?
            .iter()
            .enumerate()
            .map(|(index, dependency)| {
                dependency
                    .as_str()
                    .filter(|dependency| !dependency.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        invalid(
                            path,
                            format!(
                                "{context} dependency entry {index} must be a non-empty string"
                            ),
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    Ok(CargoRawLockNode {
        id: CargoLockId {
            name: name.to_owned(),
            version: version.to_owned(),
            source,
        },
        dependency_references,
        replacement_reference,
        emit,
        context: context.to_owned(),
    })
}

fn parse_cargo_lock_reference(
    path: &Path,
    context: &str,
    reference: &str,
) -> Result<CargoLockReference, ParseError> {
    if reference.trim() != reference
        || reference
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() && byte != b' ')
    {
        return Err(invalid(
            path,
            format!("{context} has malformed dependency reference {reference:?}"),
        ));
    }
    let (identity, source) = if let Some(open) = reference.rfind(" (") {
        if !reference.ends_with(')') {
            return Err(invalid(
                path,
                format!("{context} has malformed dependency reference {reference:?}"),
            ));
        }
        let source = &reference[open + 2..reference.len() - 1];
        if source.is_empty() || source.contains(' ') {
            return Err(invalid(
                path,
                format!("{context} has empty dependency source in {reference:?}"),
            ));
        }
        let source = cargo_normalize_lock_source(source).map_err(|error| {
            invalid(
                path,
                format!("{context} dependency reference {reference:?} has {error}"),
            )
        })?;
        (&reference[..open], Some(source))
    } else {
        if reference.contains(['(', ')']) {
            return Err(invalid(
                path,
                format!("{context} has malformed dependency reference {reference:?}"),
            ));
        }
        (reference, None)
    };
    let (name, version) = match identity.split_once(' ') {
        None => (identity, None),
        Some((name, version))
            if !name.is_empty() && !version.is_empty() && !version.contains(' ') =>
        {
            semver::Version::parse(version).map_err(|error| {
                invalid(
                    path,
                    format!(
                        "{context} dependency reference {reference:?} has invalid SemVer: {error}"
                    ),
                )
            })?;
            (name, Some(version.to_owned()))
        }
        _ => {
            return Err(invalid(
                path,
                format!("{context} has malformed dependency reference {reference:?}"),
            ));
        }
    };
    if !cargo_lock_name_valid(name) || (source.is_some() && version.is_none()) {
        return Err(invalid(
            path,
            format!("{context} has malformed dependency reference {reference:?}"),
        ));
    }
    Ok(CargoLockReference {
        name: name.to_owned(),
        version,
        source,
    })
}

fn cargo_git_source_key(source: &str) -> Option<(String, Vec<(String, String)>)> {
    let source = source.strip_prefix("git+")?;
    let mut url = Url::parse(source).ok()?;
    let mut query = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    query.sort();
    url.set_query(None);
    url.set_fragment(None);
    Some((url.to_string(), query))
}

fn cargo_lock_source_matches(reference: &str, target: &str) -> bool {
    match (
        cargo_git_source_key(reference),
        cargo_git_source_key(target),
    ) {
        (Some(reference), Some(target)) => reference == target,
        (None, None) => reference == target,
        _ => false,
    }
}

fn cargo_lock_reference_source_matches(
    reference: &str,
    target: &str,
    lockfile_version: i64,
) -> bool {
    if cargo_lock_source_matches(reference, target) {
        return true;
    }
    let (Some(reference), Some(target)) = (
        cargo_git_source_key(reference),
        cargo_git_source_key(target),
    ) else {
        return false;
    };
    lockfile_version <= 2
        && reference.0 == target.0
        && reference.1.is_empty()
        && target.1 == [("branch".to_owned(), "master".to_owned())]
}

fn cargo_registry_index_source(index: &str) -> Option<String> {
    let source = if index.starts_with("registry+") || index.starts_with("sparse+") {
        index.to_owned()
    } else {
        format!("registry+{index}")
    };
    cargo_normalize_lock_source(&source).ok()
}

fn resolve_cargo_lock_reference(
    path: &Path,
    context: &str,
    reference: &CargoLockReference,
    nodes: &[CargoRawLockNode],
    lockfile_version: i64,
) -> Result<usize, ParseError> {
    let mut candidates = nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.id.name == reference.name)
        .collect::<Vec<_>>();
    if let Some(version) = &reference.version {
        candidates.retain(|(_, node)| node.id.version == *version);
    } else {
        let versions = candidates
            .iter()
            .map(|(_, node)| node.id.version.as_str())
            .collect::<BTreeSet<_>>();
        if versions.len() > 1 {
            return Err(invalid(
                path,
                format!(
                    "{context} dependency reference {:?} omits a version shared by multiple locked versions",
                    reference.name
                ),
            ));
        }
    }
    if let Some(source) = &reference.source {
        candidates.retain(|(_, node)| {
            node.id.source.as_deref().is_some_and(|target| {
                cargo_lock_reference_source_matches(source, target, lockfile_version)
            })
        });
    } else {
        let local_candidates = candidates
            .iter()
            .filter(|(_, node)| {
                node.id
                    .source
                    .as_deref()
                    .is_none_or(|source| source.starts_with("path+"))
            })
            .map(|(index, _)| *index)
            .collect::<Vec<_>>();
        if local_candidates.len() == 1 {
            return Ok(local_candidates[0]);
        }
    }
    match candidates.as_slice() {
        [(index, _)] => Ok(*index),
        [] => Err(invalid(
            path,
            format!(
                "{context} dependency reference to {:?} has no matching locked package",
                reference.name
            ),
        )),
        _ => Err(invalid(
            path,
            format!(
                "{context} dependency reference to {:?} is ambiguous across locked identities",
                reference.name
            ),
        )),
    }
}

fn cargo_dependency_source_exact(source: &CargoDependencySource, target: &CargoLockId) -> bool {
    match source {
        CargoDependencySource::CratesIo => target.source.as_deref() == Some(CARGO_CRATES_IO_SOURCE),
        CargoDependencySource::RegistryName => false,
        CargoDependencySource::RegistryIndex(index) => cargo_registry_index_source(index)
            .as_deref()
            .is_some_and(|index| target.source.as_deref() == Some(index)),
        CargoDependencySource::Git { url, selector } => {
            let Ok(mut expected) = Url::parse(url) else {
                return false;
            };
            if let Some((kind, value)) = selector {
                expected.query_pairs_mut().append_pair(kind, value);
            }
            let expected = format!("git+{expected}");
            target
                .source
                .as_deref()
                .is_some_and(|target| cargo_lock_source_matches(&expected, target))
        }
        CargoDependencySource::Path => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CargoDeclarationTargetStrength {
    None,
    Possible,
    Exact,
}

fn cargo_declaration_target_strength(
    declaration: &CargoDeclaration,
    target: &CargoLockId,
) -> CargoDeclarationTargetStrength {
    if declaration.dependency.package_name != target.name {
        return CargoDeclarationTargetStrength::None;
    }
    if let Some(requirement) = &declaration.dependency.version {
        let (Ok(requirement), Ok(version)) = (
            semver::VersionReq::parse(requirement),
            semver::Version::parse(&target.version),
        ) else {
            return CargoDeclarationTargetStrength::None;
        };
        if !requirement.matches(&version) {
            return CargoDeclarationTargetStrength::None;
        }
    }
    if cargo_dependency_source_exact(&declaration.dependency.source, target) {
        CargoDeclarationTargetStrength::Exact
    } else {
        CargoDeclarationTargetStrength::Possible
    }
}

fn cargo_member_edge_scopes(
    member: &CargoProjectPackageId,
    dependencies: &[usize],
    nodes: &[CargoLockNode],
    declarations: &[CargoDeclaration],
) -> BTreeMap<usize, CargoScope> {
    let declarations = declarations
        .iter()
        .filter(|declaration| declaration.declaring_package == *member)
        .collect::<Vec<_>>();
    let mut exact = BTreeMap::<usize, Vec<bool>>::new();
    let mut possible = BTreeMap::<usize, Vec<bool>>::new();
    for declaration in declarations {
        let exact_targets = dependencies
            .iter()
            .copied()
            .filter(|target| {
                cargo_declaration_target_strength(declaration, &nodes[*target].id)
                    == CargoDeclarationTargetStrength::Exact
            })
            .collect::<Vec<_>>();
        if exact_targets.len() == 1 {
            exact
                .entry(exact_targets[0])
                .or_default()
                .push(declaration.dev);
            continue;
        }
        let possible_targets = dependencies
            .iter()
            .copied()
            .filter(|target| {
                cargo_declaration_target_strength(declaration, &nodes[*target].id)
                    != CargoDeclarationTargetStrength::None
            })
            .collect::<Vec<_>>();
        for target in possible_targets {
            possible.entry(target).or_default().push(declaration.dev);
        }
    }
    dependencies
        .iter()
        .copied()
        .map(|target| {
            if nodes[target].replacement.is_some() {
                return (target, CargoScope::Unknown);
            }
            let exact = exact.get(&target).map(Vec::as_slice).unwrap_or(&[]);
            let possible = possible.get(&target).map(Vec::as_slice).unwrap_or(&[]);
            let scope = if exact.iter().any(|dev| !dev) {
                CargoScope::Production
            } else if possible.iter().any(|dev| !dev) {
                CargoScope::Unknown
            } else if exact.iter().any(|dev| *dev) {
                CargoScope::Development
            } else {
                CargoScope::Unknown
            };
            (target, scope)
        })
        .collect()
}

fn cargo_reachable(
    seeds: impl IntoIterator<Item = usize>,
    nodes: &[CargoLockNode],
    members: &BTreeSet<usize>,
) -> BTreeSet<usize> {
    let mut reached = BTreeSet::new();
    let mut pending = VecDeque::new();
    for seed in seeds {
        if reached.insert(seed) {
            pending.push_back(seed);
        }
    }
    while let Some(index) = pending.pop_front() {
        if members.contains(&index) {
            continue;
        }
        let dependencies = nodes[index]
            .replacement
            .iter()
            .chain(nodes[index].dependencies.iter());
        for dependency in dependencies {
            if reached.insert(*dependency) {
                pending.push_back(*dependency);
            }
        }
    }
    reached
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
    let package_entries: &[Toml] = match document.get("package") {
        Some(package_entries) => package_entries.as_array().map(Vec::as_slice).ok_or_else(|| {
            invalid(
                path,
                format!(
                    "detected Cargo.lock version {lockfile_version} without a package array; expected resolved package entries"
                ),
            )
        })?,
        None if lockfile_version == 1 && document.contains_key("root") => &[],
        None => {
            return Err(invalid(
                path,
                format!(
                    "detected Cargo.lock version {lockfile_version} without a package array; expected resolved package entries"
                ),
            ));
        }
    };
    let mut raw_nodes = Vec::new();
    for (index, item) in package_entries.iter().enumerate() {
        let item = item.as_table().ok_or_else(|| {
            invalid(
                path,
                format!("Cargo.lock package entry {index} must be a table"),
            )
        })?;
        raw_nodes.push(cargo_lock_node(
            path,
            &format!("Cargo.lock package entry {index}"),
            item,
            true,
        )?);
    }
    if let Some(root) = document.get("root") {
        if lockfile_version != 1 {
            return Err(invalid(
                path,
                "Cargo.lock [root] is supported only for version 1 lockfiles",
            ));
        }
        let root = root
            .as_table()
            .ok_or_else(|| invalid(path, "Cargo.lock [root] must be a table"))?;
        raw_nodes.push(cargo_lock_node(
            path,
            "Cargo.lock legacy root",
            root,
            false,
        )?);
    }

    let mut identities = BTreeMap::new();
    for (index, node) in raw_nodes.iter().enumerate() {
        if let Some(previous) = identities.insert(node.id.clone(), index) {
            return Err(invalid(
                path,
                format!(
                    "Cargo.lock repeats exact package identity {} {} at entries {previous} and {index}",
                    node.id.name, node.id.version
                ),
            ));
        }
    }

    let mut nodes = Vec::with_capacity(raw_nodes.len());
    for (raw_index, raw) in raw_nodes.iter().enumerate() {
        let mut dependencies = BTreeSet::new();
        for dependency in &raw.dependency_references {
            let reference = parse_cargo_lock_reference(path, &raw.context, dependency)?;
            let dependency = resolve_cargo_lock_reference(
                path,
                &raw.context,
                &reference,
                &raw_nodes,
                lockfile_version,
            )?;
            if dependency == raw_index {
                return Err(invalid(
                    path,
                    format!("{} cannot depend on itself", raw.context),
                ));
            }
            dependencies.insert(dependency);
        }
        let replacement = raw
            .replacement_reference
            .as_deref()
            .map(|replacement| {
                let reference = parse_cargo_lock_reference(path, &raw.context, replacement)?;
                resolve_cargo_lock_reference(
                    path,
                    &raw.context,
                    &reference,
                    &raw_nodes,
                    lockfile_version,
                )
            })
            .transpose()?;
        if let Some(replacement) = replacement {
            let target = &raw_nodes[replacement];
            if target.id == raw.id {
                return Err(invalid(
                    path,
                    format!("{} cannot replace itself", raw.context),
                ));
            }
            if target.id.name != raw.id.name || target.id.version != raw.id.version {
                return Err(invalid(
                    path,
                    format!(
                        "{} replacement must have the same package name and version",
                        raw.context
                    ),
                ));
            }
            if target.replacement_reference.is_some() {
                return Err(invalid(
                    path,
                    format!(
                        "{} replacement target cannot itself define replace",
                        raw.context
                    ),
                ));
            }
        }
        nodes.push(CargoLockNode {
            id: raw.id.clone(),
            dependencies: dependencies.into_iter().collect(),
            replacement,
            emit: raw.emit,
        });
    }

    let mut direct = vec![false; nodes.len()];
    let mut direct_known = vec![false; nodes.len()];
    let mut dev = vec![false; nodes.len()];
    let mut dev_known = vec![false; nodes.len()];
    let manifest = path.parent().unwrap_or(Path::new(".")).join("Cargo.toml");
    if manifest.is_file() {
        let evidence = cargo_project_evidence(&manifest)?;
        let member_indices = evidence
            .packages
            .iter()
            .map(|member| {
                nodes.iter().position(|node| {
                    node.id.name == member.name
                        && node.id.version == member.version
                        && node.id.source.is_none()
                })
            })
            .collect::<Option<BTreeSet<_>>>();
        if let Some(member_indices) = member_indices {
            let mut direct_targets = BTreeSet::new();
            let mut production_seeds = member_indices.clone();
            let mut development_seeds = BTreeSet::new();
            let mut unknown_seeds = BTreeSet::new();
            for member_index in &member_indices {
                let member = CargoProjectPackageId {
                    name: nodes[*member_index].id.name.clone(),
                    version: nodes[*member_index].id.version.clone(),
                };
                let scopes = cargo_member_edge_scopes(
                    &member,
                    &nodes[*member_index].dependencies,
                    &nodes,
                    &evidence.declarations,
                );
                for target in &nodes[*member_index].dependencies {
                    direct_targets.insert(*target);
                    match scopes.get(target).copied().unwrap_or(CargoScope::Unknown) {
                        CargoScope::Production => {
                            production_seeds.insert(*target);
                        }
                        CargoScope::Development => {
                            development_seeds.insert(*target);
                        }
                        CargoScope::Unknown => {
                            unknown_seeds.insert(*target);
                        }
                    }
                }
            }

            let reachable =
                cargo_reachable(member_indices.iter().copied(), &nodes, &BTreeSet::new());
            let production =
                cargo_reachable(production_seeds.iter().copied(), &nodes, &member_indices);
            let development =
                cargo_reachable(development_seeds.iter().copied(), &nodes, &member_indices);
            let unknown = cargo_reachable(unknown_seeds.iter().copied(), &nodes, &member_indices);
            for index in reachable {
                direct[index] = direct_targets.contains(&index);
                direct_known[index] = true;
                if production.contains(&index) {
                    dev[index] = false;
                    dev_known[index] = true;
                } else if unknown.contains(&index) {
                    dev[index] = false;
                    dev_known[index] = false;
                } else if development.contains(&index) {
                    dev[index] = true;
                    dev_known[index] = true;
                }
            }
        }
    }

    let mut out = Vec::new();
    for (index, node) in nodes.into_iter().enumerate() {
        if !node.emit {
            continue;
        }
        let mut package = Package::new(
            Ecosystem::CratesIo,
            node.id.name,
            node.id.version,
            path.to_path_buf(),
        );
        package.direct = direct[index];
        package.direct_known = direct_known[index];
        package.dev = dev[index];
        package.dev_known = dev_known[index];
        package.enrichable =
            node.replacement.is_none() && node.id.source.as_deref() == Some(CARGO_CRATES_IO_SOURCE);
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
                existing.enrichable |= package.enrichable;
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

    fn parse_npm_value(value: &Json) -> Result<Vec<Package>, ParseError> {
        let directory = tempfile::tempdir().unwrap();
        let lock = directory.path().join("package-lock.json");
        fs::write(&lock, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        parse_package_lock(&lock)
    }

    fn assert_npm_lock_edge_directness(packages: &[Package]) {
        let package = |name: &str, version: &str| {
            packages
                .iter()
                .find(|package| package.name == name && package.version == version)
                .unwrap_or_else(|| panic!("missing npm package {name}@{version}"))
        };

        for (name, version) in [
            ("duplicate", "2.0.0"),
            ("hoisted", "1.0.0"),
            ("parent", "1.0.0"),
            ("root-actual", "1.0.0"),
            ("root-direct", "2.0.0"),
            ("shared", "1.0.0"),
            ("workspace-actual", "1.0.0"),
        ] {
            let package = package(name, version);
            assert!(package.direct, "{name}@{version} was not direct");
            assert!(
                package.direct_known,
                "{name}@{version} directness was not proven"
            );
        }

        let nested_duplicate = package("duplicate", "1.0.0");
        assert!(!nested_duplicate.direct);
        assert!(nested_duplicate.direct_known);

        for name in ["unreferenced", "unreferenced-parent", "unreferenced-child"] {
            let unreferenced = package(name, "9.0.0");
            assert!(!unreferenced.direct);
            assert!(
                !unreferenced.direct_known,
                "disconnected {name} was spuriously classified as known transitive"
            );
        }
        assert_eq!(
            packages
                .iter()
                .filter(|package| package.name == "shared" && package.version == "1.0.0")
                .count(),
            1,
            "dedup must retain one existentially direct shared coordinate"
        );
    }

    #[test]
    fn npm_v3_lock_edges_prove_exact_directness_without_external_manifests() {
        assert_npm_lock_edge_directness(&npm_fixture_packages("npm-v3-directness"));
    }

    #[test]
    fn npm_v2_lock_edges_prove_exact_directness_without_external_manifest() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/npm-v3-directness/package-lock.json");
        let mut value: Json = serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
        value["lockfileVersion"] = json!(2);
        let packages = parse_npm_value(&value).unwrap();
        assert_npm_lock_edge_directness(&packages);
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
    fn rejects_malformed_npm_v2_v3_package_records() {
        let cases = [
            (
                "non-object entry",
                "node_modules/bad",
                json!("not an object"),
                "must be an object",
            ),
            (
                "missing version",
                "node_modules/bad",
                json!({"dev": true}),
                "non-empty string version",
            ),
            (
                "wrong version type",
                "node_modules/bad",
                json!({"version": 1}),
                "field \"version\" must be a non-empty string",
            ),
            (
                "invalid registry version",
                "node_modules/bad",
                json!({"version": "^1.0.0"}),
                "invalid registry SemVer",
            ),
            (
                "malformed scoped location",
                "node_modules/@scope/too/many",
                json!({"version": "1.0.0"}),
                "valid node_modules install location",
            ),
            (
                "parent traversal before node_modules",
                "../node_modules/bad",
                json!({"version": "1.0.0"}),
                "valid node_modules install location",
            ),
            (
                "parent traversal in install prefix",
                "packages/../node_modules/bad",
                json!({"version": "1.0.0"}),
                "valid node_modules install location",
            ),
            (
                "unknown local descriptor",
                "vendor/bad",
                json!({"version": "1.0.0"}),
                "neither a linked local descriptor",
            ),
            (
                "unproven install prefix",
                "vendor/node_modules/bad",
                json!({"version": "1.0.0"}),
                "unproven install prefix",
            ),
            (
                "wrong dev type",
                "node_modules/bad",
                json!({"version": "1.0.0", "dev": "true"}),
                "field \"dev\" must be a boolean",
            ),
            (
                "wrong link type",
                "node_modules/bad",
                json!({"version": "1.0.0", "link": 1}),
                "field \"link\" must be a boolean",
            ),
            (
                "link without target",
                "node_modules/bad",
                json!({"link": true}),
                "non-empty string resolved target",
            ),
            (
                "link with missing descriptor",
                "node_modules/bad",
                json!({"link": true, "resolved": "packages/missing"}),
                "does not name an existing package descriptor object",
            ),
            (
                "wrong resolved type",
                "node_modules/bad",
                json!({"version": "1.0.0", "resolved": false}),
                "field \"resolved\" must be a non-empty string",
            ),
            (
                "garbage resolved source",
                "node_modules/bad",
                json!({"version": "1.0.0", "resolved": "not-a-source"}),
                "unsupported or malformed resolved source",
            ),
            (
                "credential-like bare tarball source",
                "node_modules/bad",
                json!({
                    "version": "1.0.0",
                    "resolved": "user:password@private.example/path/package.tgz"
                }),
                "unsupported or malformed resolved source",
            ),
            (
                "empty file version source",
                "node_modules/bad",
                json!({"version": "file:"}),
                "unsupported or malformed version source",
            ),
            (
                "empty Git version source",
                "node_modules/bad",
                json!({"version": "git:"}),
                "unsupported or malformed version source",
            ),
            (
                "empty HTTPS version source",
                "node_modules/bad",
                json!({"version": "https:"}),
                "unsupported or malformed version source",
            ),
            (
                "empty workspace version source",
                "node_modules/bad",
                json!({"version": "workspace:"}),
                "unsupported or malformed version source",
            ),
            (
                "empty SCP repository source",
                "node_modules/bad",
                json!({"version": "git@private.example:"}),
                "unsupported or malformed version source",
            ),
            (
                "SCP source with only a fragment",
                "node_modules/bad",
                json!({"version": "git@private.example:#token"}),
                "unsupported or malformed version source",
            ),
            (
                "SCP source with only a query",
                "node_modules/bad",
                json!({"version": "git@private.example:?token"}),
                "unsupported or malformed version source",
            ),
        ];

        for version in [2, 3] {
            for (label, location, entry, expected) in &cases {
                let value = json!({
                    "name": "strict-fixture",
                    "lockfileVersion": version,
                    "packages": {
                        "": {"name": "strict-fixture", "version": "1.0.0"},
                        (*location): (*entry).clone(),
                    }
                });
                let error = match parse_npm_value(&value) {
                    Ok(_) => panic!("npm v{version} accepted {label}"),
                    Err(error) => error,
                };
                let ParseError::Invalid { message, .. } = error else {
                    panic!("npm v{version} returned I/O error for {label}");
                };
                assert!(
                    message.contains(expected),
                    "npm v{version} {label} returned unexpected error: {message}"
                );
            }
        }
    }

    #[test]
    fn link_metadata_cannot_hide_an_installed_npm_package_record() {
        let packages = parse_npm_value(&json!({
            "name": "strict-fixture",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "strict-fixture", "version": "1.0.0"},
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
                },
                "node_modules/decoy": {
                    "link": true,
                    "resolved": "node_modules/lodash"
                }
            }
        }))
        .unwrap();

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "lodash");
        assert_eq!(packages[0].version, "4.17.20");
        assert!(packages[0].enrichable);

        let error = parse_npm_value(&json!({
            "name": "strict-fixture",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "strict-fixture", "version": "1.0.0"},
                "node_modules/@scope": {"version": "1.0.0"},
                "node_modules/decoy": {
                    "link": true,
                    "resolved": "node_modules/@scope"
                }
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = error else {
            panic!("malformed installed link target returned an I/O error");
        };
        assert!(message.contains("not a valid installed package location"));
    }

    #[test]
    fn npm_alias_records_require_the_declared_registry_identity() {
        for (label, name) in [
            ("missing name", None),
            ("mismatched name", Some(json!("underscore"))),
        ] {
            let mut entry = serde_json::Map::new();
            entry.insert("version".to_owned(), json!("4.17.20"));
            if let Some(name) = name {
                entry.insert("name".to_owned(), name);
            }
            let error = parse_npm_value(&json!({
                "name": "alias-fixture",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "alias-fixture",
                        "version": "1.0.0",
                        "dependencies": {"alias-lodash": "npm:lodash@4.17.20"}
                    },
                    "node_modules/alias-lodash": Json::Object(entry)
                }
            }))
            .unwrap_err();

            let ParseError::Invalid { message, .. } = error else {
                panic!("{label} alias returned an I/O error");
            };
            assert!(
                message.contains("alias package entry")
                    && message.contains("lodash")
                    && message.contains("alias-lodash"),
                "{label} alias returned unexpected context: {message}"
            );
        }
    }

    #[test]
    fn npm_alias_targets_allow_the_npm_default_version() {
        assert_eq!(npm_alias_target("lodash").unwrap(), "lodash");
        assert_eq!(npm_alias_target("lodash@latest").unwrap(), "lodash");
        assert_eq!(
            npm_alias_target("@scope/package").unwrap(),
            "@scope/package"
        );
        assert_eq!(
            npm_alias_target("@scope/package@^1.0.0").unwrap(),
            "@scope/package"
        );
        assert_eq!(npm_alias_target("lodash@").unwrap(), "lodash");
        assert_eq!(
            npm_alias_target("@scope/package@").unwrap(),
            "@scope/package"
        );
        assert!(npm_alias_target("lodash@file:../package").is_err());
        assert!(npm_alias_target("lodash@npm:other").is_err());

        let packages = npm_fixture_packages("npm-v3-alias-bare");

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "lodash");
        assert_eq!(packages[0].version, "4.18.1");
        assert!(packages[0].direct);
        assert!(packages[0].enrichable);
    }

    #[test]
    fn npm_installed_identity_selects_the_effective_duplicate_group_alias() {
        let packages = parse_npm_value(&json!({
            "name": "duplicate-group-alias",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "duplicate-group-alias",
                    "version": "1.0.0",
                    "dependencies": {"same": "npm:lodash@4.17.20"},
                    "devDependencies": {"same": "npm:underscore@1.13.7"}
                },
                "node_modules/same": {
                    "name": "underscore",
                    "version": "1.13.7",
                    "resolved": "https://registry.npmjs.org/underscore/-/underscore-1.13.7.tgz",
                    "dev": true
                }
            }
        }))
        .unwrap();

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "underscore");
        assert_eq!(packages[0].version, "1.13.7");
        assert!(packages[0].dev);
        assert!(packages[0].enrichable);
    }

    #[test]
    fn npm_effective_dev_declaration_overrides_a_source_declaration() {
        let packages = parse_npm_value(&json!({
            "name": "duplicate-group-source",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "duplicate-group-source",
                    "version": "1.0.0",
                    "dependencies": {
                        "same": "https://registry.npmjs.org/underscore/-/underscore-1.13.7.tgz"
                    },
                    "devDependencies": {"same": "npm:lodash@4.17.20"}
                },
                "node_modules/same": {
                    "name": "lodash",
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                    "dev": true
                }
            }
        }))
        .unwrap();

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "lodash");
        assert!(packages[0].dev);
        assert!(packages[0].enrichable);
    }

    #[test]
    fn npm_workspace_patterns_follow_npm_negation_semantics() {
        fn patterns(values: Json) -> NpmWorkspacePatterns {
            let document = json!({
                "": {
                    "name": "workspace-patterns",
                    "version": "1.0.0",
                    "workspaces": values
                }
            });
            npm_lock_workspace_patterns(
                Path::new("package-lock.json"),
                document.as_object().unwrap(),
            )
            .unwrap()
        }

        fn is_workspace(location: &str, patterns: &NpmWorkspacePatterns) -> bool {
            npm_is_workspace_descriptor(Path::new("package-lock.json"), location, patterns).unwrap()
        }

        let braces = patterns(json!(["/packages/{a,b}/"]));
        assert!(is_workspace("packages/a", &braces));
        assert!(is_workspace("packages/b", &braces));
        assert!(is_workspace(
            "packages/a",
            &patterns(json!([".//packages/*"]))
        ));
        assert!(!is_workspace(
            "packages/a",
            &patterns(json!(["././packages/*"]))
        ));
        assert!(!is_workspace(
            "packages/a",
            &patterns(json!(["/./packages/*"]))
        ));

        let negated_before_include = patterns(json!(["!packages/b", "packages/*"]));
        assert!(is_workspace("packages/a", &negated_before_include));
        assert!(!is_workspace("packages/b", &negated_before_include));

        let adjacent_negations = patterns(json!(["!packages/*", "!packages/a", "packages/a"]));
        assert!(!is_workspace("packages/a", &adjacent_negations));

        let double_negation = patterns(json!(["!!packages\\c"]));
        assert!(is_workspace("packages/c", &double_negation));
        let exact_extglob = patterns(json!(["packages/@(a|b)"]));
        assert!(is_workspace("packages/a", &exact_extglob));
        assert!(is_workspace("packages/b", &exact_extglob));
        assert!(!is_workspace("packages/c", &exact_extglob));

        let optional_extglob = patterns(json!(["packages/item?(s|z)"]));
        assert!(is_workspace("packages/item", &optional_extglob));
        assert!(is_workspace("packages/items", &optional_extglob));

        let literal_dollar = patterns(json!(["packages/$"]));
        assert!(is_workspace("packages/$", &literal_dollar));
        assert!(!is_workspace("packages/a", &literal_dollar));

        let negative_extglob = patterns(json!(["packages/!(c)"]));
        assert!(is_workspace("packages/a", &negative_extglob));
        assert!(!is_workspace("packages/c", &negative_extglob));

        let numeric_brace = patterns(json!(["packages/{1..3}"]));
        assert!(is_workspace("packages/2", &numeric_brace));
        assert!(!is_workspace("packages/4", &numeric_brace));

        let alphabetic_brace = patterns(json!(["packages/{a..e..2}"]));
        assert!(is_workspace("packages/c", &alphabetic_brace));
        assert!(!is_workspace("packages/d", &alphabetic_brace));

        let posix_class = patterns(json!(["packages/[[:alpha:]]"]));
        assert!(is_workspace("packages/a", &posix_class));
        assert!(!is_workspace("packages/7", &posix_class));

        assert!(!is_workspace(
            "packages/a",
            &patterns(json!(["packages/{a}"]))
        ));
        assert!(!is_workspace(
            "packages/.a",
            &patterns(json!(["packages/*"]))
        ));
        assert!(!is_workspace("#a", &patterns(json!(["#*"]))));
        assert!(!is_workspace("node_modules/c", &patterns(json!(["**"]))));
    }

    #[test]
    fn npm_links_require_a_proven_workspace_identity() {
        let forged = parse_npm_value(&json!({
            "name": "forged-link",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "forged-link",
                    "version": "1.0.0",
                    "dependencies": {"lodash": "4.17.20"}
                },
                "node_modules/lodash": {"link": true, "resolved": "packages/fake"},
                "packages/fake": {"name": "fake-lodash", "version": "1.0.0"}
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = forged else {
            panic!("forged npm link returned an I/O error");
        };
        assert!(message.contains("unproven local target"));

        let nameless_forged = parse_npm_value(&json!({
            "name": "nameless-forged-link",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "nameless-forged-link",
                    "version": "1.0.0",
                    "workspaces": ["packages/*"],
                    "dependencies": {"lodash": "4.17.20"}
                },
                "node_modules/lodash": {"link": true, "resolved": "packages/fake"},
                "packages/fake": {"version": "1.0.0"}
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = nameless_forged else {
            panic!("nameless forged npm link returned an I/O error");
        };
        assert!(message.contains("unproven local target"));

        let workspace_shadow = parse_npm_value(&json!({
            "name": "workspace-shadow",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "workspace-shadow",
                    "version": "1.0.0",
                    "workspaces": ["packages/*"],
                    "dependencies": {"a": "npm:lodash@4.17.20"}
                },
                "node_modules/a": {"link": true, "resolved": "packages/a"},
                "packages/a": {"version": "1.0.0"}
            }
        }))
        .unwrap();
        assert!(workspace_shadow.is_empty());

        let conflicting_workspace_alias = parse_npm_value(&json!({
            "name": "workspace-alias-conflict",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "workspace-alias-conflict",
                    "version": "1.0.0",
                    "workspaces": ["packages/*"]
                },
                "node_modules/b": {"link": true, "resolved": "packages/b"},
                "packages/a": {
                    "name": "a",
                    "version": "1.0.0",
                    "dependencies": {"b": "npm:lodash@4.17.20"}
                },
                "packages/b": {"name": "b", "version": "1.0.0"}
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = conflicting_workspace_alias else {
            panic!("conflicting workspace alias returned an I/O error");
        };
        assert!(message.contains("unproven local target"));

        let malformed_link_field = parse_npm_value(&json!({
            "name": "malformed-link-field",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "malformed-link-field",
                    "version": "1.0.0",
                    "workspaces": ["packages/*"]
                },
                "node_modules/a": {
                    "link": true,
                    "resolved": "packages/a",
                    "dev": "yes"
                },
                "packages/a": {"name": "a", "version": "1.0.0"}
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = malformed_link_field else {
            panic!("malformed link dev field returned an I/O error");
        };
        assert!(message.contains("field \"dev\" must be a boolean"));

        let link_with_package_metadata = parse_npm_value(&json!({
            "name": "link-package-metadata",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "link-package-metadata",
                    "version": "1.0.0",
                    "workspaces": ["packages/*"]
                },
                "node_modules/a": {
                    "link": true,
                    "resolved": "packages/a",
                    "dependencies": {"lodash": "4.17.20"}
                },
                "packages/a": {"name": "a", "version": "1.0.0"}
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = link_with_package_metadata else {
            panic!("npm link package metadata returned an I/O error");
        };
        assert!(message.contains("must not contain package metadata field \"dependencies\""));

        let duplicate_target_identity = parse_npm_value(&json!({
            "name": "duplicate-target-identity",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "duplicate-target-identity",
                    "version": "1.0.0",
                    "workspaces": ["packages/*"]
                },
                "node_modules/a": {"link": true, "resolved": "packages/a"},
                "node_modules/b": {"link": true, "resolved": "packages/a"},
                "packages/a": {"version": "1.0.0"}
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = duplicate_target_identity else {
            panic!("duplicate workspace target identity returned an I/O error");
        };
        assert!(message.contains("no matching workspace identity"));

        let orphan_external = parse_npm_value(&json!({
            "name": "orphan-external-link",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "orphan-external-link", "version": "1.0.0"},
                "node_modules/lodash": {"link": true, "resolved": "../outside"},
                "../outside": {"name": "lodash", "version": "4.17.20"}
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = orphan_external else {
            panic!("orphan external npm link returned an I/O error");
        };
        assert!(message.contains("explicit non-registry declaration"));

        let self_link = parse_npm_value(&json!({
            "name": "self-link",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "self-link", "version": "1.0.0"},
                "node_modules/hidden": {
                    "link": true,
                    "resolved": "node_modules/hidden"
                }
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = self_link else {
            panic!("self-referential npm link returned an I/O error");
        };
        assert!(message.contains("must not be itself or another link record"));

        let malformed_target_version = parse_npm_value(&json!({
            "name": "malformed-target-version",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "malformed-target-version",
                    "version": "1.0.0",
                    "workspaces": ["packages/*"]
                },
                "node_modules/a": {"link": true, "resolved": "packages/a"},
                "packages/a": {"name": "a", "version": 123}
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = malformed_target_version else {
            panic!("malformed npm link target version returned an I/O error");
        };
        assert!(message.contains("field \"version\" must be a non-empty string"));

        let unproven_prefix = parse_npm_value(&json!({
            "name": "unproven-link-prefix",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "unproven-link-prefix",
                    "version": "1.0.0",
                    "workspaces": ["packages/*"]
                },
                "vendor/node_modules/a": {"link": true, "resolved": "packages/a"},
                "packages/a": {"name": "a", "version": "1.0.0"}
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = unproven_prefix else {
            panic!("unproven npm link prefix returned an I/O error");
        };
        assert!(message.contains("unproven install prefix \"vendor\""));
    }

    #[test]
    fn npm_external_link_descriptors_do_not_require_uninstalled_edges() {
        let packages = parse_npm_value(&json!({
            "name": "external-link",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "external-link",
                    "version": "1.0.0",
                    "dependencies": {"outside": "file:../outside"}
                },
                "node_modules/outside": {"link": true, "resolved": "../outside"},
                "../outside": {
                    "name": "outside",
                    "version": "1.0.0",
                    "dependencies": {"not-installed": "1.0.0"},
                    "devDependencies": {"also-not-installed": "1.0.0"}
                }
            }
        }))
        .unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn npm_non_root_registry_constraints_cannot_fall_back_to_an_incompatible_workspace() {
        let error = parse_npm_value(&json!({
            "name": "workspace-range-confusion",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "workspace-range-confusion",
                    "version": "1.0.0",
                    "workspaces": ["packages/*"]
                },
                "node_modules/lodash": {
                    "link": true,
                    "resolved": "packages/local-lodash"
                },
                "node_modules/y": {"link": true, "resolved": "packages/y"},
                "packages/local-lodash": {
                    "name": "lodash",
                    "version": "1.0.0"
                },
                "packages/y": {
                    "name": "y",
                    "version": "1.0.0",
                    "dependencies": {"lodash": "4.17.21"}
                }
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = error else {
            panic!("incompatible workspace fallback returned an I/O error");
        };
        assert!(message.contains("does not accept linked workspace version \"1.0.0\""));
    }

    #[test]
    fn npm_sources_must_resolve_to_the_selected_link_target() {
        let valid = parse_npm_value(&json!({
            "name": "workspace-file-link",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "workspace-file-link",
                    "version": "1.0.0",
                    "workspaces": ["packages/*"]
                },
                "node_modules/a": {"link": true, "resolved": "packages/a"},
                "node_modules/y": {"link": true, "resolved": "packages/y"},
                "packages/a": {"name": "a", "version": "1.0.0"},
                "packages/y": {
                    "name": "y",
                    "version": "1.0.0",
                    "dependencies": {"a": "file:../a"}
                }
            }
        }))
        .unwrap();
        assert!(valid.is_empty());

        let error = parse_npm_value(&json!({
            "name": "workspace-source-confusion",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "workspace-source-confusion",
                    "version": "1.0.0",
                    "workspaces": ["packages/*"]
                },
                "node_modules/lodash": {
                    "link": true,
                    "resolved": "packages/local-lodash"
                },
                "node_modules/y": {"link": true, "resolved": "packages/y"},
                "packages/local-lodash": {
                    "name": "lodash",
                    "version": "1.0.0"
                },
                "packages/y": {
                    "name": "y",
                    "version": "1.0.0",
                    "dependencies": {"lodash": "file:../../external-lodash"}
                }
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = error else {
            panic!("mismatched non-root npm source returned an I/O error");
        };
        assert!(message.contains("does not resolve to linked target \"packages/local-lodash\""));

        for (name, specification) in [
            ("url-source", "https://private.example/package.tgz"),
            ("workspace-source", "workspace:*"),
        ] {
            let target = format!("../outside-{name}");
            let error = parse_npm_value(&json!({
                "name": "root-source-confusion",
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "root-source-confusion",
                        "version": "1.0.0",
                        "dependencies": {(name): specification}
                    },
                    (format!("node_modules/{name}")): {
                        "link": true,
                        "resolved": target.clone()
                    },
                    (target.clone()): {"name": name, "version": "1.0.0"}
                }
            }))
            .unwrap_err();
            let ParseError::Invalid { message, .. } = error else {
                panic!("root {name} source confusion returned an I/O error");
            };
            assert!(
                message.contains("does not resolve to linked target")
                    || message.contains("cannot resolve to non-workspace link target"),
                "root {name} source confusion returned unexpected context: {message}"
            );
        }
    }

    #[test]
    fn npm_registry_declarations_coalesced_at_one_install_must_agree() {
        let error = parse_npm_value(&json!({
            "name": "coalesced-identities",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "coalesced-identities",
                    "version": "1.0.0",
                    "workspaces": ["packages/*"],
                    "dependencies": {"shared": "npm:lodash@4.17.20"}
                },
                "node_modules/a": {"link": true, "resolved": "packages/a"},
                "packages/a": {
                    "name": "a",
                    "version": "1.0.0",
                    "dependencies": {"shared": "1.0.0"}
                },
                "node_modules/shared": {
                    "name": "lodash",
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
                }
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = error else {
            panic!("coalesced npm identities returned an I/O error");
        };
        assert!(message.contains("inconsistent with its registry declarations"));
    }

    #[test]
    fn npm_workspace_source_provenance_survives_hoisting() {
        let packages = npm_fixture_packages("npm-v3-hoisted-url");

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "lodash");
        assert_eq!(packages[0].version, "4.17.20");
        assert!(packages[0].direct);
        assert!(!packages[0].enrichable);
    }

    #[test]
    fn npm_alias_validation_is_scoped_to_the_declaring_descriptor() {
        let source_collision = npm_fixture_packages("npm-v3-alias-source-collision")
            .into_iter()
            .map(|package| (package.name.clone(), package))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(source_collision.len(), 2);
        assert!(source_collision["lodash"].enrichable);
        assert!(!source_collision["underscore"].enrichable);

        let registry_collision = npm_fixture_packages("npm-v3-alias-registry-collision")
            .into_iter()
            .map(|package| (package.name.clone(), package))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(registry_collision.len(), 2);
        assert!(registry_collision["lodash"].enrichable);
        assert!(registry_collision["is-number"].enrichable);
    }

    #[test]
    fn npm_workspace_sources_bind_to_their_concrete_installed_records() {
        let packages = npm_fixture_packages("npm-v3-workspace-source-collision")
            .into_iter()
            .map(|package| (package.name.clone(), package))
            .collect::<BTreeMap<_, _>>();

        assert_eq!(packages.len(), 2);
        assert_eq!(packages["lodash"].version, "4.17.20");
        assert!(packages["lodash"].enrichable);
        assert_eq!(packages["underscore"].version, "1.13.7");
        assert!(!packages["underscore"].enrichable);
    }

    #[test]
    fn npm_dedup_keeps_a_proven_public_occurrence_enrichable() {
        let packages = parse_npm_value(&json!({
            "name": "mixed-source-same-coordinate",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "mixed-source-same-coordinate",
                    "version": "1.0.0",
                    "dependencies": {
                        "public-lodash": "npm:lodash@4.17.20",
                        "url-lodash": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
                    }
                },
                "node_modules/public-lodash": {
                    "name": "lodash",
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
                },
                "node_modules/url-lodash": {
                    "name": "lodash",
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
                }
            }
        }))
        .unwrap();

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "lodash");
        assert!(packages[0].enrichable);
    }

    #[test]
    fn npm_ambiguous_registry_origins_are_visible_but_not_enriched() {
        let omitted = parse_npm_value(&json!({
            "name": "omitted-registry-origin",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "omitted-registry-origin",
                    "version": "1.0.0",
                    "dependencies": {"lodash": "4.17.20"}
                },
                "node_modules/lodash": {"version": "4.17.20"}
            }
        }))
        .unwrap();
        assert_eq!(omitted.len(), 1);
        assert!(!omitted[0].enrichable);

        let configured = parse_npm_value(&json!({
            "name": "configured-registry-origin",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "configured-registry-origin",
                    "version": "1.0.0",
                    "dependencies": {"lodash": "4.17.20"}
                },
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
                }
            }
        }))
        .unwrap();
        assert_eq!(configured.len(), 1);
        assert!(!configured[0].enrichable);

        let public = parse_npm_value(&json!({
            "name": "public-registry-origin",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "public-registry-origin",
                    "version": "1.0.0",
                    "dependencies": {"lodash": "4.17.20"}
                },
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
                }
            }
        }))
        .unwrap();
        assert!(public[0].enrichable);
    }

    #[test]
    fn npm_public_tarball_paths_must_match_the_package_identity() {
        assert!(npm_public_tarball_matches(
            "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
            "lodash",
            "4.17.20"
        ));
        assert!(npm_public_tarball_matches(
            "https://registry.npmjs.org/%40scope%2Fpackage/-/package-1.2.3.tgz",
            "@scope/package",
            "1.2.3"
        ));
        assert!(npm_public_tarball_matches(
            "https://registry.npmjs.org/@scope/package/-/package-1.2.3.tgz",
            "@scope/package",
            "1.2.3"
        ));

        let error = parse_npm_value(&json!({
            "name": "public-path-confusion",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "public-path-confusion",
                    "version": "1.0.0",
                    "dependencies": {"lodash": "4.17.20"}
                },
                "node_modules/lodash": {
                    "version": "4.17.20",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
                }
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = error else {
            panic!("mismatched public npm tarball returned an I/O error");
        };
        assert!(message.contains("does not match package \"lodash\" version \"4.17.20\""));
    }

    #[test]
    fn npm_required_dependency_edges_must_resolve_to_installed_records() {
        let error = parse_npm_value(&json!({
            "name": "missing-required-edge",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "missing-required-edge",
                    "version": "1.0.0",
                    "dependencies": {"lodash": "4.17.20"},
                    "optionalDependencies": {"optional-package": "1.0.0"},
                    "peerDependencies": {"peer-package": "1.0.0"}
                },
                "node_modules/safe-source": {
                    "version": "git+https://example.test/safe.git#abc"
                }
            }
        }))
        .unwrap_err();
        let ParseError::Invalid { message, .. } = error else {
            panic!("missing required npm edge returned an I/O error");
        };
        assert!(message.contains("required dependency \"lodash\""));
        assert!(message.contains("no installed package record"));
    }

    #[test]
    fn preserves_explicit_npm_nonregistry_records_without_enrichment() {
        let packages = parse_npm_value(&json!({
            "name": "strict-fixture",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "strict-fixture",
                    "version": "1.0.0",
                    "workspaces": ["packages/*"],
                    "dependencies": {
                        "alias": "npm:actual-package@3.0.0",
                        "bare-secret-source": "file:../bare-secret-source",
                        "git-no-version": "git+https://example.test/no-version.git#abc",
                        "git-nonsemver": "git+file:///tmp/nonsemver#abc",
                        "git-package": "github:example/repo#abc",
                        "gitlab-package": "gitlab:example/repo#abc",
                        "opaque-secret-source": "file:../opaque-secret-source",
                        "private-package": "6.0.0",
                        "relative-credential-source": "../user:password@private.example/repository",
                        "relative-secret-source": "../private#token=secret",
                        "registry-package": "2.0.0",
                        "scp-source": "git@private.example:owner/repo.git#token=secret",
                        "secret-source": "https://user:password@private.example/package.tgz?token=secret#fragment",
                        "url-package": "https://example.test/package.tgz"
                    }
                },
                "node_modules/workspace-package": {
                    "resolved": "packages/workspace-package",
                    "link": true
                },
                "packages/workspace-package": {
                    "name": "workspace-package",
                    "version": "1.0.0"
                },
                "node_modules/registry-package": {
                    "version": "2.0.0",
                    "resolved": "https://registry.npmjs.org/registry-package/-/registry-package-2.0.0.tgz"
                },
                "node_modules/alias": {
                    "name": "actual-package",
                    "version": "3.0.0",
                    "resolved": "https://registry.npmjs.org/actual-package/-/actual-package-3.0.0.tgz"
                },
                "node_modules/bare-secret-source": {
                    "version": "folder?token=secret/package.tgz",
                    "resolved": "file:../bare-secret-source"
                },
                "node_modules/git-package": {
                    "version": "4.0.0",
                    "resolved": "git+ssh://git@example.test/repo.git#abc"
                },
                "node_modules/git-no-version": {
                    "resolved": "git+https://example.test/no-version.git#abc"
                },
                "node_modules/git-nonsemver": {
                    "version": "dev",
                    "resolved": "git+file:///tmp/nonsemver#abc"
                },
                "node_modules/gitlab-package": {
                    "version": "branch",
                    "resolved": "gitlab:example/repo#abc"
                },
                "node_modules/opaque-secret-source": {
                    "version": "user:password@private.example/path/package.tgz",
                    "resolved": "file:../opaque-secret-source"
                },
                "node_modules/private-package": {
                    "version": "6.0.0",
                    "resolved": "https://npm.private.example/private-package/-/private-package-6.0.0.tgz"
                },
                "node_modules/relative-credential-source": {
                    "version": "../user:password@private.example/repository"
                },
                "node_modules/relative-secret-source": {
                    "resolved": "../private#token=secret"
                },
                "node_modules/scp-source": {
                    "resolved": "git@private.example:owner/repo.git#token=secret"
                },
                "node_modules/secret-source": {
                    "resolved": "https://user:password@private.example/package.tgz?token=secret#fragment"
                },
                "node_modules/url-package": {
                    "version": "5.0.0",
                    "resolved": "https://example.test/package.tgz"
                }
            }
        }))
        .unwrap();

        assert_eq!(packages.len(), 14);
        let packages = packages
            .into_iter()
            .map(|package| (package.name.clone(), package))
            .collect::<BTreeMap<_, _>>();
        assert!(packages["registry-package"].enrichable);
        assert!(packages["actual-package"].enrichable);
        assert_eq!(packages["bare-secret-source"].version, "folder");
        assert!(!packages["bare-secret-source"].enrichable);
        assert!(!packages["git-package"].enrichable);
        assert!(!packages["git-no-version"].enrichable);
        assert!(
            packages["git-no-version"]
                .version
                .starts_with("git+https://")
        );
        assert_eq!(packages["git-nonsemver"].version, "dev");
        assert!(!packages["git-nonsemver"].enrichable);
        assert_eq!(packages["gitlab-package"].version, "branch");
        assert!(!packages["gitlab-package"].enrichable);
        assert_eq!(
            packages["opaque-secret-source"].version,
            "[redacted-source]"
        );
        assert!(!packages["opaque-secret-source"].enrichable);
        assert!(!packages["private-package"].enrichable);
        assert_eq!(
            packages["relative-credential-source"].version,
            "[redacted-source]"
        );
        assert!(!packages["relative-credential-source"].enrichable);
        assert_eq!(packages["relative-secret-source"].version, "../private");
        assert!(!packages["relative-secret-source"].enrichable);
        assert_eq!(
            packages["scp-source"].version,
            "git@private.example:owner/repo.git"
        );
        assert!(!packages["scp-source"].enrichable);
        assert_eq!(
            packages["secret-source"].version,
            "https://private.example/package.tgz"
        );
        assert!(!packages["secret-source"].enrichable);
        assert!(!packages["url-package"].enrichable);
        assert!(!packages.contains_key("workspace-package"));
        assert!(!packages.contains_key("alias"));
        assert_eq!(
            npm_lock_report_coordinate("?token=secret"),
            "[redacted-source]"
        );
        for credential_shaped in [
            "./user:password@private.example/repository",
            "../user:password@private.example/repository",
            "/user:password@private.example/repository",
            "file:../user:password@private.example/repository",
            "file:///user:password@private.example/repository",
            "file:///user%3Apassword%40private.example/repository",
        ] {
            assert_eq!(
                npm_lock_report_coordinate(credential_shaped),
                "[redacted-source]",
                "credential-shaped source {credential_shaped:?} was not redacted"
            );
        }

        for source in [
            "bitbucket:example/repo#abc",
            "gist:example/repo#abc",
            "gitlab:example/repo#abc",
            "git+file:///tmp/repo#abc",
        ] {
            assert!(npm_lock_source_locator(source));
            assert_eq!(
                npm_lock_resolved_source(Some(source)).unwrap(),
                NpmResolvedSource::Nonregistry
            );
        }
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
    fn legacy_npm_v1_never_enriches_explicit_source_locators() {
        let packages = parse_npm_value(&json!({
            "name": "legacy-source-fixture",
            "lockfileVersion": 1,
            "dependencies": {
                "registry-package": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/registry-package/-/registry-package-1.0.0.tgz"
                },
                "git-package": {"version": "git+https://example.test/repo.git#abc"},
                "file-package": {"version": "file:../package"},
                "raw-source": {
                    "version": "folder?token=secret/package.tgz",
                    "resolved": "file:../raw-source"
                },
                "invalid-public-version": {
                    "version": "^1.0.0",
                    "resolved": "https://registry.npmjs.org/invalid-public-version/-/invalid-public-version-1.0.0.tgz"
                },
                "url-package": {"version": "https://user:password@example.test/package.tgz?token=secret#fragment"}
            }
        }))
        .unwrap();

        assert_eq!(packages.len(), 6);
        for package in &packages {
            assert_eq!(package.enrichable, package.name == "registry-package");
        }
        let raw_source = packages
            .iter()
            .find(|package| package.name == "raw-source")
            .expect("legacy raw source package");
        assert_eq!(raw_source.version, "folder");
        let url_package = packages
            .iter()
            .find(|package| package.name == "url-package")
            .expect("legacy URL package");
        assert_eq!(url_package.version, "https://example.test/package.tgz");
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
        assert!(!result[0].direct_known);
        assert!(!result[0].dev_known);
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
