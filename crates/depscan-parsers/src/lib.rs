//! Offline, filesystem-only dependency parsers.

use depscan_core::{DetectedSource, Ecosystem, EcosystemParser, Package, ParseError, SourceKind};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde_json::Value as Json;
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::{Path, PathBuf},
};
use toml::Value as Toml;
use walkdir::WalkDir;

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

fn node_direct_names(root: &Path) -> HashSet<String> {
    let mut names = HashSet::new();
    for path in sorted_project_files(root, &["json"])
        .into_iter()
        .filter(|p| p.file_name().and_then(|x| x.to_str()) == Some("package.json"))
    {
        if let Ok(text) = fs::read_to_string(path) {
            if let Ok(value) = serde_json::from_str::<Json>(&text) {
                for key in [
                    "dependencies",
                    "devDependencies",
                    "optionalDependencies",
                    "peerDependencies",
                ] {
                    if let Some(obj) = value.get(key).and_then(Json::as_object) {
                        names.extend(obj.keys().cloned());
                    }
                }
            }
        }
    }
    names
}

fn parse_package_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let root = path.parent().unwrap_or(Path::new("."));
    let direct = node_direct_names(root);
    let value: Json = serde_json::from_str(&text).map_err(|e| invalid(path, e))?;
    let mut packages = Vec::new();
    if let Some(map) = value.get("packages").and_then(Json::as_object) {
        for (key, entry) in map {
            if key.is_empty() || entry.get("link").and_then(Json::as_bool) == Some(true) {
                continue;
            }
            if let Some(version) = entry.get("version").and_then(Json::as_str) {
                let name = key.strip_prefix("node_modules/").unwrap_or(key);
                if name.contains("node_modules/") {
                    continue;
                }
                let mut pkg = Package::new(Ecosystem::Npm, name, version, path.to_path_buf());
                pkg.direct = direct.contains(name);
                pkg.dev = entry.get("dev").and_then(Json::as_bool).unwrap_or(false);
                packages.push(pkg);
            }
        }
    } else if let Some(deps) = value.get("dependencies") {
        parse_legacy_npm_tree(deps, path, &direct, &mut packages);
    }
    Ok(dedup(packages))
}
fn parse_legacy_npm_tree(
    node: &Json,
    path: &Path,
    direct: &HashSet<String>,
    out: &mut Vec<Package>,
) {
    if let Some(map) = node.as_object() {
        for (name, entry) in map {
            if let Some(version) = entry.get("version").and_then(Json::as_str) {
                let mut p = Package::new(Ecosystem::Npm, name, version, path.to_path_buf());
                p.direct = direct.contains(name);
                p.dev = entry.get("dev").and_then(Json::as_bool).unwrap_or(false);
                out.push(p);
            }
            if let Some(children) = entry.get("dependencies") {
                parse_legacy_npm_tree(children, path, direct, out);
            }
        }
    }
}

fn parse_bun_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    // Bun's text lockfile is JSONC. Strip comments/trailing commas without pretending strings are comments.
    let cleaned = strip_jsonc(&text);
    let value: Json = serde_json::from_str(&cleaned).map_err(|e| invalid(path, e))?;
    let root = path.parent().unwrap_or(Path::new("."));
    let direct = node_direct_names(root);
    let mut output = Vec::new();
    if let Some(map) = value.get("packages").and_then(Json::as_object) {
        for (name, entry) in map {
            let version = entry.get("version").and_then(Json::as_str).or_else(|| {
                entry
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(Json::as_str)
            });
            if let Some(version) = version {
                if !name.starts_with("workspace:") {
                    let mut p = Package::new(Ecosystem::Npm, name, version, path.to_path_buf());
                    p.direct = direct.contains(name);
                    output.push(p);
                }
            }
        }
    }
    Ok(dedup(output))
}
fn strip_jsonc(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        if ch == '"' {
            quoted = !quoted;
            result.push(ch);
            continue;
        }
        if !quoted && ch == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for c in chars.by_ref() {
                if c == '\n' {
                    result.push('\n');
                    break;
                }
            }
            continue;
        }
        result.push(ch);
    }
    let mut out = String::new();
    let mut iter = result.chars().peekable();
    while let Some(ch) = iter.next() {
        if ch == ',' {
            let mut spaces = String::new();
            while matches!(iter.peek(), Some(c) if c.is_whitespace()) {
                spaces.push(iter.next().unwrap());
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
    out
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
            if let Some(raw) = key.as_str() {
                if let Some((name, version)) = parse_pnpm_key(raw) {
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
            SourceKind::RequirementsTxt => parse_requirements(&source.path, &mut HashSet::new()),
            SourceKind::PyProject => parse_pyproject(&source.path),
            _ => Err(invalid(&source.path, "unexpected source kind")),
        }
    }
}
fn parse_python_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let value: Toml = text.parse().map_err(|e| invalid(path, e))?;
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
fn parse_requirements(
    path: &Path,
    seen: &mut HashSet<PathBuf>,
) -> Result<Vec<Package>, ParseError> {
    let canonical = path.to_path_buf();
    if !seen.insert(canonical) {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with("--hash") || line.starts_with("--") {
            continue;
        }
        if let Some(include) = line
            .strip_prefix("-r ")
            .or_else(|| line.strip_prefix("--requirement "))
        {
            out.extend(parse_requirements(
                &path.parent().unwrap_or(Path::new(".")).join(include.trim()),
                seen,
            )?);
            continue;
        }
        if let Some((name, version)) = line.split_once("==") {
            let mut p = Package::new(
                Ecosystem::PyPI,
                name.trim(),
                version.split(';').next().unwrap_or(version).trim(),
                path.to_path_buf(),
            );
            p.direct = true;
            out.push(p);
        } else if let Some(name) = line.split(['<', '>', '~', '!', '=', ';']).next() {
            if !name.trim().is_empty() {
                let mut p = Package::new(Ecosystem::PyPI, name.trim(), line, path.to_path_buf());
                p.direct = true;
                p.resolved_from_range = true;
                out.push(p);
            }
        }
    }
    Ok(dedup(out))
}
fn parse_pyproject(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let value: Toml = text.parse().map_err(|e| invalid(path, e))?;
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
                    for attr in e.attributes().flatten() {
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
fn cargo_direct_names(root: &Path) -> HashSet<String> {
    let mut names = HashSet::new();
    for path in sorted_project_files(root, &["toml"])
        .into_iter()
        .filter(|p| p.file_name().and_then(|x| x.to_str()) == Some("Cargo.toml"))
    {
        if let Ok(text) = fs::read_to_string(path) {
            if let Ok(value) = text.parse::<Toml>() {
                for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
                    if let Some(tbl) = value.get(section).and_then(Toml::as_table) {
                        names.extend(tbl.keys().cloned());
                    }
                }
                if let Some(tbl) = value
                    .get("workspace")
                    .and_then(Toml::as_table)
                    .and_then(|x| x.get("dependencies"))
                    .and_then(Toml::as_table)
                {
                    names.extend(tbl.keys().cloned());
                }
            }
        }
    }
    names
}
fn parse_cargo_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let value: Toml = text.parse().map_err(|e| invalid(path, e))?;
    let direct = cargo_direct_names(path.parent().unwrap_or(Path::new(".")));
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
            p.direct = direct.contains(name);
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
    let text = fs::read_to_string(path).map_err(|e| io_error(path, e))?;
    let value: Toml = text.parse().map_err(|e| invalid(path, e))?;
    let mut out = Vec::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = value.get(section).and_then(Toml::as_table) {
            for (name, entry) in table {
                let version = entry.as_str().map(str::to_owned).or_else(|| {
                    entry
                        .as_table()
                        .and_then(|t| t.get("version"))
                        .and_then(Toml::as_str)
                        .map(str::to_owned)
                });
                if let Some(version) = version {
                    let mut p =
                        Package::new(Ecosystem::CratesIo, name, version, path.to_path_buf());
                    p.direct = true;
                    p.dev = section == "dev-dependencies";
                    p.resolved_from_range = true;
                    out.push(p);
                }
            }
        }
    }
    Ok(dedup(out))
}

fn dedup(packages: Vec<Package>) -> Vec<Package> {
    let mut map: BTreeMap<String, Package> = BTreeMap::new();
    for p in packages {
        let key = format!("{}:{}:{}", p.ecosystem.osv_name(), p.name, p.version);
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
    use std::fs;
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
    fn parses_pnpm_scoped_key() {
        assert_eq!(
            parse_pnpm_key("/@scope/pkg@1.2.3(peer@2)"),
            Some(("@scope/pkg", "1.2.3"))
        );
    }
}
