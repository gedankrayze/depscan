use super::*;

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

pub(crate) fn sorted_dotnet_files(root: &Path) -> Vec<PathBuf> {
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

pub(crate) fn is_dotnet_project(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            ["csproj", "fsproj", "vbproj"]
                .iter()
                .any(|expected| extension.eq_ignore_ascii_case(expected))
        })
}

pub(crate) fn is_nuget_lock_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    file_name == "packages.lock.json"
        || (file_name.starts_with("packages.") && file_name.ends_with(".lock.json"))
}

pub(crate) fn is_packages_config(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some("packages.config")
}

pub(crate) fn project_lock_file(project: &Path) -> Option<PathBuf> {
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

pub(crate) fn parse_packages_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
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

mod manifests;
mod xml_model;
mod xml_reader;

pub(crate) use manifests::*;
pub(crate) use xml_model::*;
pub(crate) use xml_reader::*;
