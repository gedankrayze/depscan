use super::*;

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
