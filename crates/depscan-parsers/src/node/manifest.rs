use super::*;

pub(crate) fn parse_package_json_text(path: &Path, text: &str) -> Result<Json, ParseError> {
    let value: Json = serde_json::from_str(text).map_err(|error| invalid(path, error))?;
    if !value.is_object() {
        return Err(invalid(
            path,
            "package.json must contain a JSON object at the document root",
        ));
    }
    Ok(value)
}

pub(crate) fn read_package_json(path: &Path) -> Result<Json, ParseError> {
    let text = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
    parse_package_json_text(path, &text)
}

pub(crate) fn validated_package_json_root(
    root_manifest: &Path,
) -> Result<(PathBuf, PathBuf), ParseError> {
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

pub(crate) fn read_validated_root_package_json(path: &Path) -> Result<Json, ParseError> {
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

pub(crate) fn npm_manifest_constraint_is_registry(range: &str) -> bool {
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

pub(crate) fn parse_package_json_value(
    path: &Path,
    value: &Json,
) -> Result<Vec<Package>, ParseError> {
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

pub(crate) fn workspace_patterns(path: &Path, value: &Json) -> Result<Vec<String>, ParseError> {
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

pub(crate) fn workspace_manifests(
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

pub(crate) fn parse_package_json_project(root_manifest: &Path) -> Result<Vec<Package>, ParseError> {
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
