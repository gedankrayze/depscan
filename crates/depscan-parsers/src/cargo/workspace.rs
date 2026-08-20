use super::*;

pub(crate) fn cargo_dependency_tables(value: &Toml) -> Result<Vec<(&toml::Table, bool)>, String> {
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

pub(crate) fn cargo_manifest_declarations(
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

pub(crate) fn workspace_dependency_definitions(
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

pub(crate) fn workspace_path_list(
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

pub(crate) fn workspace_member_manifest(path: PathBuf) -> Option<PathBuf> {
    if path.is_dir() {
        Some(path.join("Cargo.toml"))
    } else if path.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml") {
        Some(path)
    } else {
        None
    }
}

pub(crate) fn workspace_member_matches(
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

pub(crate) fn relative_workspace_path(workspace_root: &Path, path: &Path) -> Option<PathBuf> {
    let canonical_root = fs::canonicalize(workspace_root).ok()?;
    let canonical_path = fs::canonicalize(path).ok()?;
    canonical_path
        .strip_prefix(canonical_root)
        .ok()
        .map(Path::to_path_buf)
}

pub(crate) fn excluded_workspace_member(
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
