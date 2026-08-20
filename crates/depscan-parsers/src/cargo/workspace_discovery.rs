use super::*;

pub(crate) fn cargo_workspace_manifests(
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

pub(crate) fn cargo_project_manifests(
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

pub(crate) struct CargoProjectEvidence {
    pub(crate) packages: BTreeSet<CargoProjectPackageId>,
    pub(crate) declarations: Vec<CargoDeclaration>,
}

pub(crate) fn cargo_project_evidence(path: &Path) -> Result<CargoProjectEvidence, ParseError> {
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

pub(crate) fn cargo_project_declarations(path: &Path) -> Result<Vec<CargoDeclaration>, ParseError> {
    cargo_project_evidence(path).map(|evidence| evidence.declarations)
}
