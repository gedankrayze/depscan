use super::*;

pub(crate) fn parse_npm_lock_declaration(
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

pub(crate) fn npm_lock_declarations(
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

pub(crate) fn npm_lock_link_target(
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

pub(crate) fn npm_descriptor_fallback_name(target: &str) -> Option<String> {
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
