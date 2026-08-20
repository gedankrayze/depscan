use super::*;

pub(super) fn validate_link_targets(
    path: &Path,
    package_entries: &serde_json::Map<String, Json>,
) -> Result<BTreeMap<String, String>, ParseError> {
    // First validate link records without using them to suppress any
    // installed package. Declaration provenance is resolved only after
    // every concrete link target has been validated.
    let mut link_targets = BTreeMap::new();
    for (key, value) in package_entries {
        let entry = value
            .as_object()
            .ok_or_else(|| invalid(path, format!("npm package entry {key:?} must be an object")))?;
        npm_lock_optional_bool(path, key, entry, "dev")?;
        if let Some(resolved) = entry.get("resolved")
            && resolved
                .as_str()
                .filter(|resolved| !resolved.trim().is_empty())
                .is_none()
        {
            return Err(invalid(
                path,
                format!("npm package entry {key:?} field \"resolved\" must be a non-empty string"),
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
            let Some(target_entry) = package_entries.get(&target).and_then(Json::as_object) else {
                return Err(invalid(
                    path,
                    format!(
                        "npm link package entry {key:?} resolved target {target:?} does not name an existing package descriptor object"
                    ),
                ));
            };
            if target == key.as_str()
                || npm_lock_optional_bool(path, &target, target_entry, "link")? == Some(true)
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
    Ok(link_targets)
}

pub(super) fn validate_link_declarations(
    path: &Path,
    package_entries: &serde_json::Map<String, Json>,
    link_targets: &BTreeMap<String, String>,
    workspace_patterns: &NpmWorkspacePatterns,
    declarations: &NpmLockDeclarations,
) -> Result<BTreeSet<String>, ParseError> {
    let mut local_descriptors = BTreeSet::new();
    for (key, target) in link_targets {
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
            Some(Json::String(version)) if !version.trim().is_empty() => Some(version.as_str()),
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
            && npm_is_workspace_descriptor(path, target, workspace_patterns)?
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
            local_descriptors.insert(target.to_owned());
        }
    }
    Ok(local_descriptors)
}
