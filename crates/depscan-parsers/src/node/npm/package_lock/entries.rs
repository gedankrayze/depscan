use super::*;

pub(super) fn parse_installed_entries(
    path: &Path,
    package_entries: &serde_json::Map<String, Json>,
    local_descriptors: &BTreeSet<String>,
    declarations: &NpmLockDeclarations,
) -> Result<Vec<Package>, ParseError> {
    let mut packages = Vec::new();
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
                format!("npm package entry {key:?} field \"resolved\" must be a non-empty string"),
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
        let package_name = entry
            .get("name")
            .map_or(Ok(location.name.as_str()), |name| {
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
        let identity_declared = declaration.map_or(package_name == location.name, |value| {
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
        let mut package = Package::new(Ecosystem::Npm, package_name, &version, path.to_path_buf());
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
    Ok(packages)
}
