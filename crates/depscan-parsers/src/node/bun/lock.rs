use super::*;

pub(crate) fn parse_bun_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
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
