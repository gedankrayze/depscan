use super::*;

mod entries;
mod links;

use entries::*;
use links::*;

pub(crate) fn parse_package_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
    let value: Json = serde_json::from_str(&text).map_err(|error| invalid(path, error))?;
    let document = value.as_object().ok_or_else(|| {
        invalid(
            path,
            "detected a non-object JSON document; expected an npm package-lock.json object",
        )
    })?;
    let lockfile_version = document
        .get("lockfileVersion")
        .and_then(Json::as_u64)
        .ok_or_else(|| {
            invalid(
                path,
                "detected JSON without an integer lockfileVersion; expected npm package-lock.json version 1, 2, or 3",
            )
        })?;
    let packages = match lockfile_version {
        1 => parse_legacy_package_lock(path, document)?,
        2 | 3 => parse_modern_package_lock(path, document, lockfile_version)?,
        version => {
            return Err(invalid(
                path,
                format!(
                    "detected unsupported npm package-lock.json lockfileVersion {version}; expected version 1, 2, or 3"
                ),
            ));
        }
    };
    Ok(dedup(packages))
}

fn parse_legacy_package_lock(
    path: &Path,
    document: &serde_json::Map<String, Json>,
) -> Result<Vec<Package>, ParseError> {
    let root = path.parent().unwrap_or(Path::new("."));
    let direct = node_direct_dependencies(root);
    let dependencies = document
        .get("dependencies")
        .and_then(Json::as_object)
        .ok_or_else(|| {
            invalid(
                path,
                "detected npm package-lock.json version 1 without a dependencies object; expected the legacy dependency tree",
            )
        })?;
    let mut packages = Vec::new();
    parse_legacy_npm_tree(dependencies, path, &direct, true, &mut packages);
    Ok(packages)
}

fn parse_modern_package_lock(
    path: &Path,
    document: &serde_json::Map<String, Json>,
    lockfile_version: u64,
) -> Result<Vec<Package>, ParseError> {
    let package_entries = document
        .get("packages")
        .and_then(Json::as_object)
        .ok_or_else(|| {
            invalid(
                path,
                format!(
                    "detected npm package-lock.json version {lockfile_version} without a packages object; expected the version 2/3 packages map"
                ),
            )
        })?;
    let link_targets = validate_link_targets(path, package_entries)?;
    let workspace_patterns = npm_lock_workspace_patterns(path, package_entries)?;
    let declarations = npm_lock_declarations(path, package_entries, &workspace_patterns)?;
    let local_descriptors = validate_link_declarations(
        path,
        package_entries,
        &link_targets,
        &workspace_patterns,
        &declarations,
    )?;
    parse_installed_entries(path, package_entries, &local_descriptors, &declarations)
}
