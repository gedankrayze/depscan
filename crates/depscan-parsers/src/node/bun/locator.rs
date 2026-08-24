use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BunResolution<'a> {
    Registry { name: &'a str, version: &'a str },
    Workspace { name: &'a str, path: &'a str },
    Path,
    Git,
    Github,
    Tarball,
    Root,
}

pub(crate) fn parse_bun_locator(locator: &str) -> Result<BunResolution<'_>, String> {
    if locator == "@root:" {
        return Ok(BunResolution::Root);
    }

    let separator = if locator.starts_with('@') {
        let slash = locator
            .find('/')
            .ok_or_else(|| "scoped package name is missing '/'".to_owned())?;
        locator[slash + 1..]
            .find('@')
            .map(|index| slash + 1 + index)
            .ok_or_else(|| "scoped package locator is missing '@resolution'".to_owned())?
    } else {
        locator
            .find('@')
            .ok_or_else(|| "package locator is missing '@resolution'".to_owned())?
    };
    let name = &locator[..separator];
    let resolution = &locator[separator + 1..];
    validate_bun_package_name(name)?;
    if resolution.is_empty() {
        return Err("package resolution is empty".to_owned());
    }

    if let Some(workspace_path) = resolution.strip_prefix("workspace:") {
        if workspace_path.is_empty() {
            return Err("workspace resolution path is empty".to_owned());
        }
        return Ok(BunResolution::Workspace {
            name,
            path: workspace_path,
        });
    }
    if resolution.starts_with("file:") || resolution.starts_with("link:") {
        if resolution
            .split_once(':')
            .is_none_or(|(_, value)| value.is_empty())
        {
            return Err("path resolution is empty".to_owned());
        }
        return Ok(BunResolution::Path);
    }
    if let Some(repository) = resolution.strip_prefix("git+") {
        if repository.is_empty() {
            return Err("git resolution is empty".to_owned());
        }
        return Ok(BunResolution::Git);
    }
    if let Some(repository) = resolution.strip_prefix("github:") {
        if repository.is_empty() {
            return Err("github resolution is empty".to_owned());
        }
        return Ok(BunResolution::Github);
    }
    if resolution.starts_with("http://")
        || resolution.starts_with("https://")
        || is_bun_tarball(resolution)
    {
        return Ok(BunResolution::Tarball);
    }

    semver::Version::parse(resolution)
        .map_err(|error| format!("registry resolution is not valid SemVer: {error}"))?;
    Ok(BunResolution::Registry {
        name,
        version: resolution,
    })
}

pub(crate) fn is_bun_tarball(resolution: &str) -> bool {
    let lowercase = resolution.to_ascii_lowercase();
    [".tgz", ".tar.gz", ".tar"]
        .iter()
        .any(|suffix| lowercase.ends_with(suffix))
}

pub(crate) fn validate_bun_package_name(name: &str) -> Result<(), String> {
    let valid = if let Some(scoped) = name.strip_prefix('@') {
        let mut parts = scoped.split('/');
        parts.next().is_some_and(|scope| !scope.is_empty())
            && parts.next().is_some_and(|package| !package.is_empty())
            && parts.next().is_none()
    } else {
        !name.is_empty() && !name.contains('/')
    };
    if !valid
        || name.chars().any(char::is_whitespace)
        || name.contains('\\')
        || matches!(name, "." | "..")
    {
        return Err("package name is malformed".to_owned());
    }
    Ok(())
}

pub(crate) fn validate_bun_locator_array(
    path: &Path,
    package_key: &str,
    items: &[Json],
    resolution: BunResolution<'_>,
    lockfile_version: BunLockVersion,
    workspaces: &HashMap<String, String>,
) -> Result<(), ParseError> {
    let error = |message: &str| {
        invalid(
            path,
            format!("Bun package {package_key:?} has malformed locator array: {message}"),
        )
    };
    let object_at = |index: usize| items.get(index).is_some_and(Json::is_object);
    let string_at = |index: usize| items.get(index).is_some_and(Json::is_string);

    match resolution {
        BunResolution::Registry { .. } => {
            if items.len() != 4 || !string_at(1) || !object_at(2) || !string_at(3) {
                return Err(error(
                    "registry entries must be [locator, registry, info, integrity]",
                ));
            }
            if lockfile_version >= BunLockVersion::V2 {
                let registry = items[1].as_str().expect("validated registry string");
                let integrity = items[3].as_str().expect("validated integrity string");
                if !bun_registry_integrity_is_valid(registry, integrity) {
                    return Err(error(
                        "version 2 and 3 off-registry npm entries require a supported integrity hash",
                    ));
                }
            }
        }
        BunResolution::Workspace {
            name,
            path: workspace_path,
        } => {
            let valid_shape = if lockfile_version == BunLockVersion::V0 {
                items.len() == 2 && object_at(1)
            } else {
                items.len() == 1
            };
            if !valid_shape {
                return Err(error(if lockfile_version == BunLockVersion::V0 {
                    "version 0 workspace entries must be [locator, info]"
                } else {
                    "version 1 through 3 workspace entries must contain only the locator"
                }));
            }
            let Some(workspace_name) = workspaces.get(workspace_path) else {
                return Err(error(
                    "workspace locator references an unknown workspace path",
                ));
            };
            if workspace_name != name {
                return Err(error(
                    "workspace locator package name does not match the referenced workspace",
                ));
            }
        }
        BunResolution::Path | BunResolution::Tarball => {
            if !(items.len() == 2 || items.len() == 3)
                || !object_at(1)
                || (items.len() == 3 && !string_at(2))
            {
                return Err(error(
                    "path and tarball entries must be [locator, info] with optional integrity",
                ));
            }
        }
        tag @ (BunResolution::Git | BunResolution::Github) => {
            if !(items.len() == 3 || items.len() == 4)
                || !object_at(1)
                || !string_at(2)
                || (items.len() == 4 && !string_at(3))
            {
                return Err(error(
                    "git entries must be [locator, info, resolved] with optional integrity",
                ));
            }
            let resolved = items[2].as_str().expect("validated git tag string");
            let enforce_safe_tag =
                tag == BunResolution::Github || lockfile_version >= BunLockVersion::V2;
            if enforce_safe_tag && !is_safe_bun_git_tag(resolved) {
                return Err(error("git resolved tag must be one safe path component"));
            }
        }
        BunResolution::Root => {
            if items.len() != 2 || !object_at(1) {
                return Err(error("root entries must be [\"@root:\", info]"));
            }
        }
    }
    Ok(())
}
