use super::*;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct CargoLockId {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) source: Option<String>,
}

pub(crate) struct CargoRawLockNode {
    pub(crate) id: CargoLockId,
    pub(crate) dependency_references: Vec<String>,
    pub(crate) replacement_reference: Option<String>,
    pub(crate) emit: bool,
    pub(crate) context: String,
}

pub(crate) struct CargoLockNode {
    pub(crate) id: CargoLockId,
    pub(crate) dependencies: Vec<usize>,
    pub(crate) replacement: Option<usize>,
    pub(crate) emit: bool,
}

pub(crate) struct CargoLockReference {
    pub(crate) name: String,
    pub(crate) version: Option<String>,
    pub(crate) source: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CargoScope {
    Production,
    Development,
    Unknown,
}

pub(crate) fn cargo_lock_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub(crate) fn cargo_normalize_lock_source(source: &str) -> Result<String, String> {
    if source.starts_with("sparse+") {
        return Url::parse(source)
            .map(|url| url.to_string())
            .map_err(|error| format!("invalid sparse registry source URL: {error}"));
    }
    let (prefix, kind, url) = if let Some(url) = source.strip_prefix("git+") {
        ("git+", "Git", url)
    } else if let Some(url) = source.strip_prefix("registry+") {
        ("registry+", "registry", url)
    } else if let Some(url) = source.strip_prefix("path+") {
        ("path+", "path", url)
    } else {
        return Err(format!("unsupported source identity {source:?}"));
    };
    let url = Url::parse(url).map_err(|error| format!("invalid {kind} source URL: {error}"))?;
    Ok(format!("{prefix}{url}"))
}

pub(crate) fn cargo_lock_node(
    path: &Path,
    context: &str,
    item: &toml::Table,
    emit: bool,
) -> Result<CargoRawLockNode, ParseError> {
    let name = item
        .get("name")
        .and_then(Toml::as_str)
        .filter(|name| cargo_lock_name_valid(name))
        .ok_or_else(|| invalid(path, format!("{context} is missing a valid package name")))?;
    let version = item
        .get("version")
        .and_then(Toml::as_str)
        .filter(|version| !version.is_empty())
        .ok_or_else(|| {
            invalid(
                path,
                format!("{context} is missing a non-empty string version"),
            )
        })?;
    semver::Version::parse(version).map_err(|error| {
        invalid(
            path,
            format!("{context} has invalid SemVer version {version:?}: {error}"),
        )
    })?;
    let source = item
        .get("source")
        .map(|source| {
            let source = source
                .as_str()
                .filter(|source| !source.is_empty())
                .ok_or_else(|| {
                    invalid(path, format!("{context} source must be a non-empty string"))
                })?;
            cargo_normalize_lock_source(source)
                .map_err(|error| invalid(path, format!("{context} has {error}")))
        })
        .transpose()?;
    let replacement_reference = item
        .get("replace")
        .map(|replacement| {
            replacement
                .as_str()
                .filter(|replacement| !replacement.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    invalid(
                        path,
                        format!("{context} replace must be a non-empty package ID string"),
                    )
                })
        })
        .transpose()?;
    if item.contains_key("dependencies") && replacement_reference.is_some() {
        return Err(invalid(
            path,
            format!("{context} cannot define both dependencies and replace"),
        ));
    }
    let dependency_references = match item.get("dependencies") {
        None => Vec::new(),
        Some(dependencies) => dependencies
            .as_array()
            .ok_or_else(|| invalid(path, format!("{context} dependencies must be an array")))?
            .iter()
            .enumerate()
            .map(|(index, dependency)| {
                dependency
                    .as_str()
                    .filter(|dependency| !dependency.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        invalid(
                            path,
                            format!(
                                "{context} dependency entry {index} must be a non-empty string"
                            ),
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    Ok(CargoRawLockNode {
        id: CargoLockId {
            name: name.to_owned(),
            version: version.to_owned(),
            source,
        },
        dependency_references,
        replacement_reference,
        emit,
        context: context.to_owned(),
    })
}

pub(crate) fn parse_cargo_lock_reference(
    path: &Path,
    context: &str,
    reference: &str,
) -> Result<CargoLockReference, ParseError> {
    if reference.trim() != reference
        || reference
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() && byte != b' ')
    {
        return Err(invalid(
            path,
            format!("{context} has malformed dependency reference {reference:?}"),
        ));
    }
    let (identity, source) = if let Some(open) = reference.rfind(" (") {
        if !reference.ends_with(')') {
            return Err(invalid(
                path,
                format!("{context} has malformed dependency reference {reference:?}"),
            ));
        }
        let source = &reference[open + 2..reference.len() - 1];
        if source.is_empty() || source.contains(' ') {
            return Err(invalid(
                path,
                format!("{context} has empty dependency source in {reference:?}"),
            ));
        }
        let source = cargo_normalize_lock_source(source).map_err(|error| {
            invalid(
                path,
                format!("{context} dependency reference {reference:?} has {error}"),
            )
        })?;
        (&reference[..open], Some(source))
    } else {
        if reference.contains(['(', ')']) {
            return Err(invalid(
                path,
                format!("{context} has malformed dependency reference {reference:?}"),
            ));
        }
        (reference, None)
    };
    let (name, version) = match identity.split_once(' ') {
        None => (identity, None),
        Some((name, version))
            if !name.is_empty() && !version.is_empty() && !version.contains(' ') =>
        {
            semver::Version::parse(version).map_err(|error| {
                invalid(
                    path,
                    format!(
                        "{context} dependency reference {reference:?} has invalid SemVer: {error}"
                    ),
                )
            })?;
            (name, Some(version.to_owned()))
        }
        _ => {
            return Err(invalid(
                path,
                format!("{context} has malformed dependency reference {reference:?}"),
            ));
        }
    };
    if !cargo_lock_name_valid(name) || (source.is_some() && version.is_none()) {
        return Err(invalid(
            path,
            format!("{context} has malformed dependency reference {reference:?}"),
        ));
    }
    Ok(CargoLockReference {
        name: name.to_owned(),
        version,
        source,
    })
}
