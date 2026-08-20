use super::*;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct CargoProjectPackageId {
    pub(crate) name: String,
    pub(crate) version: String,
}

pub(crate) fn read_cargo_manifest(path: &Path) -> Result<Toml, ParseError> {
    let text = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
    toml::from_str(&text).map_err(|error| invalid(path, error))
}

pub(crate) fn cargo_workspace_package_version(
    path: &Path,
    value: &Toml,
) -> Result<Option<String>, ParseError> {
    let Some(version) = value
        .get("workspace")
        .and_then(Toml::as_table)
        .and_then(|workspace| workspace.get("package"))
        .and_then(Toml::as_table)
        .and_then(|package| package.get("version"))
    else {
        return Ok(None);
    };
    let version = version
        .as_str()
        .filter(|version| !version.is_empty())
        .ok_or_else(|| {
            invalid(
                path,
                "Cargo workspace package version must be a non-empty string",
            )
        })?;
    semver::Version::parse(version).map_err(|error| {
        invalid(
            path,
            format!("Cargo workspace package version {version:?} is invalid SemVer: {error}"),
        )
    })?;
    Ok(Some(version.to_owned()))
}

pub(crate) fn cargo_manifest_package_id(
    path: &Path,
    value: &Toml,
    workspace_version: Option<&str>,
) -> Result<CargoProjectPackageId, ParseError> {
    let package = value
        .get("package")
        .and_then(Toml::as_table)
        .ok_or_else(|| invalid(path, "Cargo workspace member is missing a [package] table"))?;
    let name = package
        .get("name")
        .and_then(Toml::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid(path, "Cargo package name must be a non-empty string"))?;
    let version = match package.get("version") {
        Some(Toml::String(version)) if !version.is_empty() => version.as_str(),
        Some(Toml::Table(version))
            if version.get("workspace").and_then(Toml::as_bool) == Some(true) =>
        {
            workspace_version.ok_or_else(|| {
                invalid(
                    path,
                    "Cargo package inherits version from missing [workspace.package].version",
                )
            })?
        }
        Some(_) => {
            return Err(invalid(
                path,
                "Cargo package version must be a non-empty string or inherit from the workspace",
            ));
        }
        None => "0.0.0",
    };
    semver::Version::parse(version).map_err(|error| {
        invalid(
            path,
            format!("Cargo package version {version:?} is invalid SemVer: {error}"),
        )
    })?;
    Ok(CargoProjectPackageId {
        name: name.to_owned(),
        version: version.to_owned(),
    })
}

pub(crate) fn dependency_field<'a>(
    manifest: &Path,
    alias: &str,
    table: &'a toml::Table,
    field: &str,
) -> Result<Option<&'a str>, ParseError> {
    table
        .get(field)
        .map(|value| {
            value.as_str().ok_or_else(|| {
                invalid(
                    manifest,
                    format!("Cargo dependency {alias:?} field {field:?} must be a string"),
                )
            })
        })
        .transpose()
}

pub(crate) fn parse_cargo_dependency(
    manifest: &Path,
    alias: &str,
    entry: &Toml,
    workspace_dependencies: Option<&BTreeMap<String, CargoDependencySpec>>,
) -> Result<CargoDependencySpec, ParseError> {
    if alias.is_empty() {
        return Err(invalid(manifest, "Cargo dependency name cannot be empty"));
    }
    if let Some(version) = entry.as_str() {
        return Ok(CargoDependencySpec {
            package_name: alias.to_owned(),
            version: Some(version.to_owned()),
            enrichable: true,
            local_path: None,
            source: CargoDependencySource::CratesIo,
        });
    }

    let table = entry.as_table().ok_or_else(|| {
        invalid(
            manifest,
            format!("Cargo dependency {alias:?} must be a string or table"),
        )
    })?;
    let package = dependency_field(manifest, alias, table, "package")?;
    if package.is_some_and(str::is_empty) {
        return Err(invalid(
            manifest,
            format!("Cargo dependency {alias:?} field \"package\" cannot be empty"),
        ));
    }

    if let Some(workspace) = table.get("workspace") {
        if workspace.as_bool() != Some(true) {
            return Err(invalid(
                manifest,
                format!("Cargo dependency {alias:?} field \"workspace\" must be true"),
            ));
        }
        for forbidden in [
            "version",
            "path",
            "git",
            "branch",
            "tag",
            "rev",
            "registry",
            "registry-index",
            "package",
            "default-features",
        ] {
            if table.contains_key(forbidden) {
                return Err(invalid(
                    manifest,
                    format!(
                        "inherited Cargo dependency {alias:?} cannot override field {forbidden:?}"
                    ),
                ));
            }
        }
        return workspace_dependencies
            .and_then(|dependencies| dependencies.get(alias))
            .cloned()
            .ok_or_else(|| {
                invalid(
                    manifest,
                    format!(
                        "Cargo dependency {alias:?} inherits from a missing [workspace.dependencies] entry"
                    ),
                )
            });
    }

    let version = dependency_field(manifest, alias, table, "version")?.map(str::to_owned);
    let path = dependency_field(manifest, alias, table, "path")?;
    let git = dependency_field(manifest, alias, table, "git")?;
    let registry = dependency_field(manifest, alias, table, "registry")?;
    let registry_index = dependency_field(manifest, alias, table, "registry-index")?;
    let mut git_selector = None;
    for selector in ["branch", "tag", "rev"] {
        let value = dependency_field(manifest, alias, table, selector)?;
        if value.is_some() && git.is_none() {
            return Err(invalid(
                manifest,
                format!("Cargo dependency {alias:?} field {selector:?} requires a \"git\" source"),
            ));
        }
        if let Some(value) = value {
            if git_selector.is_some() {
                return Err(invalid(
                    manifest,
                    format!("Cargo dependency {alias:?} declares conflicting Git selectors"),
                ));
            }
            git_selector = Some((selector.to_owned(), value.to_owned()));
        }
    }
    let source_count = [
        path.is_some(),
        git.is_some(),
        registry.is_some() || registry_index.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if source_count > 1 || (registry.is_some() && registry_index.is_some()) {
        return Err(invalid(
            manifest,
            format!("Cargo dependency {alias:?} declares conflicting sources"),
        ));
    }
    if version.is_none() && path.is_none() && git.is_none() {
        return Err(invalid(
            manifest,
            format!("Cargo dependency {alias:?} has no version, path, or git source"),
        ));
    }
    let local_path = path.map(|dependency_path| {
        manifest
            .parent()
            .unwrap_or(Path::new("."))
            .join(dependency_path)
    });
    let source = if local_path.is_some() {
        CargoDependencySource::Path
    } else if let Some(git) = git {
        CargoDependencySource::Git {
            url: git.to_owned(),
            selector: git_selector,
        }
    } else if let Some(registry_index) = registry_index {
        CargoDependencySource::RegistryIndex(registry_index.to_owned())
    } else if registry.is_some() {
        CargoDependencySource::RegistryName
    } else {
        CargoDependencySource::CratesIo
    };
    Ok(CargoDependencySpec {
        package_name: package.unwrap_or(alias).to_owned(),
        version,
        enrichable: path.is_none()
            && git.is_none()
            && registry.is_none()
            && registry_index.is_none(),
        local_path,
        source,
    })
}
