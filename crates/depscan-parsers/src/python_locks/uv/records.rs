use super::*;

pub(super) fn parse_uv_package(
    value: &Toml,
    path: &Path,
    index: usize,
) -> Result<UvPackage, ParseError> {
    let context = format!("uv package entry {index}");
    let table = value
        .as_table()
        .ok_or_else(|| invalid(path, format!("{context} must be a table")))?;
    let display_name = required_string(table, "name", path, &context)?.to_owned();
    let name = normalized_name(&display_name, path, &context)?;
    let source = parse_uv_source(
        table
            .get("source")
            .ok_or_else(|| invalid(path, format!("{context} is missing source")))?,
        path,
        &context,
    )?;
    let version = optional_version(table.get("version"), path, &context)?;
    if version.is_none() && !source.allows_missing_version() {
        return Err(invalid(
            path,
            format!("{context} is missing a resolved version"),
        ));
    }
    let dependencies = optional_uv_dependency_array(table, "dependencies", path, &context)?;
    let optional_dependencies =
        optional_uv_dependency_groups(table, "optional-dependencies", path, &context)?;
    if table.contains_key("dev-dependencies") && table.contains_key("dependency-groups") {
        return Err(invalid(
            path,
            format!("{context} declares both dev-dependencies and dependency-groups"),
        ));
    }
    let dev_dependencies = optional_uv_dependency_groups(
        table,
        if table.contains_key("dev-dependencies") {
            "dev-dependencies"
        } else {
            "dependency-groups"
        },
        path,
        &context,
    )?;
    Ok(UvPackage {
        id: UvPackageId {
            name,
            version,
            source,
        },
        display_name,
        dependencies,
        optional_dependencies,
        dev_dependencies,
    })
}

pub(super) fn parse_uv_source(
    value: &Toml,
    path: &Path,
    context: &str,
) -> Result<PythonSource, ParseError> {
    let table = value
        .as_table()
        .ok_or_else(|| invalid(path, format!("{context} source must be a table")))?;
    let kinds = [
        "registry",
        "git",
        "url",
        "path",
        "directory",
        "editable",
        "virtual",
    ];
    let present: Vec<_> = kinds
        .into_iter()
        .filter(|kind| table.contains_key(*kind))
        .collect();
    if present.len() != 1 {
        return Err(invalid(
            path,
            format!("{context} source must declare exactly one supported source kind"),
        ));
    }
    for key in table.keys() {
        if !kinds.contains(&key.as_str()) && !(present[0] == "url" && key == "subdirectory") {
            return Err(invalid(
                path,
                format!("{context} source contains unsupported field {key:?}"),
            ));
        }
    }
    if let Some(subdirectory) = table.get("subdirectory")
        && subdirectory.as_str().is_none()
    {
        return Err(invalid(
            path,
            format!("{context} source subdirectory must be a string"),
        ));
    }
    let raw = table[present[0]]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            invalid(
                path,
                format!("{context} source {} must be a non-empty string", present[0]),
            )
        })?
        .to_owned();
    Ok(match present[0] {
        "registry" => PythonSource::Registry(raw),
        "git" => PythonSource::Git(raw),
        "url" => PythonSource::Url(raw),
        "path" => PythonSource::Path(raw),
        "directory" => PythonSource::Directory(raw),
        "editable" => PythonSource::Editable(raw),
        "virtual" => PythonSource::Virtual(raw),
        _ => unreachable!(),
    })
}

fn parse_uv_dependency(
    value: &Toml,
    path: &Path,
    context: &str,
    strict: bool,
) -> Result<UvDependency, ParseError> {
    let table = value
        .as_table()
        .ok_or_else(|| invalid(path, format!("{context} dependency must be a table")))?;
    if strict {
        for key in table.keys() {
            if !matches!(
                key.as_str(),
                "name" | "version" | "source" | "extra" | "marker"
            ) {
                return Err(invalid(
                    path,
                    format!("{context} dependency contains unsupported field {key:?}"),
                ));
            }
        }
    }
    let display_name = required_string(table, "name", path, context)?;
    let name = normalized_name(display_name, path, context)?;
    let version = optional_version(table.get("version"), path, context)?;
    let source = table
        .get("source")
        .map(|source| parse_uv_source(source, path, context))
        .transpose()?;
    if table.contains_key("extra") && table.contains_key("extras") {
        return Err(invalid(
            path,
            format!("{context} dependency declares both extra and extras"),
        ));
    }
    let mut extras = BTreeSet::new();
    if let Some(value) = table.get("extra").or_else(|| table.get("extras")) {
        let values = value
            .as_array()
            .ok_or_else(|| invalid(path, format!("{context} dependency extra must be an array")))?;
        for extra in values {
            let extra = extra
                .as_str()
                .filter(|extra| !extra.is_empty())
                .ok_or_else(|| {
                    invalid(
                        path,
                        format!("{context} dependency extras must be non-empty strings"),
                    )
                })?;
            extras.insert(extra.to_owned());
        }
    }
    if let Some(marker) = table.get("marker")
        && marker.as_str().is_none()
    {
        return Err(invalid(
            path,
            format!("{context} dependency marker must be a string"),
        ));
    }
    Ok(UvDependency {
        name,
        version,
        source,
        extras,
    })
}

fn optional_uv_dependency_array(
    table: &Table,
    key: &str,
    path: &Path,
    context: &str,
) -> Result<Vec<UvDependency>, ParseError> {
    table
        .get(key)
        .map(|value| parse_uv_dependency_array(value, path, context, true))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn optional_uv_dependency_groups(
    table: &Table,
    key: &str,
    path: &Path,
    context: &str,
) -> Result<BTreeMap<String, Vec<UvDependency>>, ParseError> {
    let Some(value) = table.get(key) else {
        return Ok(BTreeMap::new());
    };
    let groups = value
        .as_table()
        .ok_or_else(|| invalid(path, format!("{context} {key} must be a table")))?;
    let mut parsed = BTreeMap::new();
    for (group, dependencies) in groups {
        parsed.insert(
            group.clone(),
            parse_uv_dependency_array(
                dependencies,
                path,
                &format!("{context} {key} group {group:?}"),
                true,
            )?,
        );
    }
    Ok(parsed)
}

pub(super) fn parse_uv_dependency_array(
    value: &Toml,
    path: &Path,
    context: &str,
    strict: bool,
) -> Result<Vec<UvDependency>, ParseError> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid(path, format!("{context} must be an array")))?;
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            parse_uv_dependency(value, path, &format!("{context} entry {index}"), strict)
        })
        .collect()
}
