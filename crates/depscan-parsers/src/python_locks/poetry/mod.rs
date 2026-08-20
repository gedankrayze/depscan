use std::collections::{BTreeSet, HashSet};

use super::*;

mod manifest;

use manifest::poetry_direct_dependencies;

pub(crate) fn parse_poetry_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let value = read_toml(path)?;
    let root = value
        .as_table()
        .ok_or_else(|| invalid(path, "Poetry lockfile root must be a table"))?;
    let metadata = root
        .get("metadata")
        .and_then(Toml::as_table)
        .ok_or_else(|| invalid(path, "Poetry lockfile is missing a metadata table"))?;
    let lock_version = required_string(metadata, "lock-version", path, "Poetry metadata")?;
    let groups_format = poetry_groups_format(lock_version, path)?;
    let direct = poetry_direct_dependencies(path)?;
    let package_values = required_array(root, "package", path, "Poetry lockfile")?;
    let mut locked_names = HashSet::new();
    let mut output = Vec::with_capacity(package_values.len());
    for (index, value) in package_values.iter().enumerate() {
        let context = format!("Poetry package entry {index}");
        let table = value
            .as_table()
            .ok_or_else(|| invalid(path, format!("{context} must be a table")))?;
        let display_name = required_string(table, "name", path, &context)?.to_owned();
        let name = normalized_name(&display_name, path, &context)?;
        let version = required_string(table, "version", path, &context)?.to_owned();
        validate_version(&version, path, &context)?;
        required_bool(table, "optional", path, &context)?;
        let develop = table
            .get("develop")
            .map(|value| {
                value
                    .as_bool()
                    .ok_or_else(|| invalid(path, format!("{context} develop must be a boolean")))
            })
            .transpose()?
            .unwrap_or(false);
        let source = poetry_source(table.get("source"), develop, path, &context)?;
        let dev = poetry_dev_classification(table, groups_format, path, &context)?;
        locked_names.insert(name.clone());
        let mut package = Package::new(Ecosystem::PyPI, display_name, version, path.to_path_buf());
        package.enrichable = source.enrichable();
        if let Some(dev) = dev {
            package.dev = dev;
            package.dev_known = true;
        } else {
            package.dev_known = false;
        }
        if let Some(direct) = &direct {
            package.direct =
                direct.production.contains(&name) || direct.development.contains(&name);
            package.direct_known = true;
        } else {
            package.direct_known = false;
        }
        output.push(package);
    }
    if let Some(direct) = direct {
        for name in direct.production.union(&direct.development) {
            if !locked_names.contains(name) {
                return Err(invalid(
                    path,
                    format!("Poetry manifest dependency {name:?} has no locked package entry"),
                ));
            }
        }
    }
    Ok(dedup(output))
}

#[derive(Clone, Copy)]
enum PoetryGroupsFormat {
    Category,
    Optional,
    Groups,
}

#[derive(Default)]
struct PoetryDirectDependencies {
    production: BTreeSet<String>,
    development: BTreeSet<String>,
}

fn poetry_groups_format(version: &str, path: &Path) -> Result<PoetryGroupsFormat, ParseError> {
    match version {
        "1.0" | "1.1" => Ok(PoetryGroupsFormat::Category),
        "2.0" => Ok(PoetryGroupsFormat::Optional),
        "2.1" => Ok(PoetryGroupsFormat::Groups),
        _ => Err(invalid(
            path,
            format!(
                "unsupported Poetry lock-version {version:?}; supported versions are 1.0, 1.1, 2.0, and 2.1"
            ),
        )),
    }
}

fn poetry_dev_classification(
    table: &Table,
    format: PoetryGroupsFormat,
    path: &Path,
    context: &str,
) -> Result<Option<bool>, ParseError> {
    match format {
        PoetryGroupsFormat::Category => poetry_category(table, path, context).map(Some),
        PoetryGroupsFormat::Optional => {
            if table.contains_key("category") && table.contains_key("groups") {
                return Err(invalid(
                    path,
                    format!("{context} declares both category and groups"),
                ));
            }
            if table.contains_key("category") {
                poetry_category(table, path, context).map(Some)
            } else if table.contains_key("groups") {
                poetry_groups(table, path, context).map(Some)
            } else {
                Ok(None)
            }
        }
        PoetryGroupsFormat::Groups => poetry_groups(table, path, context).map(Some),
    }
}

fn poetry_category(table: &Table, path: &Path, context: &str) -> Result<bool, ParseError> {
    match required_string(table, "category", path, context)? {
        "main" => Ok(false),
        "dev" => Ok(true),
        category => Err(invalid(
            path,
            format!("{context} has unsupported category {category:?}"),
        )),
    }
}

fn poetry_groups(table: &Table, path: &Path, context: &str) -> Result<bool, ParseError> {
    let groups = required_array(table, "groups", path, context)?;
    if groups.is_empty() {
        return Err(invalid(path, format!("{context} groups must not be empty")));
    }
    let mut main = false;
    for group in groups {
        let group = group
            .as_str()
            .filter(|group| !group.is_empty())
            .ok_or_else(|| {
                invalid(
                    path,
                    format!("{context} groups must contain non-empty strings"),
                )
            })?;
        main |= group == "main";
    }
    Ok(!main)
}

fn poetry_source(
    value: Option<&Toml>,
    develop: bool,
    path: &Path,
    context: &str,
) -> Result<PythonSource, ParseError> {
    let Some(value) = value else {
        return Ok(PythonSource::Registry(PYPI_INDEX.to_owned()));
    };
    let table = value
        .as_table()
        .ok_or_else(|| invalid(path, format!("{context} source must be a table")))?;
    for key in table.keys() {
        if !matches!(
            key.as_str(),
            "type" | "url" | "reference" | "resolved_reference" | "subdirectory"
        ) {
            return Err(invalid(
                path,
                format!("{context} source contains unsupported field {key:?}"),
            ));
        }
    }
    for key in ["reference", "resolved_reference", "subdirectory"] {
        if let Some(value) = table.get(key)
            && value.as_str().is_none()
        {
            return Err(invalid(
                path,
                format!("{context} source {key} must be a string"),
            ));
        }
    }
    let source_type = required_string(table, "type", path, &format!("{context} source"))?;
    let url = required_string(table, "url", path, &format!("{context} source"))?.to_owned();
    Ok(match source_type {
        "legacy" | "registry" => PythonSource::Registry(url),
        "git" => PythonSource::Git(url),
        "url" => PythonSource::Url(url),
        "file" | "path" => PythonSource::Path(url),
        "directory" => {
            if develop {
                PythonSource::Editable(url)
            } else {
                PythonSource::Directory(url)
            }
        }
        "editable" => PythonSource::Editable(url),
        other => {
            return Err(invalid(
                path,
                format!("{context} has unsupported Poetry source type {other:?}"),
            ));
        }
    })
}
