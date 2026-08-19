use std::collections::{BTreeSet, HashSet};

use super::*;

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

fn poetry_direct_dependencies(
    lock_path: &Path,
) -> Result<Option<PoetryDirectDependencies>, ParseError> {
    let Some(directory) = lock_path.parent() else {
        return Ok(None);
    };
    let manifest_path = directory.join("pyproject.toml");
    if !manifest_path.is_file() {
        return Ok(None);
    }
    let value = read_toml(&manifest_path)?;
    let root = value
        .as_table()
        .ok_or_else(|| invalid(&manifest_path, "Python manifest root must be a table"))?;
    let mut direct = PoetryDirectDependencies::default();
    if let Some(project) = root.get("project") {
        let project = project
            .as_table()
            .ok_or_else(|| invalid(&manifest_path, "project must be a table"))?;
        collect_requirement_array(
            project.get("dependencies"),
            &mut direct.production,
            &manifest_path,
            "project.dependencies",
        )?;
        collect_requirement_groups(
            project.get("optional-dependencies"),
            &mut direct.production,
            &manifest_path,
            "project.optional-dependencies",
        )?;
    }
    collect_requirement_groups(
        root.get("dependency-groups"),
        &mut direct.development,
        &manifest_path,
        "dependency-groups",
    )?;
    if let Some(poetry) = root
        .get("tool")
        .and_then(Toml::as_table)
        .and_then(|tool| tool.get("poetry"))
    {
        let poetry = poetry
            .as_table()
            .ok_or_else(|| invalid(&manifest_path, "tool.poetry must be a table"))?;
        collect_poetry_dependency_table(
            poetry.get("dependencies"),
            &mut direct.production,
            &manifest_path,
            "tool.poetry.dependencies",
            true,
        )?;
        collect_poetry_dependency_table(
            poetry.get("dev-dependencies"),
            &mut direct.development,
            &manifest_path,
            "tool.poetry.dev-dependencies",
            false,
        )?;
        if let Some(groups) = poetry.get("group") {
            let groups = groups
                .as_table()
                .ok_or_else(|| invalid(&manifest_path, "tool.poetry.group must be a table"))?;
            for (name, group) in groups {
                let group = group.as_table().ok_or_else(|| {
                    invalid(
                        &manifest_path,
                        format!("tool.poetry.group.{name} must be a table"),
                    )
                })?;
                let target = if name == "main" {
                    &mut direct.production
                } else {
                    &mut direct.development
                };
                collect_poetry_dependency_table(
                    group.get("dependencies"),
                    target,
                    &manifest_path,
                    &format!("tool.poetry.group.{name}.dependencies"),
                    false,
                )?;
            }
        }
    }
    Ok(Some(direct))
}

fn collect_requirement_array(
    value: Option<&Toml>,
    target: &mut BTreeSet<String>,
    path: &Path,
    context: &str,
) -> Result<(), ParseError> {
    let Some(value) = value else {
        return Ok(());
    };
    let requirements = value
        .as_array()
        .ok_or_else(|| invalid(path, format!("{context} must be an array")))?;
    for (index, requirement) in requirements.iter().enumerate() {
        let requirement = requirement
            .as_str()
            .ok_or_else(|| invalid(path, format!("{context} entry {index} must be a string")))?;
        target.insert(requirement_name(requirement, path, context)?);
    }
    Ok(())
}

fn collect_requirement_groups(
    value: Option<&Toml>,
    target: &mut BTreeSet<String>,
    path: &Path,
    context: &str,
) -> Result<(), ParseError> {
    let Some(value) = value else {
        return Ok(());
    };
    let groups = value
        .as_table()
        .ok_or_else(|| invalid(path, format!("{context} must be a table")))?;
    for (group, requirements) in groups {
        let requirements = requirements
            .as_array()
            .ok_or_else(|| invalid(path, format!("{context}.{group} must be an array")))?;
        for (index, requirement) in requirements.iter().enumerate() {
            if let Some(requirement) = requirement.as_str() {
                target.insert(requirement_name(requirement, path, context)?);
            } else {
                let include = requirement.as_table().and_then(|table| {
                    (table.len() == 1)
                        .then(|| table.get("include-group"))
                        .flatten()
                        .and_then(Toml::as_str)
                        .filter(|included| !included.is_empty())
                });
                if include.is_none() {
                    return Err(invalid(
                        path,
                        format!(
                            "{context}.{group} entry {index} must be a requirement string or include-group"
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn collect_poetry_dependency_table(
    value: Option<&Toml>,
    target: &mut BTreeSet<String>,
    path: &Path,
    context: &str,
    skip_python: bool,
) -> Result<(), ParseError> {
    let Some(value) = value else {
        return Ok(());
    };
    let dependencies = value
        .as_table()
        .ok_or_else(|| invalid(path, format!("{context} must be a table")))?;
    for (name, declaration) in dependencies {
        if skip_python && name.eq_ignore_ascii_case("python") {
            continue;
        }
        if !matches!(
            declaration,
            Toml::String(_) | Toml::Table(_) | Toml::Array(_)
        ) {
            return Err(invalid(
                path,
                format!("{context}.{name} has an unsupported declaration"),
            ));
        }
        target.insert(normalized_name(name, path, context)?);
    }
    Ok(())
}

fn requirement_name(specification: &str, path: &Path, context: &str) -> Result<String, ParseError> {
    let specification = specification.trim_start();
    let end = specification
        .find(|character: char| {
            !character.is_ascii_alphanumeric() && !matches!(character, '-' | '_' | '.')
        })
        .unwrap_or(specification.len());
    let name = &specification[..end];
    normalized_name(name, path, context)
}
