use super::*;

pub(super) fn poetry_direct_dependencies(
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
