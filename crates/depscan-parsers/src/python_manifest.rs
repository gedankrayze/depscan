use depscan_core::{Ecosystem, Package, ParseError, normalize_name};
use std::{fs, path::Path};
use toml::{Table, Value as Toml};

use super::{dedup, invalid, io_error};
use constraint::PoetryConstraint;
use dependency::PoetryDependency;
use source::PoetrySourcePolicy;

mod constraint;
mod dependency;
mod pep508;
mod source;

pub(super) fn parse_pyproject(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
    let value: Toml = toml::from_str(&text).map_err(|error| invalid(path, error))?;
    let root = value
        .as_table()
        .ok_or_else(|| invalid(path, "Python manifest root must be a table"))?;
    let poetry = poetry_table(root, path)?;
    let source_policy =
        PoetrySourcePolicy::parse(poetry.and_then(|poetry| poetry.get("source")), path)?;
    let mut packages = pep508::parse(root, &source_policy, path)?;

    if let Some(poetry) = poetry {
        validate_project_extras(poetry.get("extras"), path)?;
        append_poetry_table(
            poetry.get("dependencies"),
            "tool.poetry.dependencies",
            false,
            true,
            &source_policy,
            &mut packages,
            path,
        )?;
        append_poetry_table(
            poetry.get("dev-dependencies"),
            "tool.poetry.dev-dependencies",
            true,
            false,
            &source_policy,
            &mut packages,
            path,
        )?;
        append_poetry_groups(poetry.get("group"), &source_policy, &mut packages, path)?;
    }

    Ok(dedup(packages))
}

fn poetry_table<'a>(root: &'a Table, path: &Path) -> Result<Option<&'a Table>, ParseError> {
    let Some(tool) = root.get("tool") else {
        return Ok(None);
    };
    let tool = tool
        .as_table()
        .ok_or_else(|| invalid(path, "tool must be a table"))?;
    let Some(poetry) = tool.get("poetry") else {
        return Ok(None);
    };
    poetry
        .as_table()
        .map(Some)
        .ok_or_else(|| invalid(path, "tool.poetry must be a table"))
}

fn append_poetry_groups(
    value: Option<&Toml>,
    policy: &PoetrySourcePolicy,
    packages: &mut Vec<Package>,
    path: &Path,
) -> Result<(), ParseError> {
    let Some(value) = value else {
        return Ok(());
    };
    let groups = value
        .as_table()
        .ok_or_else(|| invalid(path, "tool.poetry.group must be a table"))?;
    for name in groups.keys() {
        append_poetry_group(
            name,
            name != "main",
            groups,
            policy,
            &mut Vec::new(),
            packages,
            path,
        )?;
    }
    Ok(())
}

fn append_poetry_group(
    name: &str,
    dev: bool,
    groups: &Table,
    policy: &PoetrySourcePolicy,
    active: &mut Vec<String>,
    packages: &mut Vec<Package>,
    path: &Path,
) -> Result<(), ParseError> {
    if active.iter().any(|entry| entry == name) {
        active.push(name.to_owned());
        return Err(invalid(
            path,
            format!("tool.poetry.group include cycle: {}", active.join(" -> ")),
        ));
    }
    let context = format!("tool.poetry.group.{name}");
    let group = groups
        .get(name)
        .ok_or_else(|| invalid(path, format!("{context} is not defined")))?
        .as_table()
        .ok_or_else(|| invalid(path, format!("{context} must be a table")))?;
    for key in group.keys() {
        if !matches!(key.as_str(), "dependencies" | "optional" | "include-groups") {
            return Err(invalid(
                path,
                format!("{context} contains unsupported field {key:?}"),
            ));
        }
    }
    if let Some(optional) = group.get("optional")
        && optional.as_bool().is_none()
    {
        return Err(invalid(
            path,
            format!("{context}.optional must be a boolean"),
        ));
    }
    active.push(name.to_owned());
    append_poetry_table(
        group.get("dependencies"),
        &format!("{context}.dependencies"),
        dev,
        false,
        policy,
        packages,
        path,
    )?;
    if let Some(includes) = group.get("include-groups") {
        validate_string_array(includes, path, &format!("{context}.include-groups"))?;
        for included in includes
            .as_array()
            .expect("validated include-groups array")
            .iter()
            .filter_map(Toml::as_str)
        {
            append_poetry_group(included, dev, groups, policy, active, packages, path)?;
        }
    }
    active.pop();
    Ok(())
}

fn append_poetry_table(
    value: Option<&Toml>,
    context: &str,
    dev: bool,
    overlays_project: bool,
    policy: &PoetrySourcePolicy,
    packages: &mut Vec<Package>,
    path: &Path,
) -> Result<(), ParseError> {
    let Some(value) = value else {
        return Ok(());
    };
    let dependencies = value
        .as_table()
        .ok_or_else(|| invalid(path, format!("{context} must be a table")))?;
    for (display_name, value) in dependencies {
        if display_name.eq_ignore_ascii_case("python") && overlays_project {
            validate_interpreter_constraint(value, path, context)?;
            continue;
        }
        let dependency_context = format!("{context}.{display_name}");
        let declaration = PoetryDependency::parse(value, policy, path, &dependency_context)?;
        let normalized_name = normalize_name(Ecosystem::PyPI, display_name);
        if normalized_name.is_empty() {
            return Err(invalid(
                path,
                format!("{dependency_context} has an empty package name"),
            ));
        }

        let overlay_targets = if overlays_project {
            packages
                .iter_mut()
                .filter(|package| package.name == normalized_name && !package.dev)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        if !overlay_targets.is_empty() {
            for package in overlay_targets {
                package.enrichable &= declaration.enrichable(policy);
            }
            continue;
        }

        packages.push(declaration.into_package(
            display_name,
            dev,
            policy,
            path,
            &dependency_context,
        )?);
    }
    Ok(())
}

fn validate_interpreter_constraint(
    value: &Toml,
    path: &Path,
    context: &str,
) -> Result<(), ParseError> {
    let raw = value.as_str().ok_or_else(|| {
        invalid(
            path,
            format!("{context}.python interpreter constraint must be a string"),
        )
    })?;
    if raw.trim().is_empty() {
        return Err(invalid(
            path,
            format!("{context}.python interpreter constraint cannot be empty"),
        ));
    }
    PoetryConstraint::parse(
        raw,
        path,
        &format!("{context}.python interpreter constraint"),
    )?;
    Ok(())
}

fn validate_project_extras(value: Option<&Toml>, path: &Path) -> Result<(), ParseError> {
    let Some(value) = value else {
        return Ok(());
    };
    let extras = value
        .as_table()
        .ok_or_else(|| invalid(path, "tool.poetry.extras must be a table"))?;
    for (name, dependencies) in extras {
        if name.is_empty() {
            return Err(invalid(
                path,
                "tool.poetry.extras contains an empty extra name",
            ));
        }
        validate_string_array(dependencies, path, &format!("tool.poetry.extras.{name}"))?;
    }
    Ok(())
}

fn validate_string_array(value: &Toml, path: &Path, context: &str) -> Result<(), ParseError> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid(path, format!("{context} must be an array of strings")))?;
    if values
        .iter()
        .any(|value| value.as_str().is_none_or(|value| value.trim().is_empty()))
    {
        return Err(invalid(
            path,
            format!("{context} must contain only non-empty strings"),
        ));
    }
    Ok(())
}
