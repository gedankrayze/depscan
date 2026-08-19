use depscan_core::{Ecosystem, Package, ParseError};
use pep440_rs::VersionSpecifiers;
use pep508_rs::{Requirement, VerbatimUrl, VersionOrUrl};
use std::path::Path;
use toml::{Table, Value as Toml};

use super::source::PoetrySourcePolicy;
use crate::invalid;

pub(super) fn parse(
    root: &Table,
    policy: &PoetrySourcePolicy,
    path: &Path,
) -> Result<Vec<Package>, ParseError> {
    let mut packages = Vec::new();
    if let Some(project) = root.get("project") {
        let project = project
            .as_table()
            .ok_or_else(|| invalid(path, "project must be a table"))?;
        validate_requires_python(project.get("requires-python"), path)?;
        append_requirement_array(
            project.get("dependencies"),
            "project.dependencies",
            false,
            policy,
            path,
            &mut packages,
        )?;
        append_optional_dependencies(
            project.get("optional-dependencies"),
            policy,
            path,
            &mut packages,
        )?;
    }
    append_dependency_groups(root.get("dependency-groups"), policy, path, &mut packages)?;
    Ok(packages)
}

fn validate_requires_python(value: Option<&Toml>, path: &Path) -> Result<(), ParseError> {
    let Some(value) = value else {
        return Ok(());
    };
    let raw = value.as_str().ok_or_else(|| {
        invalid(
            path,
            "project.requires-python must be a non-empty PEP 440 string",
        )
    })?;
    if raw.trim().is_empty() {
        return Err(invalid(
            path,
            "project.requires-python must be a non-empty PEP 440 string",
        ));
    }
    raw.parse::<VersionSpecifiers>().map_err(|error| {
        invalid(
            path,
            format!("project.requires-python is not valid PEP 440: {error}"),
        )
    })?;
    Ok(())
}

fn append_optional_dependencies(
    value: Option<&Toml>,
    policy: &PoetrySourcePolicy,
    path: &Path,
    packages: &mut Vec<Package>,
) -> Result<(), ParseError> {
    let Some(value) = value else {
        return Ok(());
    };
    let extras = value
        .as_table()
        .ok_or_else(|| invalid(path, "project.optional-dependencies must be a table"))?;
    for (name, requirements) in extras {
        if name.is_empty() {
            return Err(invalid(
                path,
                "project.optional-dependencies contains an empty extra name",
            ));
        }
        append_requirement_array(
            Some(requirements),
            &format!("project.optional-dependencies.{name}"),
            false,
            policy,
            path,
            packages,
        )?;
    }
    Ok(())
}

fn append_dependency_groups(
    value: Option<&Toml>,
    policy: &PoetrySourcePolicy,
    path: &Path,
    packages: &mut Vec<Package>,
) -> Result<(), ParseError> {
    let Some(value) = value else {
        return Ok(());
    };
    let groups = value
        .as_table()
        .ok_or_else(|| invalid(path, "dependency-groups must be a table"))?;
    for name in groups.keys() {
        append_dependency_group(
            name,
            name != "main",
            groups,
            policy,
            path,
            &mut Vec::new(),
            packages,
        )?;
    }
    Ok(())
}

fn append_dependency_group(
    name: &str,
    dev: bool,
    groups: &Table,
    policy: &PoetrySourcePolicy,
    path: &Path,
    active: &mut Vec<String>,
    packages: &mut Vec<Package>,
) -> Result<(), ParseError> {
    if active.iter().any(|entry| entry == name) {
        active.push(name.to_owned());
        return Err(invalid(
            path,
            format!("dependency-groups include cycle: {}", active.join(" -> ")),
        ));
    }
    let entries = groups
        .get(name)
        .ok_or_else(|| invalid(path, format!("dependency group {name:?} is not defined")))?
        .as_array()
        .ok_or_else(|| invalid(path, format!("dependency-groups.{name} must be an array")))?;
    active.push(name.to_owned());
    for (index, entry) in entries.iter().enumerate() {
        let context = format!("dependency-groups.{name} entry {index}");
        if let Some(requirement) = entry.as_str() {
            packages.push(parse_requirement(requirement, &context, dev, policy, path)?);
            continue;
        }
        let include = entry
            .as_table()
            .filter(|table| table.len() == 1)
            .and_then(|table| table.get("include-group"))
            .and_then(Toml::as_str)
            .filter(|included| !included.is_empty())
            .ok_or_else(|| {
                invalid(
                    path,
                    format!("{context} must be a PEP 508 string or {{ include-group = \"name\" }}"),
                )
            })?;
        append_dependency_group(include, dev, groups, policy, path, active, packages)?;
    }
    active.pop();
    Ok(())
}

fn append_requirement_array(
    value: Option<&Toml>,
    context: &str,
    dev: bool,
    policy: &PoetrySourcePolicy,
    path: &Path,
    packages: &mut Vec<Package>,
) -> Result<(), ParseError> {
    let Some(value) = value else {
        return Ok(());
    };
    let requirements = value.as_array().ok_or_else(|| {
        invalid(
            path,
            format!("{context} must be an array of PEP 508 strings"),
        )
    })?;
    for (index, value) in requirements.iter().enumerate() {
        let requirement = value.as_str().ok_or_else(|| {
            invalid(
                path,
                format!("{context} entry {index} must be a PEP 508 string"),
            )
        })?;
        packages.push(parse_requirement(
            requirement,
            &format!("{context} entry {index}"),
            dev,
            policy,
            path,
        )?);
    }
    Ok(())
}

fn parse_requirement(
    raw: &str,
    context: &str,
    dev: bool,
    policy: &PoetrySourcePolicy,
    path: &Path,
) -> Result<Package, ParseError> {
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let requirement = Requirement::<VerbatimUrl>::parse(raw, base).map_err(|error| {
        invalid(
            path,
            format!("{context} is not a valid PEP 508 requirement: {error}"),
        )
    })?;
    let display_name = source_distribution_name(raw)
        .unwrap_or_else(|| requirement.name.as_ref())
        .to_owned();
    if requirement.marker.contents().is_some() {
        tracing::warn!(
            source_file = %path.display(),
            dependency = %display_name,
            "pyproject environment marker is assumed true"
        );
    }

    let (version, constraint, enrichable) = match requirement.version_or_url {
        Some(VersionOrUrl::Url(url)) => (url.to_string(), None, false),
        Some(VersionOrUrl::VersionSpecifier(specifiers)) => {
            let normalized = specifiers.to_string();
            let raw_constraint = raw_registry_constraint(raw).unwrap_or_else(|| normalized.clone());
            (
                raw_constraint.clone(),
                Some((raw_constraint, normalized)),
                policy.unqualified_pypi(),
            )
        }
        None => (
            "*".to_owned(),
            Some(("*".to_owned(), ">=0".to_owned())),
            policy.unqualified_pypi(),
        ),
    };
    let mut package = Package::new(Ecosystem::PyPI, display_name, version, path.to_path_buf());
    package.direct = true;
    package.dev = dev;
    package.enrichable = enrichable;
    if let Some((raw, normalized)) = constraint {
        package.set_normalized_manifest_constraint(raw, normalized);
    }
    Ok(package)
}

fn source_distribution_name(input: &str) -> Option<&str> {
    let end = input
        .char_indices()
        .take_while(|(_, character)| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
        .map(|(index, character)| index + character.len_utf8())
        .last()?;
    Some(&input[..end])
}

fn raw_registry_constraint(input: &str) -> Option<String> {
    let before_marker = input.split_once(';').map_or(input, |parts| parts.0);
    let name_end = source_distribution_name(before_marker)?.len();
    let mut remainder = before_marker[name_end..].trim_start();
    if let Some(after_open) = remainder.strip_prefix('[') {
        let close = after_open.find(']')?;
        remainder = after_open[close + 1..].trim_start();
    }
    (!remainder.is_empty()).then(|| remainder.trim().to_owned())
}
