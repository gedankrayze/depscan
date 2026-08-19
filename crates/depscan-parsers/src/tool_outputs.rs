use super::{dedup, invalid, parse_yarn_classic, yarn_direct_dependencies};
use depscan_core::{Ecosystem, NuGetVersion, Package, ParseError};
use serde_json::Value as Json;
use std::path::{Path, PathBuf};

/// Parse the Yarn Classic text emitted by `bun bun.lockb` without touching the filesystem.
///
/// External tool execution deliberately lives in the CLI crate. Keeping this function pure lets
/// callers apply the same strict parser and package provenance rules as a checked-in lockfile.
pub fn parse_bun_lockb_output(path: &Path, text: &str) -> Result<Vec<Package>, ParseError> {
    if !text.lines().any(|line| line.trim() == "# yarn lockfile v1") {
        return Err(invalid(
            path,
            "Bun did not emit a Yarn Classic lockfile with a '# yarn lockfile v1' header",
        ));
    }
    let direct = yarn_direct_dependencies(path.parent().unwrap_or(Path::new(".")));
    parse_yarn_classic(path, text, &direct)
}

/// Parse schema version 1 JSON emitted by `dotnet list <project> package`.
///
/// This function is filesystem- and process-free. The CLI owns the explicitly authorized tool
/// invocation and passes its bounded stdout here for structural validation.
pub fn parse_dotnet_list_json(path: &Path, text: &str) -> Result<Vec<Package>, ParseError> {
    let value: Json = serde_json::from_str(text).map_err(|error| invalid(path, error))?;
    let document = value
        .as_object()
        .ok_or_else(|| invalid(path, "dotnet package-list output must be a JSON object"))?;
    let version = document
        .get("version")
        .and_then(Json::as_u64)
        .ok_or_else(|| {
            invalid(
                path,
                "dotnet package-list output is missing an integer version",
            )
        })?;
    if version != 1 {
        return Err(invalid(
            path,
            format!("unsupported dotnet package-list output version {version}; expected version 1"),
        ));
    }
    if let Some(problems) = document.get("problems") {
        let problems = problems
            .as_array()
            .ok_or_else(|| invalid(path, "dotnet package-list problems must be an array"))?;
        if !problems.is_empty() {
            return Err(invalid(
                path,
                format!("dotnet package-list reported {} problem(s)", problems.len()),
            ));
        }
    }
    let projects = document
        .get("projects")
        .and_then(Json::as_array)
        .ok_or_else(|| invalid(path, "dotnet package-list projects must be an array"))?;
    if projects.len() != 1 {
        return Err(invalid(
            path,
            format!(
                "dotnet package-list must describe exactly one requested project, found {}",
                projects.len()
            ),
        ));
    }
    parse_dotnet_project(path, &projects[0])
}

fn parse_dotnet_project(path: &Path, project: &Json) -> Result<Vec<Package>, ParseError> {
    let project = project
        .as_object()
        .ok_or_else(|| invalid(path, "dotnet package-list project must be an object"))?;
    let reported_path = project
        .get("path")
        .and_then(Json::as_str)
        .ok_or_else(|| invalid(path, "dotnet package-list project is missing a string path"))?;
    if Path::new(reported_path).file_name() != path.file_name() {
        return Err(invalid(
            path,
            format!(
                "dotnet package-list described project {reported_path:?}, not the requested project"
            ),
        ));
    }
    let frameworks = project
        .get("frameworks")
        .and_then(Json::as_array)
        .ok_or_else(|| invalid(path, "dotnet package-list frameworks must be an array"))?;
    if frameworks.is_empty() {
        return Err(invalid(
            path,
            "dotnet package-list did not report any target frameworks",
        ));
    }

    let mut packages = Vec::new();
    for framework in frameworks {
        parse_dotnet_framework(path, framework, &mut packages)?;
    }
    Ok(dedup(packages))
}

fn parse_dotnet_framework(
    path: &Path,
    framework: &Json,
    packages: &mut Vec<Package>,
) -> Result<(), ParseError> {
    let framework = framework
        .as_object()
        .ok_or_else(|| invalid(path, "dotnet package-list framework must be an object"))?;
    let framework_name = framework
        .get("framework")
        .and_then(Json::as_str)
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| {
            invalid(
                path,
                "dotnet package-list framework is missing a non-empty framework name",
            )
        })?;
    for (field, direct) in [("topLevelPackages", true), ("transitivePackages", false)] {
        let Some(entries) = framework.get(field) else {
            continue;
        };
        let entries = entries.as_array().ok_or_else(|| {
            invalid(
                path,
                format!(
                    "dotnet package-list {field} for framework {framework_name:?} must be an array"
                ),
            )
        })?;
        for entry in entries {
            packages.push(parse_dotnet_package(
                path,
                framework_name,
                field,
                direct,
                entry,
            )?);
        }
    }
    Ok(())
}

fn parse_dotnet_package(
    path: &Path,
    framework_name: &str,
    field: &str,
    direct: bool,
    entry: &Json,
) -> Result<Package, ParseError> {
    let entry = entry.as_object().ok_or_else(|| {
        invalid(
            path,
            format!(
                "dotnet package-list {field} entry for framework {framework_name:?} must be an object"
            ),
        )
    })?;
    let name = entry
        .get("id")
        .and_then(Json::as_str)
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| {
            invalid(
                path,
                format!(
                    "dotnet package-list {field} entry for framework {framework_name:?} is missing a non-empty id"
                ),
            )
        })?;
    let resolved = entry
        .get("resolvedVersion")
        .and_then(Json::as_str)
        .ok_or_else(|| {
            invalid(
                path,
                format!(
                    "dotnet package-list package {name:?} in framework {framework_name:?} is missing resolvedVersion"
                ),
            )
        })?;
    NuGetVersion::parse(resolved).map_err(|error| {
        invalid(
            path,
            format!(
                "dotnet package-list package {name:?} in framework {framework_name:?} has {error}"
            ),
        )
    })?;
    let mut package = Package::new(Ecosystem::NuGet, name, resolved, PathBuf::from(path));
    package.direct = direct;
    Ok(package)
}
