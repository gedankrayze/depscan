use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::*;

mod graph;
mod records;

use graph::*;
use records::*;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct UvPackageId {
    name: String,
    version: Option<String>,
    source: PythonSource,
}

#[derive(Clone, Debug)]
struct UvDependency {
    name: String,
    version: Option<String>,
    source: Option<PythonSource>,
    extras: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct UvPackage {
    id: UvPackageId,
    display_name: String,
    dependencies: Vec<UvDependency>,
    optional_dependencies: BTreeMap<String, Vec<UvDependency>>,
    dev_dependencies: BTreeMap<String, Vec<UvDependency>>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReachablePackage {
    index: usize,
    extras: BTreeSet<String>,
}

pub(crate) fn parse_uv_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let value = read_toml(path)?;
    let root = value
        .as_table()
        .ok_or_else(|| invalid(path, "uv lockfile root must be a table"))?;
    let version = required_integer(root, "version", path, "uv lockfile")?;
    if version != UV_LOCK_VERSION {
        return Err(invalid(
            path,
            format!(
                "unsupported uv lockfile version {version}; supported version is {UV_LOCK_VERSION}"
            ),
        ));
    }
    if let Some(revision) = root.get("revision") {
        let revision = revision
            .as_integer()
            .ok_or_else(|| invalid(path, "uv lockfile revision must be a non-negative integer"))?;
        if revision < 0 {
            return Err(invalid(
                path,
                "uv lockfile revision must be a non-negative integer",
            ));
        }
    }
    required_string(root, "requires-python", path, "uv lockfile")?;
    let package_values = required_array(root, "package", path, "uv lockfile")?;
    let mut packages = Vec::with_capacity(package_values.len());
    for (index, value) in package_values.iter().enumerate() {
        packages.push(parse_uv_package(value, path, index)?);
    }

    let mut by_name = BTreeMap::<String, Vec<usize>>::new();
    let mut exact = BTreeSet::new();
    for (index, package) in packages.iter().enumerate() {
        if !exact.insert(package.id.clone()) {
            return Err(invalid(
                path,
                format!("uv package {:?} is duplicated", package.display_name),
            ));
        }
        by_name
            .entry(package.id.name.clone())
            .or_default()
            .push(index);
    }

    let manifest = root.get("manifest").map(|value| {
        value
            .as_table()
            .ok_or_else(|| invalid(path, "uv manifest must be a table"))
    });
    let manifest = manifest.transpose()?;
    let member_names = uv_manifest_members(manifest, path)?;
    let mut project_roots = BTreeSet::new();
    for (index, package) in packages.iter().enumerate() {
        if package.id.source.is_project_root() || member_names.contains(&package.id.name) {
            project_roots.insert(index);
        }
    }
    for member in &member_names {
        if !packages.iter().any(|package| &package.id.name == member) {
            return Err(invalid(
                path,
                format!("uv manifest member {member:?} has no package entry"),
            ));
        }
    }

    let mut production_seeds = Vec::new();
    let mut development_seeds = Vec::new();
    for index in &project_roots {
        let package = &packages[*index];
        production_seeds.extend(package.dependencies.iter().cloned());
        production_seeds.extend(package.optional_dependencies.values().flatten().cloned());
        development_seeds.extend(package.dev_dependencies.values().flatten().cloned());
    }
    if let Some(manifest) = manifest {
        production_seeds.extend(uv_manifest_requirements(manifest, "requirements", path)?);
        if let Some(groups) = manifest.get("dependency-groups") {
            let groups = groups
                .as_table()
                .ok_or_else(|| invalid(path, "uv manifest dependency-groups must be a table"))?;
            for (group, requirements) in groups {
                development_seeds.extend(parse_uv_dependency_array(
                    requirements,
                    path,
                    &format!("uv manifest dependency group {group:?}"),
                    false,
                )?);
            }
        }
    }

    let classifications_known = !project_roots.is_empty()
        || manifest.is_some_and(|manifest| {
            manifest.contains_key("requirements") || manifest.contains_key("dependency-groups")
        });
    let direct = if classifications_known {
        resolve_seed_indices(
            production_seeds.iter().chain(&development_seeds),
            &packages,
            &by_name,
            path,
        )?
    } else {
        BTreeSet::new()
    };
    let production = reachable_indices(&production_seeds, &packages, &by_name, path)?;
    let development = reachable_indices(&development_seeds, &packages, &by_name, path)?;

    let mut output = Vec::new();
    for (index, package) in packages.into_iter().enumerate() {
        if project_roots.contains(&index) {
            continue;
        }
        let Some(version) = package.id.version else {
            return Err(invalid(
                path,
                format!(
                    "uv dependency package {:?} has no resolved version",
                    package.display_name
                ),
            ));
        };
        let mut parsed = Package::new(
            Ecosystem::PyPI,
            package.display_name,
            version,
            path.to_path_buf(),
        );
        parsed.enrichable = package.id.source.enrichable();
        if classifications_known {
            parsed.direct = direct.contains(&index);
            parsed.direct_known = true;
        } else {
            parsed.direct_known = false;
        }
        if production.contains(&index) {
            parsed.dev = false;
            parsed.dev_known = true;
        } else if development.contains(&index) {
            parsed.dev = true;
            parsed.dev_known = true;
        } else {
            parsed.dev_known = false;
        }
        output.push(parsed);
    }
    Ok(dedup(output))
}
