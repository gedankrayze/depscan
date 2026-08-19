use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::*;

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

fn parse_uv_package(value: &Toml, path: &Path, index: usize) -> Result<UvPackage, ParseError> {
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

fn parse_uv_source(value: &Toml, path: &Path, context: &str) -> Result<PythonSource, ParseError> {
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

fn parse_uv_dependency_array(
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

fn uv_manifest_members(
    manifest: Option<&Table>,
    path: &Path,
) -> Result<BTreeSet<String>, ParseError> {
    let Some(value) = manifest.and_then(|manifest| manifest.get("members")) else {
        return Ok(BTreeSet::new());
    };
    let members = value
        .as_array()
        .ok_or_else(|| invalid(path, "uv manifest members must be an array"))?;
    members
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let member = value.as_str().ok_or_else(|| {
                invalid(path, format!("uv manifest member {index} must be a string"))
            })?;
            normalized_name(member, path, "uv manifest member")
        })
        .collect()
}

fn uv_manifest_requirements(
    manifest: &Table,
    key: &str,
    path: &Path,
) -> Result<Vec<UvDependency>, ParseError> {
    manifest
        .get(key)
        .map(|value| parse_uv_dependency_array(value, path, &format!("uv manifest {key}"), false))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn resolve_seed_indices<'a>(
    dependencies: impl Iterator<Item = &'a UvDependency>,
    packages: &[UvPackage],
    by_name: &BTreeMap<String, Vec<usize>>,
    path: &Path,
) -> Result<BTreeSet<usize>, ParseError> {
    dependencies
        .map(|dependency| resolve_uv_dependency(dependency, packages, by_name, path))
        .collect()
}

fn reachable_indices(
    seeds: &[UvDependency],
    packages: &[UvPackage],
    by_name: &BTreeMap<String, Vec<usize>>,
    path: &Path,
) -> Result<BTreeSet<usize>, ParseError> {
    let mut queue = VecDeque::new();
    for seed in seeds {
        queue.push_back(ReachablePackage {
            index: resolve_uv_dependency(seed, packages, by_name, path)?,
            extras: seed.extras.clone(),
        });
    }
    let mut visited_states = BTreeSet::new();
    let mut visited_indices = BTreeSet::new();
    while let Some(state) = queue.pop_front() {
        if !visited_states.insert(state.clone()) {
            continue;
        }
        visited_indices.insert(state.index);
        let package = &packages[state.index];
        for dependency in &package.dependencies {
            queue.push_back(ReachablePackage {
                index: resolve_uv_dependency(dependency, packages, by_name, path)?,
                extras: dependency.extras.clone(),
            });
        }
        for extra in &state.extras {
            let dependencies = package.optional_dependencies.get(extra).ok_or_else(|| {
                invalid(
                    path,
                    format!(
                        "uv package {:?} is selected with unknown extra {extra:?}",
                        package.display_name
                    ),
                )
            })?;
            for dependency in dependencies {
                queue.push_back(ReachablePackage {
                    index: resolve_uv_dependency(dependency, packages, by_name, path)?,
                    extras: dependency.extras.clone(),
                });
            }
        }
    }
    Ok(visited_indices)
}

fn resolve_uv_dependency(
    dependency: &UvDependency,
    packages: &[UvPackage],
    by_name: &BTreeMap<String, Vec<usize>>,
    path: &Path,
) -> Result<usize, ParseError> {
    let candidates = by_name
        .get(&dependency.name)
        .into_iter()
        .flatten()
        .copied()
        .filter(|index| {
            let id = &packages[*index].id;
            dependency
                .version
                .as_ref()
                .is_none_or(|version| id.version.as_ref() == Some(version))
                && dependency
                    .source
                    .as_ref()
                    .is_none_or(|source| &id.source == source)
        })
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [index] => Ok(*index),
        [] => Err(invalid(
            path,
            format!(
                "uv dependency {:?} has no matching package entry",
                dependency.name
            ),
        )),
        _ => Err(invalid(
            path,
            format!(
                "uv dependency {:?} is ambiguous; version and source are required",
                dependency.name
            ),
        )),
    }
}
