use super::*;

pub(super) fn uv_manifest_members(
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

pub(super) fn uv_manifest_requirements(
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

pub(super) fn resolve_seed_indices<'a>(
    dependencies: impl Iterator<Item = &'a UvDependency>,
    packages: &[UvPackage],
    by_name: &BTreeMap<String, Vec<usize>>,
    path: &Path,
) -> Result<BTreeSet<usize>, ParseError> {
    dependencies
        .map(|dependency| resolve_uv_dependency(dependency, packages, by_name, path))
        .collect()
}

pub(super) fn reachable_indices(
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
