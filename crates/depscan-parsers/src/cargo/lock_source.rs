use super::*;

pub(crate) fn cargo_git_source_key(source: &str) -> Option<(String, Vec<(String, String)>)> {
    let source = source.strip_prefix("git+")?;
    let mut url = Url::parse(source).ok()?;
    let mut query = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    query.sort();
    url.set_query(None);
    url.set_fragment(None);
    Some((url.to_string(), query))
}

pub(crate) fn cargo_lock_source_matches(reference: &str, target: &str) -> bool {
    match (
        cargo_git_source_key(reference),
        cargo_git_source_key(target),
    ) {
        (Some(reference), Some(target)) => reference == target,
        (None, None) => reference == target,
        _ => false,
    }
}

pub(crate) fn cargo_lock_reference_source_matches(
    reference: &str,
    target: &str,
    lockfile_version: i64,
) -> bool {
    if cargo_lock_source_matches(reference, target) {
        return true;
    }
    let (Some(reference), Some(target)) = (
        cargo_git_source_key(reference),
        cargo_git_source_key(target),
    ) else {
        return false;
    };
    lockfile_version <= 2
        && reference.0 == target.0
        && reference.1.is_empty()
        && target.1 == [("branch".to_owned(), "master".to_owned())]
}

pub(crate) fn cargo_registry_index_source(index: &str) -> Option<String> {
    let source = if index.starts_with("registry+") || index.starts_with("sparse+") {
        index.to_owned()
    } else {
        format!("registry+{index}")
    };
    cargo_normalize_lock_source(&source).ok()
}

pub(crate) fn resolve_cargo_lock_reference(
    path: &Path,
    context: &str,
    reference: &CargoLockReference,
    nodes: &[CargoRawLockNode],
    lockfile_version: i64,
) -> Result<usize, ParseError> {
    let mut candidates = nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.id.name == reference.name)
        .collect::<Vec<_>>();
    if let Some(version) = &reference.version {
        candidates.retain(|(_, node)| node.id.version == *version);
    } else {
        let versions = candidates
            .iter()
            .map(|(_, node)| node.id.version.as_str())
            .collect::<BTreeSet<_>>();
        if versions.len() > 1 {
            return Err(invalid(
                path,
                format!(
                    "{context} dependency reference {:?} omits a version shared by multiple locked versions",
                    reference.name
                ),
            ));
        }
    }
    if let Some(source) = &reference.source {
        candidates.retain(|(_, node)| {
            node.id.source.as_deref().is_some_and(|target| {
                cargo_lock_reference_source_matches(source, target, lockfile_version)
            })
        });
    } else {
        let local_candidates = candidates
            .iter()
            .filter(|(_, node)| {
                node.id
                    .source
                    .as_deref()
                    .is_none_or(|source| source.starts_with("path+"))
            })
            .map(|(index, _)| *index)
            .collect::<Vec<_>>();
        if local_candidates.len() == 1 {
            return Ok(local_candidates[0]);
        }
    }
    match candidates.as_slice() {
        [(index, _)] => Ok(*index),
        [] => Err(invalid(
            path,
            format!(
                "{context} dependency reference to {:?} has no matching locked package",
                reference.name
            ),
        )),
        _ => Err(invalid(
            path,
            format!(
                "{context} dependency reference to {:?} is ambiguous across locked identities",
                reference.name
            ),
        )),
    }
}

pub(crate) fn cargo_dependency_source_exact(
    source: &CargoDependencySource,
    target: &CargoLockId,
) -> bool {
    match source {
        CargoDependencySource::CratesIo => target.source.as_deref() == Some(CARGO_CRATES_IO_SOURCE),
        CargoDependencySource::RegistryName => false,
        CargoDependencySource::RegistryIndex(index) => cargo_registry_index_source(index)
            .as_deref()
            .is_some_and(|index| target.source.as_deref() == Some(index)),
        CargoDependencySource::Git { url, selector } => {
            let Ok(mut expected) = Url::parse(url) else {
                return false;
            };
            if let Some((kind, value)) = selector {
                expected.query_pairs_mut().append_pair(kind, value);
            }
            let expected = format!("git+{expected}");
            target
                .source
                .as_deref()
                .is_some_and(|target| cargo_lock_source_matches(&expected, target))
        }
        CargoDependencySource::Path => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CargoDeclarationTargetStrength {
    None,
    Possible,
    Exact,
}

pub(crate) fn cargo_declaration_target_strength(
    declaration: &CargoDeclaration,
    target: &CargoLockId,
) -> CargoDeclarationTargetStrength {
    if declaration.dependency.package_name != target.name {
        return CargoDeclarationTargetStrength::None;
    }
    if let Some(requirement) = &declaration.dependency.version {
        let (Ok(requirement), Ok(version)) = (
            semver::VersionReq::parse(requirement),
            semver::Version::parse(&target.version),
        ) else {
            return CargoDeclarationTargetStrength::None;
        };
        if !requirement.matches(&version) {
            return CargoDeclarationTargetStrength::None;
        }
    }
    if cargo_dependency_source_exact(&declaration.dependency.source, target) {
        CargoDeclarationTargetStrength::Exact
    } else {
        CargoDeclarationTargetStrength::Possible
    }
}
