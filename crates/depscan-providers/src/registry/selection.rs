use super::*;

pub(crate) fn matching_version<'a>(
    package: &Package,
    versions: impl IntoIterator<Item = &'a str>,
) -> Result<Option<String>, ProviderError> {
    let Some(constraint) = package.manifest_constraint.as_ref() else {
        if package.resolved_from_range {
            return Err(ProviderError::InvalidResponse(format!(
                "{} is marked range-derived but has no preserved manifest constraint",
                package.display_name
            )));
        }
        return Ok(None);
    };
    latest_matching_version(package.ecosystem, constraint.normalized(), versions)
        .map_err(|error| ProviderError::InvalidResponse(error.to_string()))
}

pub(crate) fn version_result(
    package: &Package,
    latest: String,
    latest_matching: Option<String>,
    yanked: bool,
) -> LatestVersions {
    let staleness = if package.resolved_from_range {
        depscan_core::Staleness::Unknown
    } else {
        classify_staleness(package.ecosystem, &package.version, &latest)
    };
    LatestVersions {
        latest_stable: latest,
        latest_matching,
        staleness,
        yanked,
    }
}

pub(crate) fn npm_version_result(
    package: &Package,
    data: &Value,
) -> Result<LatestVersions, ProviderError> {
    let latest = data
        .get("dist-tags")
        .and_then(|value| value.get("latest"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::InvalidResponse(format!(
                "npm response lacked latest for {}",
                package.name
            ))
        })?
        .to_owned();
    let matching = if package.manifest_constraint.is_some() {
        let versions = data
            .get("versions")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ProviderError::InvalidResponse(format!(
                    "npm response lacked release versions for manifest-only package {}",
                    package.name
                ))
            })?;
        matching_version(package, versions.keys().map(String::as_str))?
    } else {
        matching_version(package, std::iter::empty())?
    };
    Ok(version_result(package, latest, matching, false))
}

pub(crate) fn pypi_version_result(
    package: &Package,
    data: &Value,
) -> Result<LatestVersions, ProviderError> {
    let releases = data
        .get("releases")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ProviderError::InvalidResponse("PyPI response lacked releases".to_owned())
        })?;
    let latest = select_pypi_release(releases, &package.version).ok_or_else(|| {
        ProviderError::InvalidResponse(format!("PyPI has no suitable release for {}", package.name))
    })?;
    let yanked = releases
        .get(&package.version)
        .is_some_and(pypi_release_is_yanked);
    let matching = matching_version(
        package,
        releases
            .iter()
            .filter(|(_, files)| !pypi_release_is_yanked(files))
            .map(|(version, _)| version.as_str()),
    )?;
    Ok(version_result(package, latest, matching, yanked))
}

pub(crate) fn nuget_version_result(
    package: &Package,
    data: &Value,
) -> Result<LatestVersions, ProviderError> {
    let versions = data
        .get("versions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProviderError::InvalidResponse("NuGet response lacked versions".to_owned())
        })?;
    let latest =
        select_nuget_release(versions.iter().filter_map(Value::as_str)).ok_or_else(|| {
            ProviderError::InvalidResponse(format!(
                "NuGet has no stable version for {}",
                package.name
            ))
        })?;
    let matching = matching_version(package, versions.iter().filter_map(Value::as_str))?;
    Ok(version_result(package, latest, matching, false))
}

pub(crate) fn crates_version_result(
    package: &Package,
    entries: &[CratesIndexEntry],
) -> Result<LatestVersions, ProviderError> {
    let mut all: Vec<&str> = Vec::new();
    let mut matchable: Vec<&str> = Vec::new();
    let mut yanked = false;
    for entry in entries {
        if entry.vers == package.version {
            yanked = entry.yanked;
        }
        if !entry.yanked {
            matchable.push(&entry.vers);
            if !is_prerelease(Ecosystem::CratesIo, &entry.vers) {
                all.push(&entry.vers);
            }
        }
    }
    let latest = maximum_version(Ecosystem::CratesIo, all).ok_or_else(|| {
        ProviderError::InvalidResponse(format!(
            "crates.io has no stable version for {}",
            package.name
        ))
    })?;
    let matching = matching_version(package, matchable)?;
    Ok(version_result(package, latest, matching, yanked))
}
pub(crate) fn maximum_version<'a>(
    eco: Ecosystem,
    versions: impl IntoIterator<Item = &'a str>,
) -> Option<String> {
    versions
        .into_iter()
        .max_by(|a, b| compare_versions(eco, a, b))
        .map(str::to_owned)
}

pub(crate) fn select_nuget_release<'a>(
    versions: impl IntoIterator<Item = &'a str>,
) -> Option<String> {
    versions
        .into_iter()
        .filter_map(|raw| {
            NuGetVersion::parse(raw)
                .ok()
                .filter(|version| !version.is_prerelease())
                .map(|version| (raw, version))
        })
        .max_by(|(left_raw, left), (right_raw, right)| {
            left.cmp(right).then_with(|| left_raw.cmp(right_raw))
        })
        .map(|(raw, _)| raw.to_owned())
}

pub(crate) fn select_pypi_release(
    releases: &serde_json::Map<String, Value>,
    installed: &str,
) -> Option<String> {
    let allow_prerelease = pypi_version_is_prerelease(installed);
    releases
        .iter()
        .filter(|(version, files)| {
            let valid_candidate = pypi_version_is_stable(version)
                || (allow_prerelease && pypi_version_is_prerelease(version));
            valid_candidate && !pypi_release_is_yanked(files)
        })
        .map(|(version, _)| version.as_str())
        .max_by(|a, b| compare_versions(Ecosystem::PyPI, a, b))
        .map(str::to_owned)
}

pub(crate) fn pypi_release_is_yanked(files: &Value) -> bool {
    files.as_array().is_some_and(|files| {
        !files.is_empty()
            && files
                .iter()
                .all(|file| file.get("yanked").and_then(Value::as_bool).unwrap_or(false))
    })
}

pub(crate) fn is_prerelease(eco: Ecosystem, version: &str) -> bool {
    match eco {
        Ecosystem::Npm | Ecosystem::CratesIo => version.contains('-'),
        Ecosystem::NuGet => {
            NuGetVersion::parse(version).is_ok_and(|version| version.is_prerelease())
        }
        Ecosystem::PyPI => pypi_version_is_prerelease(version),
    }
}
