use super::*;

pub(crate) fn parse_yarn_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = read_yaml_text(path)?;
    parse_yarn_lock_text(path, &text)
}

pub(crate) fn parse_yarn_lock_text(path: &Path, text: &str) -> Result<Vec<Package>, ParseError> {
    let root = path.parent().unwrap_or(Path::new("."));
    let direct = yarn_direct_dependencies(root);
    let has_berry_metadata = text.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("__metadata:") || line.starts_with("\"__metadata\":")
    });
    if has_berry_metadata {
        parse_yarn_berry(path, text, &direct)
    } else if text.lines().any(|line| line.trim() == "# yarn lockfile v1") {
        parse_yarn_classic(path, text, &direct)
    } else {
        Err(invalid(
            path,
            "unrecognized Yarn lockfile; expected a Yarn Classic '# yarn lockfile v1' header or Berry __metadata",
        ))
    }
}

pub(crate) const YARN_BERRY_MIN_LOCKFILE_VERSION: u64 = 4;
pub(crate) const YARN_BERRY_MAX_LOCKFILE_VERSION: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum YarnSource {
    Registry,
    Workspace,
    Other,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct YarnLocator<'a> {
    pub(crate) name: &'a str,
    pub(crate) reference: &'a str,
}

pub(crate) fn parse_yarn_locator(locator: &str) -> Result<YarnLocator<'_>, String> {
    let separator = if locator.starts_with('@') {
        let slash = locator
            .find('/')
            .ok_or_else(|| "scoped package name is missing '/'".to_owned())?;
        locator[slash + 1..]
            .find('@')
            .map(|index| slash + 1 + index)
            .ok_or_else(|| "scoped package locator is missing '@reference'".to_owned())?
    } else {
        locator
            .find('@')
            .ok_or_else(|| "package locator is missing '@reference'".to_owned())?
    };
    let name = &locator[..separator];
    let reference = &locator[separator + 1..];
    validate_bun_package_name(name)?;
    if reference.is_empty() {
        return Err("package reference is empty".to_owned());
    }
    Ok(YarnLocator { name, reference })
}

pub(crate) fn split_yarn_descriptors(raw: &str) -> Result<Vec<String>, String> {
    let mut descriptors = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, ch) in raw.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
        } else if ch == ',' {
            descriptors.push(parse_yarn_scalar(&raw[start..index])?);
            start = index + ch.len_utf8();
        }
    }
    if quoted {
        return Err("unterminated quote in descriptor list".to_owned());
    }
    descriptors.push(parse_yarn_scalar(&raw[start..])?);
    if descriptors.iter().any(String::is_empty) {
        return Err("descriptor list contains an empty selector".to_owned());
    }
    Ok(descriptors)
}

pub(crate) fn parse_yarn_scalar(raw: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("value is empty".to_owned());
    }
    if value.starts_with('"') {
        serde_json::from_str::<String>(value).map_err(|error| error.to_string())
    } else if value.contains('"') || value.chars().any(char::is_whitespace) {
        Err("unquoted value contains quotes or whitespace".to_owned())
    } else {
        Ok(value.to_owned())
    }
}

pub(crate) fn yarn_reference_source(reference: &str) -> YarnSource {
    let reference_without_params = reference.split("::").next().unwrap_or(reference);
    if reference_without_params.starts_with("workspace:") {
        YarnSource::Workspace
    } else if reference_without_params.starts_with("npm:")
        || (!reference_without_params.contains(':')
            && semver::Version::parse(reference_without_params).is_ok())
    {
        YarnSource::Registry
    } else if let Some(inner) = reference_without_params
        .strip_prefix("virtual:")
        .and_then(|value| value.split_once('#').map(|(_, inner)| inner))
    {
        yarn_reference_source(inner)
    } else if reference_without_params.starts_with("patch:")
        && reference_without_params
            .to_ascii_lowercase()
            .contains("@npm%3a")
    {
        YarnSource::Registry
    } else {
        YarnSource::Other
    }
}

pub(crate) type YarnSemverBounds = ((u64, u64, u64), (u64, u64, u64));

pub(crate) fn yarn_caret_bounds(selector: &str) -> Option<YarnSemverBounds> {
    let raw = selector.strip_prefix('^')?;
    let parts = raw
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let major = parts[0];
    let minor = parts.get(1).copied().unwrap_or(0);
    let patch = parts.get(2).copied().unwrap_or(0);
    let upper = if parts.len() == 1 || major > 0 {
        (major.checked_add(1)?, 0, 0)
    } else if parts.len() == 2 || minor > 0 {
        (0, minor.checked_add(1)?, 0)
    } else {
        (0, 0, patch.checked_add(1)?)
    };
    Some(((major, minor, patch), upper))
}

pub(crate) fn yarn_semver_selector_equivalent(left: &str, right: &str) -> bool {
    left == right
        || yarn_caret_bounds(left)
            .zip(yarn_caret_bounds(right))
            .is_some_and(|(left, right)| left == right)
}

pub(crate) fn yarn_npm_selector_equivalent(left: &str, right: &str) -> bool {
    if yarn_semver_selector_equivalent(left, right) {
        return true;
    }
    let (Ok(left), Ok(right)) = (parse_yarn_locator(left), parse_yarn_locator(right)) else {
        return false;
    };
    left.name == right.name && yarn_semver_selector_equivalent(left.reference, right.reference)
}

pub(crate) fn yarn_dependency_selector_matches(reference: &str, constraint: &str) -> bool {
    let reference = reference.split("::").next().unwrap_or(reference);
    if reference == constraint || reference.strip_prefix("npm:") == Some(constraint) {
        return true;
    }
    match (
        reference.strip_prefix("npm:"),
        constraint.strip_prefix("npm:"),
    ) {
        (Some(reference), Some(constraint)) => yarn_npm_selector_equivalent(reference, constraint),
        (Some(reference), None) => yarn_semver_selector_equivalent(reference, constraint),
        (None, Some(_)) => false,
        (None, None) => yarn_semver_selector_equivalent(reference, constraint),
    }
}

pub(crate) fn bind_yarn_direct_dependencies(
    direct: &YarnDirectDependencies,
    descriptor_groups: &[Vec<String>],
) -> Result<YarnDirectDependencies, String> {
    let mut bound = YarnDirectDependencies {
        by_name: direct.by_name.clone(),
    };
    for descriptors in descriptor_groups {
        let parsed = descriptors
            .iter()
            .map(|descriptor| parse_yarn_locator(descriptor))
            .collect::<Result<Vec<_>, _>>()?;
        let mut entry_matches = BTreeSet::new();
        for locator in parsed {
            if let Some(selectors) = bound.by_name.get(locator.name) {
                for (index, selector) in selectors.iter().enumerate() {
                    if yarn_dependency_selector_matches(locator.reference, &selector.constraint) {
                        entry_matches.insert((locator.name.to_owned(), index));
                    }
                }
            }
        }
        for (name, index) in entry_matches {
            let Some(selector) = bound
                .by_name
                .get_mut(&name)
                .and_then(|selectors| selectors.get_mut(index))
            else {
                return Err(format!(
                    "Yarn direct dependency {name:?} disappeared while binding selector matches"
                ));
            };
            selector.matching_entries += 1;
        }
    }
    Ok(bound)
}

pub(crate) fn yarn_direct_metadata(
    descriptors: &[String],
    registry_name: &str,
    direct: &YarnDirectDependencies,
) -> Result<(bool, bool, bool, bool, Option<String>), String> {
    let mut flags = YarnDirectness::default();
    let mut display_alias = None;
    for descriptor in descriptors {
        let locator = parse_yarn_locator(descriptor)?;
        if let Some(selectors) = direct.by_name.get(locator.name) {
            for selector in selectors {
                let selected = selector.matching_entries == 1
                    && yarn_dependency_selector_matches(locator.reference, &selector.constraint);
                if selected {
                    flags.production |= selector.directness.production;
                    flags.development |= selector.directness.development;
                    if locator.name != registry_name {
                        display_alias.get_or_insert_with(|| locator.name.to_owned());
                    }
                }
            }
        }
    }
    let is_direct = flags.production || flags.development;
    Ok((
        is_direct,
        is_direct,
        flags.development && !flags.production,
        is_direct,
        display_alias,
    ))
}

pub(crate) fn validate_yarn_registry_version(
    version: &str,
    reference: &str,
    context: &str,
) -> Result<(), String> {
    let parsed_version = semver::Version::parse(version)
        .map_err(|error| format!("{context} has an invalid npm version {version:?}: {error}"))?;
    let exact_reference = reference
        .strip_prefix("npm:")
        .unwrap_or(reference)
        .split("::")
        .next()
        .unwrap_or(reference);
    if reference.starts_with("npm:") || !reference.contains(':') {
        let parsed_reference = semver::Version::parse(exact_reference).map_err(|error| {
            format!("{context} has an invalid npm resolution {reference:?}: {error}")
        })?;
        if parsed_reference != parsed_version {
            return Err(format!(
                "{context} version {version:?} does not match npm resolution {reference:?}"
            ));
        }
    }
    Ok(())
}
