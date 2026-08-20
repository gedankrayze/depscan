use super::*;

pub(super) fn parse_requirement(input: &str, base: &Path) -> Result<PackageSpec, SyntaxError> {
    match Requirement::<VerbatimUrl>::parse(input, base) {
        Ok(requirement) => package_from_requirement(input, requirement),
        Err(_) if looks_like_direct(input) => parse_direct(input, base, false),
        Err(_) => Err(SyntaxError::new(
            "invalid PEP 508 requirement; expected a package name with an optional version, extras, marker, or named direct URL",
        )),
    }
}

pub(super) fn package_from_requirement(
    input: &str,
    requirement: Requirement<VerbatimUrl>,
) -> Result<PackageSpec, SyntaxError> {
    let display_name = source_distribution_name(input)
        .unwrap_or_else(|| requirement.name.as_ref())
        .to_owned();
    let has_marker = requirement.marker.contents().is_some();
    let has_extras = !requirement.extras.is_empty();

    match requirement.version_or_url {
        Some(VersionOrUrl::Url(url)) => Ok(PackageSpec {
            display_name,
            version: url.to_string(),
            enrichable: false,
            resolved_from_range: true,
            has_marker,
            constraint_compatible: false,
            registry_constraint: None,
        }),
        Some(VersionOrUrl::VersionSpecifier(specifiers)) => {
            let mut iter = specifiers.iter();
            let first = iter.next();
            let exact = first
                .filter(|specifier| *specifier.operator() == Operator::Equal)
                .filter(|_| iter.next().is_none());
            let normalized = specifiers.to_string();
            let raw = raw_registry_constraint(input).unwrap_or_else(|| normalized.clone());
            let (version, resolved_from_range) = if let Some(specifier) = exact {
                (
                    raw_exact_version(input).unwrap_or_else(|| specifier.version().to_string()),
                    false,
                )
            } else {
                (raw.clone(), true)
            };
            Ok(PackageSpec {
                display_name,
                version,
                enrichable: true,
                resolved_from_range,
                has_marker,
                constraint_compatible: !has_extras,
                registry_constraint: Some(ConstraintSpec { raw, normalized }),
            })
        }
        None => Ok(PackageSpec {
            display_name,
            version: "*".to_owned(),
            enrichable: true,
            resolved_from_range: true,
            has_marker,
            constraint_compatible: !has_extras,
            registry_constraint: Some(ConstraintSpec {
                raw: "*".to_owned(),
                normalized: ">=0".to_owned(),
            }),
        }),
    }
}

pub(super) fn source_distribution_name(input: &str) -> Option<&str> {
    let end = input
        .char_indices()
        .take_while(|(_, character)| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
        .map(|(index, character)| index + character.len_utf8())
        .last()?;
    Some(&input[..end])
}

pub(super) fn raw_registry_constraint(input: &str) -> Option<String> {
    let before_marker = input.split_once(';').map_or(input, |parts| parts.0);
    let name_end = source_distribution_name(before_marker)?.len();
    let mut remainder = before_marker[name_end..].trim_start();
    if let Some(after_open) = remainder.strip_prefix('[') {
        let close = after_open.find(']')?;
        remainder = after_open[close + 1..].trim_start();
    }
    (!remainder.is_empty()).then(|| remainder.trim().to_owned())
}

pub(super) fn raw_exact_version(input: &str) -> Option<String> {
    let before_marker = input.split_once(';').map_or(input, |parts| parts.0);
    let (_, version) = before_marker.split_once("==")?;
    let version = version.trim().trim_end_matches(')').trim();
    (!version.is_empty() && !version.contains(',') && !version.ends_with(".*"))
        .then(|| version.to_owned())
}

pub(super) fn parse_direct(
    input: &str,
    base: &Path,
    editable: bool,
) -> Result<PackageSpec, SyntaxError> {
    if let Ok(requirement) = Requirement::<VerbatimUrl>::parse(input, base)
        && matches!(requirement.version_or_url, Some(VersionOrUrl::Url(_)))
    {
        return package_from_requirement(input, requirement);
    }

    let display_name = infer_direct_name(input, base).ok_or_else(|| {
        let kind = if editable { "editable" } else { "direct" };
        SyntaxError::new(format!(
            "unnamed {kind} requirement cannot be represented; use `name @ URL` or a VCS URL with `#egg=name`"
        ))
    })?;
    Ok(PackageSpec {
        display_name,
        version: input.to_owned(),
        enrichable: false,
        resolved_from_range: true,
        has_marker: false,
        constraint_compatible: false,
        registry_constraint: None,
    })
}

pub(super) fn looks_like_direct(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let windows_drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    input.starts_with(['/', '.', '~', '\\'])
        || windows_drive
        || lower.starts_with("file:")
        || ["git+", "hg+", "svn+", "bzr+"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        || lower.contains("://")
        || [".whl", ".zip", ".tar.gz", ".tar.bz2", ".tar.xz"]
            .iter()
            .any(|suffix| {
                lower
                    .split(['#', '?'])
                    .next()
                    .map(strip_archive_extras)
                    .is_some_and(|x| x.ends_with(suffix))
            })
}

pub(super) fn infer_direct_name(input: &str, base: &Path) -> Option<String> {
    if let Some(fragment) = input.split_once('#').map(|parts| parts.1) {
        for field in fragment.split('&') {
            if let Some(egg) = field.strip_prefix("egg=") {
                let name = egg.split_once('[').map_or(egg, |parts| parts.0);
                if valid_distribution_name(name) {
                    return Some(name.to_owned());
                }
            }
        }
    }

    let without_fragment = input.split_once('#').map_or(input, |parts| parts.0);
    let without_query = without_fragment
        .split_once('?')
        .map_or(without_fragment, |parts| parts.0);
    let raw_name = without_query
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()?;
    let raw_name = strip_archive_extras(raw_name);
    let raw_name = if matches!(raw_name, "." | ".." | "") {
        let resolved = base.join(raw_name);
        Cow::Owned(
            resolved
                .components()
                .next_back()?
                .as_os_str()
                .to_str()?
                .to_owned(),
        )
    } else {
        Cow::Borrowed(raw_name)
    };
    let raw_name = raw_name.trim_end_matches(".git");
    let lower = raw_name.to_ascii_lowercase();
    let artifact = [".tar.bz2", ".tar.gz", ".tar.xz", ".whl", ".zip"]
        .iter()
        .find_map(|suffix| {
            lower
                .ends_with(suffix)
                .then(|| &raw_name[..raw_name.len() - suffix.len()])
        });
    let candidate = if let Some(artifact) = artifact {
        if lower.ends_with(".whl") {
            artifact.split('-').next().unwrap_or(artifact)
        } else {
            artifact.rsplit_once('-').map_or(artifact, |parts| parts.0)
        }
    } else {
        raw_name
    };
    valid_distribution_name(candidate).then(|| candidate.to_owned())
}

pub(super) fn strip_archive_extras(value: &str) -> &str {
    let Some(without_close) = value.strip_suffix(']') else {
        return value;
    };
    let Some(open) = without_close.rfind('[') else {
        return value;
    };
    let candidate = &without_close[..open];
    let candidate_lower = candidate.to_ascii_lowercase();
    if [".whl", ".zip", ".tar.gz", ".tar.bz2", ".tar.xz"]
        .iter()
        .any(|suffix| candidate_lower.ends_with(suffix))
    {
        candidate
    } else {
        value
    }
}

pub(super) fn valid_distribution_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && name
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}
