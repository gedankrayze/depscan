use super::*;

pub(crate) struct NpmWorkspacePattern {
    source: String,
    matcher: NpmMinimatch,
}

#[derive(Default)]
pub(crate) struct NpmWorkspacePatterns {
    included: Vec<NpmWorkspacePattern>,
    excluded: Vec<NpmWorkspacePattern>,
}

pub(crate) fn npm_lock_workspace_patterns(
    path: &Path,
    package_entries: &serde_json::Map<String, Json>,
) -> Result<NpmWorkspacePatterns, ParseError> {
    let Some(root) = package_entries.get("").and_then(Json::as_object) else {
        return Ok(NpmWorkspacePatterns::default());
    };
    let Some(workspaces) = root.get("workspaces") else {
        return Ok(NpmWorkspacePatterns::default());
    };
    let entries = match workspaces {
        Json::Array(entries) => entries,
        Json::Object(object) => {
            object
                .get("packages")
                .and_then(Json::as_array)
                .ok_or_else(|| {
                    invalid(
                        path,
                        "npm lock root workspaces object must contain a packages array",
                    )
                })?
        }
        _ => {
            return Err(invalid(
                path,
                "npm lock root workspaces must be an array or object containing a packages array",
            ));
        }
    };
    if entries.len() > MAX_WORKSPACE_PATTERNS {
        return Err(invalid(
            path,
            format!("npm lock root workspaces exceeds the {MAX_WORKSPACE_PATTERNS}-pattern limit"),
        ));
    }
    let mut patterns = NpmWorkspacePatterns::default();
    for (index, entry) in entries.iter().enumerate() {
        let raw = entry
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                invalid(
                    path,
                    format!("npm lock root workspace entry {index} must be a non-empty string"),
                )
            })?;
        let bang_count = raw.bytes().take_while(|byte| *byte == b'!').count();
        let excluded = bang_count % 2 == 1;
        let normalized_separators = raw[bang_count..].replace('\\', "/");
        // npm map-workspaces applies exactly `/^\.?\/+/'` once. In
        // particular, `.//packages/*` becomes `packages/*`, while
        // `././packages/*` becomes `./packages/*` and must not be simplified
        // again into a broader workspace proof.
        let normalized = normalized_separators
            .strip_prefix('.')
            .filter(|suffix| suffix.starts_with('/'))
            .map_or_else(
                || normalized_separators.trim_start_matches('/'),
                |suffix| suffix.trim_start_matches('/'),
            );
        let normalized = normalized.trim_end_matches('/');
        let relative = Path::new(normalized);
        if normalized.is_empty()
            || relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(invalid(
                path,
                format!("npm lock root workspace pattern {raw:?} must remain within the project"),
            ));
        }
        let matcher = NpmMinimatch::compile(normalized).map_err(|error| {
            invalid(
                path,
                format!("invalid npm workspace pattern {raw:?}: {error}"),
            )
        })?;
        let pattern = NpmWorkspacePattern {
            source: normalized.to_owned(),
            matcher,
        };
        if excluded {
            patterns.excluded.push(pattern);
        } else {
            // npm removes an earlier exclusion only when this positive
            // pattern is itself selected by that exclusion. A later
            // broad include therefore does not accidentally re-include
            // a specifically excluded workspace.
            let mut negative_index = 0usize;
            while negative_index < patterns.excluded.len() {
                let negative = &patterns.excluded[negative_index];
                let selected = negative.matcher.is_match(normalized).map_err(|error| {
                    invalid(
                        path,
                        format!(
                            "npm workspace pattern {:?} could not evaluate positive pattern {normalized:?}: {error}",
                            negative.source
                        ),
                    )
                })?;
                if selected {
                    // npm's map-workspaces mutates the negative list with
                    // splice while incrementing the loop index. Preserve
                    // that observable ordering: the entry shifted into this
                    // slot is intentionally not reconsidered.
                    patterns.excluded.remove(negative_index);
                }
                negative_index += 1;
            }
            patterns.included.push(pattern);
        }
    }
    for negative in &patterns.excluded {
        let mut retained = Vec::with_capacity(patterns.included.len());
        for positive in patterns.included.drain(..) {
            let selected = negative
                .matcher
                .is_match(positive.source.as_str())
                .map_err(|error| {
                    invalid(
                        path,
                        format!(
                            "npm workspace exclusion {:?} could not evaluate positive pattern {:?}: {error}",
                            negative.source, positive.source
                        ),
                    )
                })?;
            if !selected {
                retained.push(positive);
            }
        }
        patterns.included = retained;
    }
    Ok(patterns)
}

pub(crate) fn npm_is_workspace_descriptor(
    path: &Path,
    location: &str,
    patterns: &NpmWorkspacePatterns,
) -> Result<bool, ParseError> {
    if location.is_empty()
        || location
            .split('/')
            .any(|segment| matches!(segment, "" | "." | ".." | "node_modules"))
    {
        return Ok(false);
    }
    let mut excluded = false;
    for pattern in &patterns.excluded {
        if pattern.matcher.is_match(location).map_err(|error| {
            invalid(
                path,
                format!(
                    "npm workspace exclusion {:?} could not evaluate package location {location:?}: {error}",
                    pattern.source
                ),
            )
        })? {
            excluded = true;
            break;
        }
    }
    let mut included = false;
    for pattern in &patterns.included {
        if pattern.matcher.is_match(location).map_err(|error| {
            invalid(
                path,
                format!(
                    "npm workspace pattern {:?} could not evaluate package location {location:?}: {error}",
                    pattern.source
                ),
            )
        })? {
            included = true;
            break;
        }
    }
    Ok(!excluded && included)
}
