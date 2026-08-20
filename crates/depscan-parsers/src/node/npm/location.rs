use super::*;

pub(crate) struct NpmPackageLocation {
    pub(crate) name: String,
    pub(crate) install_parent_key: String,
}

pub(crate) fn npm_package_location(location: &str) -> Option<NpmPackageLocation> {
    let segments: Vec<_> = location.split('/').collect();
    if segments
        .iter()
        .any(|segment| matches!(*segment, "" | "." | ".."))
    {
        return None;
    }

    // npm records install locations, not package names. The final node_modules
    // component identifies nested resolutions without leaking parent paths into
    // the package identity. Root, workspace-target, and other local descriptors
    // have no node_modules component and are intentionally not registry-scanned.
    let node_modules = segments
        .iter()
        .rposition(|segment| *segment == "node_modules")?;
    let package_segments = &segments[node_modules + 1..];
    let name = match package_segments {
        [name] if valid_npm_package_segment(name) && !name.starts_with('@') => (*name).to_owned(),
        [scope, name]
            if scope.starts_with('@')
                && scope.len() > 1
                && valid_npm_package_segment(scope)
                && valid_npm_package_segment(name)
                && !name.starts_with('@') =>
        {
            format!("{scope}/{name}")
        }
        _ => return None,
    };

    Some(NpmPackageLocation {
        name,
        install_parent_key: segments[..node_modules].join("/"),
    })
}

pub(crate) fn valid_npm_package_segment(segment: &str) -> bool {
    !matches!(segment, "" | "." | ".." | "node_modules")
}

pub(crate) fn npm_lock_optional_bool(
    path: &Path,
    location: &str,
    entry: &serde_json::Map<String, Json>,
    field: &str,
) -> Result<Option<bool>, ParseError> {
    entry
        .get(field)
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                invalid(
                    path,
                    format!("npm package entry {location:?} field {field:?} must be a boolean"),
                )
            })
        })
        .transpose()
}

pub(crate) fn npm_lock_source_locator(version: &str) -> bool {
    let lower = version.to_ascii_lowercase();
    lower.starts_with("workspace:")
        || lower.starts_with("file:")
        || lower.starts_with("link:")
        || lower.starts_with("git:")
        || lower.starts_with("git+")
        || lower.starts_with("git@")
        || lower.starts_with("github:")
        || lower.starts_with("gitlab:")
        || lower.starts_with("bitbucket:")
        || lower.starts_with("gist:")
        || lower.starts_with("http:")
        || lower.starts_with("https:")
        || lower.starts_with("ssh:")
        || lower.starts_with("npm:")
        || version.starts_with('/')
        || version.starts_with("./")
        || version.starts_with("../")
}

pub(crate) fn npm_lock_declared_nonregistry(specification: &str) -> bool {
    npm_lock_source_locator(specification) && npm_alias_reference(specification).is_none()
}

pub(crate) fn npm_alias_reference(specification: &str) -> Option<&str> {
    specification
        .get(..4)
        .filter(|prefix| prefix.eq_ignore_ascii_case("npm:"))
        .map(|_| &specification[4..])
}

pub(crate) fn npm_alias_parts(reference: &str) -> Result<(&str, &str), String> {
    if reference.is_empty() {
        return Err("alias target is empty".to_owned());
    }
    let separator = if reference.starts_with('@') {
        let slash = reference
            .find('/')
            .ok_or_else(|| "scoped alias target is missing '/'".to_owned())?;
        reference[slash + 1..]
            .find('@')
            .map(|index| slash + 1 + index)
    } else {
        reference.find('@')
    };
    let (name, version) = separator.map_or((reference, None), |separator| {
        (&reference[..separator], Some(&reference[separator + 1..]))
    });
    validate_bun_package_name(name)?;
    if version.is_some_and(|version| !version.is_empty() && npm_lock_source_locator(version)) {
        return Err("alias target version must be a registry version, range, or tag".to_owned());
    }
    Ok((
        name,
        version.filter(|version| !version.is_empty()).unwrap_or("*"),
    ))
}

#[cfg(test)]
pub(crate) fn npm_alias_target(reference: &str) -> Result<&str, String> {
    npm_alias_parts(reference).map(|(name, _)| name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NpmResolvedSource {
    PublicRegistry,
    Nonregistry,
    OmittedRegistryResolution,
    ConfiguredRegistry,
}

pub(crate) fn npm_lock_resolved_source(
    resolved: Option<&str>,
) -> Result<NpmResolvedSource, String> {
    let Some(resolved) = resolved else {
        return Ok(NpmResolvedSource::OmittedRegistryResolution);
    };
    if resolved == "registry.npmjs.org" || resolved.starts_with("registry.npmjs.org/") {
        // npm documents this as a magic reference to the configured registry,
        // which is not necessarily the public registry used by this scanner.
        return Ok(NpmResolvedSource::ConfiguredRegistry);
    }
    if resolved.starts_with('/') || resolved.starts_with("./") || resolved.starts_with("../") {
        return Ok(NpmResolvedSource::Nonregistry);
    }
    if resolved.starts_with("git@") {
        let Some((authority, repository)) = resolved.split_once(':') else {
            return Err("SCP-style Git source is missing ':'".to_owned());
        };
        let repository = repository
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
            .trim();
        if authority.trim_start_matches("git@").is_empty() || repository.is_empty() {
            return Err("SCP-style Git source must contain a host and repository path".to_owned());
        }
        return Ok(NpmResolvedSource::Nonregistry);
    }
    if resolved.ends_with(".tgz")
        && resolved.contains('/')
        && !resolved.contains("://")
        && !resolved.contains([':', '?', '#', '@'])
        && !resolved.contains(char::is_whitespace)
        && !resolved.contains('\\')
    {
        return Ok(NpmResolvedSource::Nonregistry);
    }

    if let Some((scheme, suffix)) = resolved.split_once(':')
        && matches!(
            scheme.to_ascii_lowercase().as_str(),
            "bitbucket"
                | "file"
                | "gist"
                | "git"
                | "git+file"
                | "git+http"
                | "git+https"
                | "git+ssh"
                | "github"
                | "gitlab"
                | "link"
                | "npm"
                | "ssh"
                | "workspace"
        )
    {
        let payload = suffix.split(['?', '#']).next().unwrap_or_default().trim();
        if payload.trim_matches('/').is_empty() {
            return Err("source URL has no package or repository path".to_owned());
        }
    }

    let parsed = Url::parse(resolved).map_err(|_| "source is not a supported URL or path")?;
    match parsed.scheme() {
        "http" | "https" => {
            let host = parsed
                .host_str()
                .ok_or_else(|| "HTTP source has no host".to_owned())?;
            let canonical_public = host.eq_ignore_ascii_case("registry.npmjs.org")
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.port().is_none();
            Ok(if canonical_public {
                NpmResolvedSource::PublicRegistry
            } else {
                NpmResolvedSource::Nonregistry
            })
        }
        "bitbucket" | "file" | "gist" | "git" | "git+file" | "git+http" | "git+https"
        | "git+ssh" | "github" | "gitlab" | "link" | "npm" | "ssh" | "workspace" => {
            if parsed.path().is_empty() {
                Err("source URL has no path".to_owned())
            } else {
                Ok(NpmResolvedSource::Nonregistry)
            }
        }
        _ => Err("source uses an unsupported URL scheme".to_owned()),
    }
}

pub(crate) fn npm_percent_decode_path_component(component: &str) -> Option<String> {
    let bytes = component.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            let hex = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            decoded.push(hex(high)? * 16 + hex(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

pub(crate) fn npm_public_tarball_matches(
    resolved: &str,
    package_name: &str,
    version: &str,
) -> bool {
    let Ok(parsed) = Url::parse(resolved) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed
            .host_str()
            .is_none_or(|host| !host.eq_ignore_ascii_case("registry.npmjs.org"))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return false;
    }
    let Some(segments) = parsed.path_segments() else {
        return false;
    };
    let Some(segments) = segments
        .map(npm_percent_decode_path_component)
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let tarball_name = package_name
        .rsplit_once('/')
        .map_or(package_name, |(_, name)| name);
    let expected_tarball = format!("{tarball_name}-{version}.tgz");
    match segments.as_slice() {
        [name, separator, tarball] => {
            name == package_name && separator == "-" && tarball == &expected_tarball
        }
        [scope, name, separator, tarball] => {
            package_name == format!("{scope}/{name}")
                && separator == "-"
                && tarball == &expected_tarball
        }
        _ => false,
    }
}

pub(crate) fn npm_lock_report_coordinate(resolved: &str) -> String {
    let credential_shaped = |value: &str| {
        value.split('/').any(|segment| {
            let decoded =
                npm_percent_decode_path_component(segment).unwrap_or_else(|| segment.to_owned());
            decoded
                .rsplit_once('@')
                .is_some_and(|(userinfo, host)| userinfo.contains(':') && !host.is_empty())
        })
    };
    let raw_without_secrets = || {
        let secret = resolved.find(['?', '#']).unwrap_or(resolved.len());
        let sanitized = &resolved[..secret];
        if sanitized.trim().is_empty() || credential_shaped(sanitized) {
            "[redacted-source]".to_owned()
        } else {
            sanitized.to_owned()
        }
    };
    if resolved.starts_with("git@") && resolved.contains(':') {
        return raw_without_secrets();
    }
    let Ok(mut parsed) = Url::parse(resolved) else {
        return raw_without_secrets();
    };
    if credential_shaped(parsed.path())
        || (parsed.cannot_be_a_base() && parsed.path().contains('@'))
    {
        return "[redacted-source]".to_owned();
    }
    if !parsed.username().is_empty() {
        let _ = parsed.set_username("");
    }
    if parsed.password().is_some() {
        let _ = parsed.set_password(None);
    }
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

pub(crate) fn npm_declared_local_target(descriptor: &str, specification: &str) -> Option<String> {
    let local = ["file:", "link:"]
        .into_iter()
        .find_map(|prefix| {
            specification
                .get(..prefix.len())
                .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
                .map(|_| &specification[prefix.len()..])
        })
        .or_else(|| {
            specification
                .starts_with(['.', '/'])
                .then_some(specification)
        })?;
    let local = local.replace('\\', "/");
    if local.is_empty()
        || local.starts_with('/')
        || local.contains(['?', '#', '\0'])
        || local.contains("://")
    {
        return None;
    }

    let mut segments = descriptor
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for segment in local.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.last().is_some_and(|segment| segment != "..") {
                    segments.pop();
                } else {
                    segments.push("..".to_owned());
                }
            }
            value => segments.push(value.to_owned()),
        }
    }
    (!segments.is_empty()).then(|| segments.join("/"))
}
