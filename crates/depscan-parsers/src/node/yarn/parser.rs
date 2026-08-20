use super::*;

pub(crate) fn parse_yarn_berry(
    path: &Path,
    text: &str,
    direct: &YarnDirectDependencies,
) -> Result<Vec<Package>, ParseError> {
    let value = parse_yaml_document(path, text)?;
    let entries = value
        .as_mapping()
        .ok_or_else(|| invalid(path, "Yarn Berry lockfile root must be a mapping"))?;
    let metadata = value
        .get("__metadata")
        .and_then(Yaml::as_mapping)
        .ok_or_else(|| invalid(path, "Yarn Berry lockfile is missing a __metadata mapping"))?;
    let lockfile_version = metadata
        .get("version")
        .and_then(Yaml::as_u64)
        .ok_or_else(|| invalid(path, "Yarn Berry __metadata is missing an integer version"))?;
    if !(YARN_BERRY_MIN_LOCKFILE_VERSION..=YARN_BERRY_MAX_LOCKFILE_VERSION)
        .contains(&lockfile_version)
    {
        return Err(invalid(
            path,
            format!(
                "unsupported Yarn Berry lockfile version {lockfile_version}; supported released versions are {YARN_BERRY_MIN_LOCKFILE_VERSION} through {YARN_BERRY_MAX_LOCKFILE_VERSION}"
            ),
        ));
    }

    let mut descriptor_groups = Vec::new();
    for (raw_key, _) in entries {
        let key = raw_key.as_str();
        if key == "__metadata" {
            continue;
        }
        let descriptors = split_yarn_descriptors(key).map_err(|error| {
            invalid(
                path,
                format!("invalid Yarn Berry descriptor list {key:?}: {error}"),
            )
        })?;
        descriptor_groups.push(descriptors);
    }
    let direct = bind_yarn_direct_dependencies(direct, &descriptor_groups)
        .map_err(|error| invalid(path, format!("invalid Yarn Berry descriptor: {error}")))?;

    let mut packages = Vec::new();
    for (raw_key, raw_entry) in entries {
        let key = raw_key.as_str();
        if key == "__metadata" {
            continue;
        }
        let descriptors = split_yarn_descriptors(key).map_err(|error| {
            invalid(
                path,
                format!("invalid Yarn Berry descriptor list {key:?}: {error}"),
            )
        })?;
        for descriptor in &descriptors {
            parse_yarn_locator(descriptor).map_err(|error| {
                invalid(
                    path,
                    format!("invalid Yarn Berry descriptor {descriptor:?}: {error}"),
                )
            })?;
        }
        let entry = raw_entry
            .as_mapping()
            .ok_or_else(|| invalid(path, format!("Yarn Berry entry {key:?} must be a mapping")))?;
        let version = entry.get("version").and_then(Yaml::as_str).ok_or_else(|| {
            invalid(
                path,
                format!("Yarn Berry entry {key:?} is missing a string version"),
            )
        })?;
        let resolution = entry
            .get("resolution")
            .and_then(Yaml::as_str)
            .ok_or_else(|| {
                invalid(
                    path,
                    format!("Yarn Berry entry {key:?} is missing a string resolution"),
                )
            })?;
        let locator = parse_yarn_locator(resolution).map_err(|error| {
            invalid(
                path,
                format!("Yarn Berry entry {key:?} has invalid resolution {resolution:?}: {error}"),
            )
        })?;
        let source = yarn_reference_source(locator.reference);
        if source == YarnSource::Workspace {
            continue;
        }
        if source == YarnSource::Registry {
            validate_yarn_registry_version(
                version,
                locator.reference,
                &format!("Yarn Berry entry {key:?}"),
            )
            .map_err(|error| invalid(path, error))?;
        }
        let (is_direct, direct_known, is_dev, dev_known, display_alias) =
            yarn_direct_metadata(&descriptors, locator.name, &direct).map_err(|error| {
                invalid(
                    path,
                    format!("Yarn Berry entry {key:?} has invalid descriptor: {error}"),
                )
            })?;
        let mut package = Package::new(Ecosystem::Npm, locator.name, version, path.to_path_buf());
        package.direct = is_direct;
        package.direct_known = direct_known;
        package.dev = is_dev;
        package.dev_known = dev_known;
        package.enrichable = source == YarnSource::Registry;
        if let Some(display_alias) = display_alias {
            package.display_name = display_alias;
        }
        packages.push(package);
    }
    Ok(dedup(packages))
}

#[derive(Debug)]
pub(crate) struct YarnClassicEntry {
    key: String,
    descriptors: Vec<String>,
    version: Option<String>,
    resolved: Option<String>,
}

pub(crate) fn parse_yarn_classic(
    path: &Path,
    text: &str,
    direct: &YarnDirectDependencies,
) -> Result<Vec<Package>, ParseError> {
    let mut entries = Vec::new();
    let mut current: Option<YarnClassicEntry> = None;
    for (line_index, line) in text.lines().enumerate() {
        let line_number = line_index + 1;
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            let key = line.strip_suffix(':').ok_or_else(|| {
                invalid(
                    path,
                    format!("invalid Yarn Classic entry header on line {line_number}"),
                )
            })?;
            let descriptors = split_yarn_descriptors(key).map_err(|error| {
                invalid(
                    path,
                    format!("invalid Yarn Classic descriptor list on line {line_number}: {error}"),
                )
            })?;
            for descriptor in &descriptors {
                parse_yarn_locator(descriptor).map_err(|error| {
                    invalid(
                        path,
                        format!(
                            "invalid Yarn Classic descriptor {descriptor:?} on line {line_number}: {error}"
                        ),
                    )
                })?;
            }
            current = Some(YarnClassicEntry {
                key: key.to_owned(),
                descriptors,
                version: None,
                resolved: None,
            });
            continue;
        }
        if line.starts_with('\t') {
            return Err(invalid(
                path,
                format!("Yarn Classic lockfile uses a tab for indentation on line {line_number}"),
            ));
        }
        let indentation = line.bytes().take_while(|byte| *byte == b' ').count();
        if indentation != 2 {
            continue;
        }
        let entry = current.as_mut().ok_or_else(|| {
            invalid(
                path,
                format!("Yarn Classic field appears before an entry on line {line_number}"),
            )
        })?;
        let field = &line[indentation..];
        if let Some(raw_version) = field.strip_prefix("version ") {
            if entry.version.is_some() {
                return Err(invalid(
                    path,
                    format!("Yarn Classic entry {:?} repeats version", entry.key),
                ));
            }
            entry.version = Some(parse_yarn_scalar(raw_version).map_err(|error| {
                invalid(
                    path,
                    format!("invalid Yarn Classic version on line {line_number}: {error}"),
                )
            })?);
        } else if let Some(raw_resolved) = field.strip_prefix("resolved ") {
            if entry.resolved.is_some() {
                return Err(invalid(
                    path,
                    format!("Yarn Classic entry {:?} repeats resolved", entry.key),
                ));
            }
            entry.resolved = Some(parse_yarn_scalar(raw_resolved).map_err(|error| {
                invalid(
                    path,
                    format!("invalid Yarn Classic resolution on line {line_number}: {error}"),
                )
            })?);
        }
    }
    if let Some(entry) = current {
        entries.push(entry);
    }
    let descriptor_groups = entries
        .iter()
        .map(|entry| entry.descriptors.clone())
        .collect::<Vec<_>>();
    let direct = bind_yarn_direct_dependencies(direct, &descriptor_groups)
        .map_err(|error| invalid(path, format!("invalid Yarn Classic descriptor: {error}")))?;
    let mut packages = Vec::new();
    for entry in entries {
        push_yarn_classic_entry(path, entry, &direct, &mut packages)?;
    }
    Ok(dedup(packages))
}

pub(crate) fn push_yarn_classic_entry(
    path: &Path,
    entry: YarnClassicEntry,
    direct: &YarnDirectDependencies,
    packages: &mut Vec<Package>,
) -> Result<(), ParseError> {
    let version = entry.version.ok_or_else(|| {
        invalid(
            path,
            format!("Yarn Classic entry {:?} is missing version", entry.key),
        )
    })?;
    let mut source = None;
    let mut package_name = None;
    for descriptor in &entry.descriptors {
        let locator = parse_yarn_locator(descriptor).map_err(|error| invalid(path, error))?;
        let (descriptor_name, descriptor_source) = yarn_classic_descriptor_source(locator)
            .map_err(|error| {
                invalid(
                    path,
                    format!(
                        "Yarn Classic entry {:?} has invalid source descriptor: {error}",
                        entry.key
                    ),
                )
            })?;
        if source.is_some_and(|previous| previous != descriptor_source)
            || package_name
                .as_deref()
                .is_some_and(|previous| previous != descriptor_name)
        {
            return Err(invalid(
                path,
                format!(
                    "Yarn Classic entry {:?} mixes package identities or source protocols",
                    entry.key
                ),
            ));
        }
        source = Some(descriptor_source);
        package_name = Some(descriptor_name.to_owned());
    }
    let source = source.ok_or_else(|| invalid(path, "Yarn Classic entry has no descriptors"))?;
    if source == YarnSource::Workspace {
        return Ok(());
    }
    let package_name =
        package_name.ok_or_else(|| invalid(path, "Yarn Classic entry has no package identity"))?;
    if source == YarnSource::Registry {
        semver::Version::parse(&version).map_err(|error| {
            invalid(
                path,
                format!(
                    "Yarn Classic entry {:?} has an invalid npm version {version:?}: {error}",
                    entry.key
                ),
            )
        })?;
    }
    let (is_direct, direct_known, is_dev, dev_known, display_alias) =
        yarn_direct_metadata(&entry.descriptors, &package_name, direct).map_err(|error| {
            invalid(
                path,
                format!(
                    "Yarn Classic entry {:?} has invalid descriptor: {error}",
                    entry.key
                ),
            )
        })?;
    let mut package = Package::new(Ecosystem::Npm, package_name, version, path.to_path_buf());
    package.direct = is_direct;
    package.direct_known = direct_known;
    package.dev = is_dev;
    package.dev_known = dev_known;
    package.enrichable = source == YarnSource::Registry;
    if let Some(display_alias) = display_alias {
        package.display_name = display_alias;
    }
    packages.push(package);
    Ok(())
}

pub(crate) fn yarn_classic_descriptor_source(
    locator: YarnLocator<'_>,
) -> Result<(&str, YarnSource), String> {
    if let Some(alias) = locator.reference.strip_prefix("npm:") {
        if alias.contains('@') {
            let target = parse_yarn_locator(alias)?;
            return Ok((target.name, YarnSource::Registry));
        }
        return Ok((locator.name, YarnSource::Registry));
    }
    let source = if locator.reference.starts_with("workspace:") {
        YarnSource::Workspace
    } else if locator.reference.contains(':') {
        YarnSource::Other
    } else {
        YarnSource::Registry
    };
    Ok((locator.name, source))
}
