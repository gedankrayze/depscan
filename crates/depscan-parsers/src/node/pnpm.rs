use super::*;

pub(crate) fn parse_pnpm_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = read_yaml_text(path)?;
    let value = parse_yaml_document(path, &text)?;
    value.as_mapping().ok_or_else(|| {
        invalid(
            path,
            "detected a non-mapping YAML document; expected a pnpm-lock.yaml mapping",
        )
    })?;
    let lockfile_version = value.get("lockfileVersion").ok_or_else(|| {
        invalid(
            path,
            "detected YAML without lockfileVersion; expected pnpm lockfile version 6.0 or 9.0",
        )
    })?;
    let supported_version = lockfile_version
        .as_str()
        .is_some_and(|version| matches!(version, "6" | "6.0" | "9" | "9.0"))
        || lockfile_version
            .as_f64()
            .is_some_and(|version| version == 6.0 || version == 9.0);
    if !supported_version {
        let detected = lockfile_version.as_str().map_or_else(
            || {
                lockfile_version
                    .as_f64()
                    .map_or_else(|| "non-scalar".to_owned(), |version| version.to_string())
            },
            str::to_owned,
        );
        return Err(invalid(
            path,
            format!(
                "detected unsupported pnpm lockfileVersion {detected:?}; expected version 6.0 or 9.0"
            ),
        ));
    }
    let mut out = Vec::new();
    let packages = value
        .get("packages")
        .and_then(Yaml::as_mapping)
        .ok_or_else(|| {
            invalid(
                path,
                "detected a supported pnpm lockfile without a packages mapping; expected the resolved package map",
            )
        })?;
    let direct_references = pnpm_direct_references(&value, packages);
    for (key, entry) in packages {
        let entry = entry.as_mapping().ok_or_else(|| {
            invalid(
                path,
                format!("pnpm package entry {key:?} must be a mapping"),
            )
        })?;
        let (name, version) = parse_pnpm_key(key).ok_or_else(|| {
            invalid(
                path,
                format!("pnpm package key {key:?} is not a supported package locator"),
            )
        })?;
        validate_bun_package_name(name).map_err(|error| {
            invalid(
                path,
                format!("pnpm package key {key:?} has an invalid package name: {error}"),
            )
        })?;
        if version.starts_with("file:")
            || version.starts_with("link:")
            || version.starts_with("workspace:")
            || version.starts_with("git+")
            || version.starts_with("github:")
            || version.starts_with("http://")
            || version.starts_with("https://")
        {
            continue;
        }
        semver::Version::parse(version).map_err(|error| {
            invalid(
                path,
                format!("pnpm package key {key:?} has an invalid npm version {version:?}: {error}"),
            )
        })?;
        let dev = entry
            .get("dev")
            .map(|value| {
                value.as_bool().ok_or_else(|| {
                    invalid(
                        path,
                        format!("pnpm package entry {key:?} dev must be a boolean"),
                    )
                })
            })
            .transpose()?;
        let exact_locator = key.trim_start_matches('/');
        let mut package = Package::new(Ecosystem::Npm, name, version, path.to_path_buf());
        package.dev = dev.unwrap_or(false);
        package.dev_known = dev.is_some();
        if let Some(direct) = direct_references.get(exact_locator) {
            package.direct = true;
            package.direct_known = true;
            package.dev = direct.development && !direct.production;
            package.dev_known = true;
            if let Some(display_alias) = direct.display_alias() {
                package.display_name = display_alias.to_owned();
            }
        } else {
            package.direct_known = false;
        }
        out.push(package);
    }
    Ok(dedup(out))
}

#[derive(Default)]
pub(crate) struct PnpmDirectReference {
    production: bool,
    development: bool,
    canonical: bool,
    aliases: BTreeSet<String>,
}

impl PnpmDirectReference {
    pub(crate) fn display_alias(&self) -> Option<&str> {
        (!self.canonical && self.aliases.len() == 1)
            .then(|| self.aliases.first().map(String::as_str))
            .flatten()
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.production |= other.production;
        self.development |= other.development;
        self.canonical |= other.canonical;
        self.aliases.extend(other.aliases);
    }
}

pub(crate) fn pnpm_direct_references(
    value: &Yaml,
    packages: &noyalib::Mapping,
) -> BTreeMap<String, PnpmDirectReference> {
    let mut requested = BTreeMap::new();
    if let Some(importers) = value.get("importers").and_then(Yaml::as_mapping) {
        for importer in importers.values().filter_map(Yaml::as_mapping) {
            append_pnpm_importer_references(importer, &mut requested);
        }
    }

    // pnpm v6 uses these document-level dependency groups for a non-workspace project.
    if value.get("importers").is_none()
        && let Some(root) = value.as_mapping()
    {
        append_pnpm_importer_references(root, &mut requested);
    }

    let package_locators = packages
        .keys()
        .map(|locator| locator.trim_start_matches('/').to_owned())
        .collect::<BTreeSet<_>>();
    let snapshot_locators = value
        .get("snapshots")
        .and_then(Yaml::as_mapping)
        .into_iter()
        .flat_map(|snapshots| snapshots.iter())
        .filter(|(_, snapshot)| snapshot.as_mapping().is_some())
        .map(|(locator, _)| locator.trim_start_matches('/').to_owned())
        .collect::<BTreeSet<_>>();

    let mut direct = BTreeMap::<String, PnpmDirectReference>::new();
    for (resolved_locator, reference) in requested {
        let package_locator = if package_locators.contains(&resolved_locator) {
            Some(resolved_locator)
        } else if snapshot_locators.contains(&resolved_locator) {
            parse_pnpm_key(&resolved_locator).map(|(name, version)| format!("{name}@{version}"))
        } else {
            None
        };
        let Some(package_locator) =
            package_locator.filter(|locator| package_locators.contains(locator))
        else {
            continue;
        };
        direct.entry(package_locator).or_default().merge(reference);
    }
    direct
}

pub(crate) fn append_pnpm_importer_references(
    importer: &noyalib::Mapping,
    direct: &mut BTreeMap<String, PnpmDirectReference>,
) {
    for (group, development) in [
        ("dependencies", false),
        ("optionalDependencies", false),
        ("peerDependencies", false),
        ("devDependencies", true),
    ] {
        let Some(dependencies) = importer.get(group).and_then(Yaml::as_mapping) else {
            continue;
        };
        for (declared_name, dependency) in dependencies {
            let Some(version) = pnpm_importer_version(dependency) else {
                continue;
            };
            let Some((locator, package_name)) = pnpm_resolved_locator(declared_name, version)
            else {
                continue;
            };
            let reference = direct.entry(locator).or_default();
            if development {
                reference.development = true;
            } else {
                reference.production = true;
            }
            if package_name != declared_name.as_str() {
                reference.aliases.insert(declared_name.clone());
            } else {
                reference.canonical = true;
            }
        }
    }
}

pub(crate) fn pnpm_importer_version(dependency: &Yaml) -> Option<&str> {
    dependency.as_str().or_else(|| {
        dependency
            .as_mapping()
            .and_then(|entry| entry.get("version"))
            .and_then(Yaml::as_str)
    })
}

pub(crate) fn pnpm_resolved_locator(
    declared_name: &str,
    resolved: &str,
) -> Option<(String, String)> {
    let resolved = resolved.trim_start_matches('/');
    if resolved.is_empty()
        || resolved.starts_with("file:")
        || resolved.starts_with("link:")
        || resolved.starts_with("workspace:")
        || resolved.starts_with("git+")
        || resolved.starts_with("github:")
        || resolved.starts_with("http://")
        || resolved.starts_with("https://")
    {
        return None;
    }

    let locator = if parse_pnpm_key(resolved).is_some() {
        resolved.to_owned()
    } else {
        format!("{declared_name}@{resolved}")
    };
    let (package_name, version) = parse_pnpm_key(&locator)?;
    validate_bun_package_name(package_name).ok()?;
    semver::Version::parse(version).ok()?;
    let package_name = package_name.to_owned();
    Some((locator, package_name))
}

pub(crate) fn parse_pnpm_key(raw: &str) -> Option<(&str, &str)> {
    let key = raw.trim_start_matches('/').split('(').next().unwrap_or(raw);
    let at = if let Some(stripped) = key.strip_prefix('@') {
        stripped.rfind('@').map(|i| i + 1)
    } else {
        key.rfind('@')
    }?;
    let (name, version) = key.split_at(at);
    let version = version.trim_start_matches('@');
    (!name.is_empty() && !version.is_empty()).then_some((name, version))
}
