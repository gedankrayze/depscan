use super::*;

pub(crate) fn parse_nuget_project(path: &Path) -> Result<Vec<Package>, ParseError> {
    if let Some(lock) = project_lock_file(path) {
        return parse_packages_lock(&lock);
    }
    let document = parse_nuget_xml_document(path)?;
    require_xml_root(path, &document.root, "Project")?;
    let central_path = nearest_directory_packages_props(path);
    let central = central_path
        .as_deref()
        .map(central_package_versions)
        .transpose()?
        .unwrap_or_default();
    let mut references: Vec<NugetXmlItem> = Vec::new();
    for reference in document
        .items
        .into_iter()
        .filter(|item| item.kind == NugetXmlItemKind::PackageReference)
    {
        if reference.identity_kind == Some(NugetXmlIdentityKind::Update) {
            let normalized_name = reference
                .name
                .as_deref()
                .expect("validated package name")
                .to_ascii_lowercase();
            let mut updated = false;
            for existing in references.iter_mut().filter(|existing| {
                existing
                    .name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&normalized_name))
            }) {
                if reference.version.is_some() {
                    existing.version.clone_from(&reference.version);
                }
                if reference.version_override.is_some() {
                    existing
                        .version_override
                        .clone_from(&reference.version_override);
                }
                existing.development_dependency |= reference.development_dependency;
                updated = true;
            }
            if updated {
                continue;
            }
        }
        references.push(reference);
    }

    let mut packages = Vec::new();
    for reference in references {
        let display_name = reference.name.expect("validated package name");
        let central_version = central.get(&display_name.to_ascii_lowercase());
        let version = reference
            .version_override
            .or(reference.version)
            .or_else(|| central_version.map(|central| central.version.clone()))
            .ok_or_else(|| {
                let props = central_path
                    .as_ref()
                    .map_or_else(|| "no Directory.Packages.props was found".to_owned(), |path| {
                        format!("{} has no matching PackageVersion", path.display())
                    });
                invalid(
                    path,
                    format!(
                        "PackageReference {display_name:?} has no inline, override, or central version ({props})"
                    ),
                )
            })?;
        let name = central_version.map_or(display_name, |central| central.display_name.clone());
        packages.push(package_from_manifest(
            name,
            version,
            path,
            reference.development_dependency,
        ));
    }
    Ok(dedup(packages))
}

pub(crate) fn parse_directory_packages_props(path: &Path) -> Result<Vec<Package>, ParseError> {
    Ok(central_package_versions(path)?
        .into_values()
        .map(|central| package_from_manifest(central.display_name, central.version, path, false))
        .collect())
}

pub(crate) fn parse_packages_config(path: &Path) -> Result<Vec<Package>, ParseError> {
    let document = parse_nuget_xml_document(path)?;
    require_xml_root(path, &document.root, "packages")?;
    let packages = document
        .items
        .into_iter()
        .filter(|item| item.kind == NugetXmlItemKind::LegacyPackage)
        .map(|item| {
            let mut package = Package::new(
                Ecosystem::NuGet,
                item.name.expect("validated package name"),
                item.version.expect("validated package version"),
                path.to_path_buf(),
            );
            package.direct = true;
            package.dev = item.development_dependency;
            package
        })
        .collect();
    Ok(dedup(packages))
}
