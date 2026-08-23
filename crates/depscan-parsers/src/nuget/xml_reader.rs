use super::*;

pub(crate) fn parse_nuget_xml_document(path: &Path) -> Result<NugetXmlDocument, ParseError> {
    let content = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
    let mut reader = Reader::from_str(&content);
    reader.config_mut().trim_text(true);
    let mut root = None;
    let mut items = Vec::new();
    let mut open: Option<OpenNugetXmlItem> = None;
    let mut depth = 0_usize;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(element)) => {
                let qualified_name = element.name();
                let name = xml_local_name(qualified_name.as_ref());
                if depth == 0 {
                    root = Some(name.to_owned());
                }
                if open
                    .as_ref()
                    .is_some_and(|open_item| open_item.captured.is_some())
                {
                    return Err(invalid(
                        path,
                        "NuGet package metadata cannot contain nested XML elements",
                    ));
                }
                if let Some(kind) = nuget_item_kind(name) {
                    if open.is_some() {
                        return Err(invalid(path, "NuGet package items cannot be nested"));
                    }
                    open = Some(OpenNugetXmlItem {
                        depth,
                        item: new_nuget_xml_item(path, &element, kind)?,
                        captured: None,
                    });
                } else if let Some(kind) = nuget_metadata_kind(name)
                    && let Some(open_item) = open.as_mut()
                    && depth == open_item.depth + 1
                {
                    if open_item.captured.is_some() {
                        return Err(invalid(path, "NuGet package metadata cannot be nested"));
                    }
                    open_item.captured = Some(CapturedMetadata {
                        kind,
                        depth,
                        value: String::new(),
                    });
                    parse_nuget_xml_attributes(path, &element)?;
                } else {
                    parse_nuget_xml_attributes(path, &element)?;
                }
                depth += 1;
            }
            Ok(Event::Empty(element)) => {
                let qualified_name = element.name();
                let name = xml_local_name(qualified_name.as_ref());
                if depth == 0 {
                    root = Some(name.to_owned());
                }
                if open
                    .as_ref()
                    .is_some_and(|open_item| open_item.captured.is_some())
                {
                    return Err(invalid(
                        path,
                        "NuGet package metadata cannot contain nested XML elements",
                    ));
                }
                if let Some(kind) = nuget_item_kind(name) {
                    if open.is_some() {
                        return Err(invalid(path, "NuGet package items cannot be nested"));
                    }
                    let item = new_nuget_xml_item(path, &element, kind)?;
                    if let Some(item) = finish_nuget_xml_item(path, item)? {
                        items.push(item);
                    }
                } else if nuget_metadata_kind(name).is_some()
                    && open
                        .as_ref()
                        .is_some_and(|open_item| depth == open_item.depth + 1)
                {
                    return Err(invalid(path, "NuGet package metadata cannot be empty"));
                } else {
                    parse_nuget_xml_attributes(path, &element)?;
                }
            }
            Ok(Event::Text(text)) => {
                let text = text.xml10_content();
                append_xml_text(path, &mut open, &text)?;
            }
            Ok(Event::CData(text)) => {
                let text = text.xml10_content();
                if let Some(captured) = open.as_mut().and_then(|open| open.captured.as_mut()) {
                    captured.value.push_str(&text);
                }
            }
            Ok(Event::End(element)) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| invalid(path, "unexpected closing XML element"))?;
                let qualified_name = element.name();
                let name = xml_local_name(qualified_name.as_ref());
                if let Some(open_item) = open.as_mut()
                    && let Some(captured) = open_item.captured.as_ref()
                    && depth == captured.depth
                {
                    if nuget_metadata_kind(name) != Some(captured.kind) {
                        return Err(invalid(path, "mismatched NuGet package metadata"));
                    }
                    let captured = open_item.captured.take().expect("capture checked above");
                    set_nuget_metadata(path, &mut open_item.item, captured.kind, captured.value)?;
                }
                if open
                    .as_ref()
                    .is_some_and(|open_item| depth == open_item.depth)
                {
                    let open_item = open.take().expect("open item checked above");
                    if nuget_item_kind(name) != Some(open_item.item.kind) {
                        return Err(invalid(path, "mismatched NuGet package item"));
                    }
                    if let Some(item) = finish_nuget_xml_item(path, open_item.item)? {
                        items.push(item);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(error) => return Err(invalid(path, error)),
            _ => {}
        }
        buf.clear();
    }

    let root = root.ok_or_else(|| invalid(path, "NuGet XML document has no root element"))?;
    Ok(NugetXmlDocument { root, items })
}

pub(crate) fn require_xml_root(
    path: &Path,
    actual: &str,
    expected: &str,
) -> Result<(), ParseError> {
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(invalid(
            path,
            format!("expected NuGet XML root {expected:?}, found {actual:?}"),
        ))
    }
}

pub(crate) fn nearest_directory_packages_props(project: &Path) -> Option<PathBuf> {
    project.parent()?.ancestors().find_map(|directory| {
        let candidate = directory.join("Directory.Packages.props");
        candidate.is_file().then_some(candidate)
    })
}

pub(crate) fn central_package_versions(
    path: &Path,
) -> Result<BTreeMap<String, CentralPackageVersion>, ParseError> {
    let document = parse_nuget_xml_document(path)?;
    require_xml_root(path, &document.root, "Project")?;
    let mut versions = BTreeMap::new();
    for item in document
        .items
        .into_iter()
        .filter(|item| item.kind == NugetXmlItemKind::PackageVersion)
    {
        let display_name = item.name.expect("validated package name");
        let version = item
            .version_override
            .or(item.version)
            .expect("validated package version");
        versions.insert(
            display_name.to_ascii_lowercase(),
            CentralPackageVersion {
                display_name,
                version,
            },
        );
    }
    Ok(versions)
}

pub(crate) fn package_from_manifest(
    name: String,
    version: String,
    source: &Path,
    dev: bool,
) -> Package {
    let mut package = Package::new(
        Ecosystem::NuGet,
        name,
        version.clone(),
        source.to_path_buf(),
    );
    package.direct = true;
    package.dev = dev;
    package.set_manifest_constraint(version);
    package
}
