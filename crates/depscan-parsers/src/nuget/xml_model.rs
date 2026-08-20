use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NugetXmlItemKind {
    PackageReference,
    PackageVersion,
    GlobalPackageReference,
    LegacyPackage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NugetXmlIdentityKind {
    Include,
    Update,
    Id,
}

#[derive(Debug)]
pub(crate) struct NugetXmlItem {
    pub(crate) kind: NugetXmlItemKind,
    pub(crate) identity_kind: Option<NugetXmlIdentityKind>,
    pub(crate) name: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) version_override: Option<String>,
    pub(crate) development_dependency: bool,
    pub(crate) removed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NugetMetadataKind {
    Version,
    VersionOverride,
    DevelopmentDependency,
}

#[derive(Debug)]
pub(crate) struct CapturedMetadata {
    pub(crate) kind: NugetMetadataKind,
    pub(crate) depth: usize,
    pub(crate) value: String,
}

#[derive(Debug)]
pub(crate) struct OpenNugetXmlItem {
    pub(crate) depth: usize,
    pub(crate) item: NugetXmlItem,
    pub(crate) captured: Option<CapturedMetadata>,
}

#[derive(Debug)]
pub(crate) struct NugetXmlDocument {
    pub(crate) root: String,
    pub(crate) items: Vec<NugetXmlItem>,
}

#[derive(Debug, Clone)]
pub(crate) struct CentralPackageVersion {
    pub(crate) display_name: String,
    pub(crate) version: String,
}

pub(crate) fn xml_local_name(bytes: &[u8]) -> Result<&str, String> {
    let name = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    Ok(name.rsplit(':').next().unwrap_or(name))
}

pub(crate) fn nuget_item_kind(name: &str) -> Option<NugetXmlItemKind> {
    if name.eq_ignore_ascii_case("PackageReference") {
        Some(NugetXmlItemKind::PackageReference)
    } else if name.eq_ignore_ascii_case("PackageVersion") {
        Some(NugetXmlItemKind::PackageVersion)
    } else if name.eq_ignore_ascii_case("GlobalPackageReference") {
        Some(NugetXmlItemKind::GlobalPackageReference)
    } else if name.eq_ignore_ascii_case("package") {
        Some(NugetXmlItemKind::LegacyPackage)
    } else {
        None
    }
}

pub(crate) fn nuget_metadata_kind(name: &str) -> Option<NugetMetadataKind> {
    if name.eq_ignore_ascii_case("Version") {
        Some(NugetMetadataKind::Version)
    } else if name.eq_ignore_ascii_case("VersionOverride") {
        Some(NugetMetadataKind::VersionOverride)
    } else if name.eq_ignore_ascii_case("DevelopmentDependency") {
        Some(NugetMetadataKind::DevelopmentDependency)
    } else {
        None
    }
}

pub(crate) fn parse_nuget_xml_attributes(
    path: &Path,
    reader: &Reader<&[u8]>,
    element: &BytesStart<'_>,
) -> Result<HashMap<String, String>, ParseError> {
    let mut attributes = HashMap::new();
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|error| invalid(path, error))?;
        let key = xml_local_name(attribute.key.as_ref()).map_err(|error| invalid(path, error))?;
        let key = key.to_ascii_lowercase();
        let value = attribute
            .decoded_and_normalized_value(XmlVersion::Implicit1_0, reader.decoder())
            .map_err(|error| invalid(path, error))?
            .into_owned();
        if attributes.insert(key.clone(), value).is_some() {
            return Err(invalid(path, format!("duplicated XML attribute {key:?}")));
        }
    }
    Ok(attributes)
}

pub(crate) fn new_nuget_xml_item(
    path: &Path,
    reader: &Reader<&[u8]>,
    element: &BytesStart<'_>,
    kind: NugetXmlItemKind,
) -> Result<NugetXmlItem, ParseError> {
    let mut attributes = parse_nuget_xml_attributes(path, reader, element)?;
    let identities: Vec<_> = ["include", "update", "id"]
        .into_iter()
        .filter_map(|key| attributes.remove(key).map(|value| (key, value)))
        .collect();
    if identities.len() > 1 {
        return Err(invalid(
            path,
            "NuGet package item has more than one of Include, Update, and id",
        ));
    }
    let identity = identities.into_iter().next();
    let identity_kind = identity.as_ref().map(|(key, _)| match *key {
        "include" => NugetXmlIdentityKind::Include,
        "update" => NugetXmlIdentityKind::Update,
        "id" => NugetXmlIdentityKind::Id,
        _ => unreachable!("identity keys are statically constrained"),
    });
    let name = identity.map(|(_, value)| value);
    let removed = attributes.contains_key("remove");
    let development_dependency = attributes
        .remove("developmentdependency")
        .map(|value| parse_xml_bool(path, "developmentDependency", &value))
        .transpose()?
        .unwrap_or(false);
    Ok(NugetXmlItem {
        kind,
        identity_kind,
        name,
        version: attributes.remove("version"),
        version_override: attributes.remove("versionoverride"),
        development_dependency,
        removed,
    })
}

pub(crate) fn parse_xml_bool(path: &Path, field: &str, value: &str) -> Result<bool, ParseError> {
    if value.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(invalid(
            path,
            format!("NuGet {field} must be true or false, got {value:?}"),
        ))
    }
}

pub(crate) fn append_xml_text(
    path: &Path,
    open: &mut Option<OpenNugetXmlItem>,
    text: &str,
) -> Result<(), ParseError> {
    if let Some(captured) = open.as_mut().and_then(|open| open.captured.as_mut()) {
        let text = unescape(text).map_err(|error| invalid(path, error))?;
        captured.value.push_str(&text);
    }
    Ok(())
}

pub(crate) fn set_nuget_metadata(
    path: &Path,
    item: &mut NugetXmlItem,
    kind: NugetMetadataKind,
    value: String,
) -> Result<(), ParseError> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(invalid(path, "NuGet package metadata cannot be empty"));
    }
    match kind {
        NugetMetadataKind::Version => {
            if item.version.replace(value).is_some() {
                return Err(invalid(
                    path,
                    "NuGet package item defines Version more than once",
                ));
            }
        }
        NugetMetadataKind::VersionOverride => {
            if item.version_override.replace(value).is_some() {
                return Err(invalid(
                    path,
                    "NuGet package item defines VersionOverride more than once",
                ));
            }
        }
        NugetMetadataKind::DevelopmentDependency => {
            item.development_dependency = parse_xml_bool(path, "DevelopmentDependency", &value)?;
        }
    }
    Ok(())
}

pub(crate) fn finish_nuget_xml_item(
    path: &Path,
    mut item: NugetXmlItem,
) -> Result<Option<NugetXmlItem>, ParseError> {
    if item.removed {
        if item.name.is_some() {
            return Err(invalid(
                path,
                "NuGet package item cannot combine Remove with Include, Update, or id",
            ));
        }
        return Ok(None);
    }
    item.name = item.name.map(|name| name.trim().to_owned());
    item.version = item.version.map(|version| version.trim().to_owned());
    item.version_override = item
        .version_override
        .map(|version| version.trim().to_owned());
    if item
        .name
        .as_deref()
        .is_none_or(|name| name.trim().is_empty())
    {
        return Err(invalid(
            path,
            "NuGet package item is missing its package name",
        ));
    }
    if item.version.as_deref().is_some_and(str::is_empty)
        || item.version_override.as_deref().is_some_and(str::is_empty)
    {
        return Err(invalid(path, "NuGet package version cannot be empty"));
    }
    if item.kind != NugetXmlItemKind::PackageReference
        && item
            .version_override
            .as_ref()
            .or(item.version.as_ref())
            .is_none_or(|version| version.trim().is_empty())
    {
        return Err(invalid(
            path,
            "NuGet package item is missing its package version",
        ));
    }
    Ok(Some(item))
}
