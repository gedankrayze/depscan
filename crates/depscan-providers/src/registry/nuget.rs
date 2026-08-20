use super::*;

pub(crate) fn nuget_registry_cache_key(package: &Package) -> String {
    format!("nuget:{}", package.name)
}

#[cfg(test)]
pub(crate) fn nuget_registry_url(package: &Package) -> String {
    nuget_registry_url_with_base(NUGET_REGISTRY_BASE_URL, package)
}

pub(crate) fn nuget_registry_url_with_base(base_url: &str, package: &Package) -> String {
    format!(
        "{}/{}/index.json",
        base_url,
        encode_path_segment(&package.name)
    )
}

pub(crate) fn nuget_registration_cache_key(package: &Package) -> String {
    format!("nuget-registration:{}", package.name)
}

pub(crate) fn nuget_registration_url_with_base(base_url: &str, package: &Package) -> String {
    format!(
        "{}/{}/index.json",
        base_url,
        encode_path_segment(&package.name)
    )
}

pub(crate) fn nuget_registration_page_cache_key(
    package: &Package,
    lower: &str,
    upper: &str,
) -> String {
    format!("nuget-registration-page:{}:{lower}:{upper}", package.name)
}

#[derive(Debug)]
pub(crate) enum NugetRegistrationPageSource {
    Inline(Value),
    Linked {
        lower: String,
        upper: String,
        url: String,
    },
}

pub(crate) fn invalid_nuget_registration(reason: impl std::fmt::Display) -> ProviderError {
    ProviderError::InvalidResponse(format!("NuGet registration metadata is invalid: {reason}"))
}

pub(crate) fn nuget_registration_page_for_version(
    document: &Value,
    target_raw: &str,
) -> Result<NugetRegistrationPageSource, ProviderError> {
    let target = NuGetVersion::parse(target_raw).map_err(invalid_nuget_registration)?;
    let root = document
        .as_object()
        .ok_or_else(|| invalid_nuget_registration("index root must be an object"))?;
    let pages = root
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_nuget_registration("index must contain a pages array"))?;
    let count = root
        .get("count")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_nuget_registration("index must contain an integer page count"))?;
    if usize::try_from(count).ok() != Some(pages.len()) {
        return Err(invalid_nuget_registration(format_args!(
            "index page count {count} does not match its {} pages",
            pages.len()
        )));
    }

    let mut selected = None;
    for (index, page) in pages.iter().enumerate() {
        let page = page.as_object().ok_or_else(|| {
            invalid_nuget_registration(format_args!("index page {index} must be an object"))
        })?;
        let lower_raw = page.get("lower").and_then(Value::as_str).ok_or_else(|| {
            invalid_nuget_registration(format_args!("index page {index} has no lower bound"))
        })?;
        let upper_raw = page.get("upper").and_then(Value::as_str).ok_or_else(|| {
            invalid_nuget_registration(format_args!("index page {index} has no upper bound"))
        })?;
        let lower = NuGetVersion::parse(lower_raw).map_err(invalid_nuget_registration)?;
        let upper = NuGetVersion::parse(upper_raw).map_err(invalid_nuget_registration)?;
        if lower > upper {
            return Err(invalid_nuget_registration(format_args!(
                "index page {index} lower bound {lower_raw:?} exceeds {upper_raw:?}"
            )));
        }
        if target < lower || target > upper {
            continue;
        }
        if selected.is_some() {
            return Err(invalid_nuget_registration(format_args!(
                "more than one index page contains version {target_raw:?}"
            )));
        }
        selected = Some(match page.get("items") {
            Some(items) => {
                let items = items.as_array().ok_or_else(|| {
                    invalid_nuget_registration(format_args!(
                        "inline index page {index} items must be an array"
                    ))
                })?;
                let count = page.get("count").and_then(Value::as_u64).ok_or_else(|| {
                    invalid_nuget_registration(format_args!(
                        "inline index page {index} has no integer leaf count"
                    ))
                })?;
                if usize::try_from(count).ok() != Some(items.len()) {
                    return Err(invalid_nuget_registration(format_args!(
                        "inline index page {index} leaf count {count} does not match its {} leaves",
                        items.len()
                    )));
                }
                NugetRegistrationPageSource::Inline(Value::Object(page.clone()))
            }
            None => {
                let url = page.get("@id").and_then(Value::as_str).ok_or_else(|| {
                    invalid_nuget_registration(format_args!(
                        "non-inline index page {index} has no @id"
                    ))
                })?;
                NugetRegistrationPageSource::Linked {
                    lower: lower_raw.to_owned(),
                    upper: upper_raw.to_owned(),
                    url: url.to_owned(),
                }
            }
        });
    }
    selected.ok_or_else(|| {
        invalid_nuget_registration(format_args!(
            "no index page contains version {target_raw:?}"
        ))
    })
}

pub(crate) fn validated_nuget_registration_page_url(
    base_url: &str,
    package: &Package,
    raw_url: &str,
) -> Result<String, ProviderError> {
    let base = Url::parse(base_url).map_err(|error| {
        invalid_nuget_registration(format_args!("registration base URL is invalid: {error}"))
    })?;
    let mut page = Url::parse(raw_url).map_err(|error| {
        invalid_nuget_registration(format_args!("registration page URL is invalid: {error}"))
    })?;
    if page.origin() != base.origin() || !page.username().is_empty() || page.password().is_some() {
        return Err(invalid_nuget_registration(
            "registration page URL must use the registration base origin without credentials",
        ));
    }
    let package_prefix = format!(
        "{}/{}/",
        base.path().trim_end_matches('/'),
        encode_path_segment(&package.name)
    );
    if !page.path().starts_with(&package_prefix) {
        return Err(invalid_nuget_registration(format_args!(
            "registration page URL path must start with {package_prefix:?}"
        )));
    }
    page.set_fragment(None);
    Ok(page.into())
}

pub(crate) fn canonical_nuget_name_from_registration_page(
    package: &Package,
    target_raw: &str,
    page: &Value,
) -> Result<String, ProviderError> {
    let target = NuGetVersion::parse(target_raw).map_err(invalid_nuget_registration)?;
    let page = page
        .as_object()
        .ok_or_else(|| invalid_nuget_registration("page root must be an object"))?;
    let leaves = page
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_nuget_registration("page must contain a leaves array"))?;
    let count = page
        .get("count")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_nuget_registration("page must contain an integer leaf count"))?;
    if usize::try_from(count).ok() != Some(leaves.len()) {
        return Err(invalid_nuget_registration(format_args!(
            "page leaf count {count} does not match its {} leaves",
            leaves.len()
        )));
    }

    let mut canonical = None;
    for (index, leaf) in leaves.iter().enumerate() {
        let catalog = leaf
            .get("catalogEntry")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                invalid_nuget_registration(format_args!(
                    "registration leaf {index} has no catalogEntry object"
                ))
            })?;
        let version_raw = catalog
            .get("version")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                invalid_nuget_registration(format_args!(
                    "registration leaf {index} has no catalogEntry.version"
                ))
            })?;
        let version = NuGetVersion::parse(version_raw).map_err(invalid_nuget_registration)?;
        if version != target {
            continue;
        }
        if canonical.is_some() {
            return Err(invalid_nuget_registration(format_args!(
                "more than one registration leaf matches version {target_raw:?}"
            )));
        }
        let id = catalog.get("id").and_then(Value::as_str).ok_or_else(|| {
            invalid_nuget_registration(format_args!(
                "registration leaf {index} has no catalogEntry.id"
            ))
        })?;
        if normalize_name(Ecosystem::NuGet, id) != package.name {
            return Err(invalid_nuget_registration(format_args!(
                "catalogEntry.id {id:?} does not match requested package {:?}",
                package.name
            )));
        }
        canonical = Some(id.to_owned());
    }
    canonical.ok_or_else(|| {
        invalid_nuget_registration(format_args!(
            "no registration leaf matches version {target_raw:?}"
        ))
    })
}
