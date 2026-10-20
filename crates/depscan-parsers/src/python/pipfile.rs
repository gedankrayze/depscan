use super::*;
use serde_json::Map;

pub(super) fn parse_pipfile_lock(path: &Path) -> Result<Vec<Package>, ParseError> {
    let text = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
    let value: Json = serde_json::from_str(&text).map_err(|error| invalid(path, error))?;
    let document = value
        .as_object()
        .ok_or_else(|| invalid(path, "expected a Pipfile.lock object"))?;
    let metadata = document
        .get("_meta")
        .and_then(Json::as_object)
        .ok_or_else(|| invalid(path, "expected Pipfile.lock metadata with a _meta object"))?;
    let spec = metadata
        .get("pipfile-spec")
        .and_then(Json::as_u64)
        .ok_or_else(|| invalid(path, "expected integer Pipfile.lock pipfile-spec 6"))?;
    if spec != 6 {
        return Err(invalid(
            path,
            format!("unsupported Pipfile.lock pipfile-spec {spec}; expected 6"),
        ));
    }
    for section in ["default", "develop"] {
        if !document.get(section).is_some_and(Json::is_object) {
            return Err(invalid(
                path,
                format!("Pipfile.lock without a {section} object; expected a dependency map"),
            ));
        }
    }
    let sources = sources(path, metadata.get("sources"))?;
    let directness = pipfile_direct_dependencies(path);
    let mut output = Vec::new();
    for (section, dependencies) in document.iter().filter(|(name, _)| *name != "_meta") {
        let dependencies = dependencies.as_object().ok_or_else(|| {
            invalid(
                path,
                format!("Pipfile.lock category {section:?} must be an object"),
            )
        })?;
        for (name, item) in dependencies {
            let context = format!("Pipfile.lock {section} package {name:?}");
            python_locks::normalized_name(name, path, &context)?;
            let item = item
                .as_object()
                .ok_or_else(|| invalid(path, format!("{context} must be an object")))?;
            let nonregistry = nonregistry(path, item, &context)?;
            let version = match item.get("version") {
                Some(value) => {
                    let raw = value.as_str().ok_or_else(|| {
                        invalid(path, format!("{context} version must be a string"))
                    })?;
                    let version = raw.strip_prefix("==").unwrap_or(raw);
                    python_locks::validate_version(version, path, &context)?;
                    version
                }
                None if nonregistry => "<non-registry>",
                None => {
                    return Err(invalid(
                        path,
                        format!("{context} is missing a resolved version or non-index source"),
                    ));
                }
            };
            let mut package = Package::new(Ecosystem::PyPI, name, version, path.to_path_buf());
            package.enrichable = !nonregistry && public_index(path, item, &sources, &context)?;
            match directness.for_lock_section(section) {
                Some(direct) => package.direct = direct.contains(&package.name),
                None => package.direct_known = false,
            }
            package.dev = section == "develop";
            package.dev_known = matches!(section.as_str(), "default" | "develop");
            output.push(package);
        }
    }
    Ok(dedup(output))
}

fn sources(path: &Path, value: Option<&Json>) -> Result<BTreeMap<String, bool>, ParseError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let entries = value
        .as_array()
        .ok_or_else(|| invalid(path, "Pipfile.lock sources must be an array"))?;
    let mut sources = BTreeMap::new();
    for entry in entries {
        let name = entry
            .get("name")
            .and_then(Json::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid(path, "Pipfile.lock source needs a nonempty name"))?;
        let url = entry
            .get("url")
            .and_then(Json::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid(path, "Pipfile.lock source needs a nonempty URL"))?;
        if sources
            .insert(name.to_owned(), python_locks::is_pypi_index(url))
            .is_some()
        {
            return Err(invalid(path, "Pipfile.lock source names must be unique"));
        }
    }
    Ok(sources)
}

fn nonregistry(path: &Path, item: &Map<String, Json>, context: &str) -> Result<bool, ParseError> {
    let mut nonregistry = false;
    for field in ["git", "file", "path"] {
        if let Some(value) = item.get(field) {
            if !value.as_str().is_some_and(|value| !value.is_empty()) {
                return Err(invalid(
                    path,
                    format!("{context} {field} must be a nonempty string"),
                ));
            }
            nonregistry = true;
        }
    }
    if let Some(value) = item.get("editable") {
        nonregistry |= value
            .as_bool()
            .ok_or_else(|| invalid(path, format!("{context} editable must be a boolean")))?;
    }
    Ok(nonregistry)
}

fn public_index(
    path: &Path,
    item: &Map<String, Json>,
    sources: &BTreeMap<String, bool>,
    context: &str,
) -> Result<bool, ParseError> {
    match item.get("index") {
        Some(value) => {
            let index = value
                .as_str()
                .ok_or_else(|| invalid(path, format!("{context} index must be a string")))?;
            Ok(sources.get(index).copied().unwrap_or(false))
        }
        None => Ok(sources.len() == 1 && sources.values().all(|public| *public)),
    }
}
