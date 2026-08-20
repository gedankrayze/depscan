use super::*;

pub(crate) fn parse_legacy_npm_tree(
    dependencies: &serde_json::Map<String, Json>,
    path: &Path,
    direct: &NodeDirectDependencies,
    top_level: bool,
    out: &mut Vec<Package>,
) {
    for (name, entry) in dependencies {
        let Some(entry) = entry.as_object() else {
            continue;
        };
        if let Some(version) = entry
            .get("version")
            .and_then(Json::as_str)
            .filter(|version| !version.is_empty())
        {
            let parsed_version = semver::Version::parse(version);
            let report_version = if parsed_version.is_err() {
                npm_lock_report_coordinate(version)
            } else {
                version.to_owned()
            };
            let mut package =
                Package::new(Ecosystem::Npm, name, &report_version, path.to_path_buf());
            if top_level {
                match direct.directness(name) {
                    Some(is_direct) => package.direct = is_direct,
                    None => package.direct_known = false,
                }
            }
            package.dev = entry.get("dev").and_then(Json::as_bool).unwrap_or(false);
            package.enrichable = parsed_version.is_ok()
                && !npm_lock_source_locator(version)
                && matches!(
                    npm_lock_resolved_source(entry.get("resolved").and_then(Json::as_str)),
                    Ok(NpmResolvedSource::PublicRegistry)
                );
            out.push(package);
        }
        if let Some(children) = entry.get("dependencies").and_then(Json::as_object) {
            parse_legacy_npm_tree(children, path, direct, false, out);
        }
    }
}
