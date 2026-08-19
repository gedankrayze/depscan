use depscan_core::{Ecosystem, Package, ParseError};
use std::path::Path;
use toml::{Table, Value as Toml};

use super::{
    constraint::PoetryConstraint,
    source::{PoetrySource, PoetrySourcePolicy, optional_string},
    validate_string_array,
};
use crate::invalid;

#[derive(Debug)]
pub(super) struct PoetryDependency {
    version: Option<PoetryConstraint>,
    source: PoetrySource,
}

impl PoetryDependency {
    pub(super) fn parse(
        value: &Toml,
        policy: &PoetrySourcePolicy,
        path: &Path,
        context: &str,
    ) -> Result<Self, ParseError> {
        if let Some(raw) = value.as_str() {
            return Ok(Self {
                version: Some(PoetryConstraint::parse(raw, path, context)?),
                source: PoetrySource::Registry,
            });
        }
        if value.is_array() {
            return Err(invalid(
                path,
                format!(
                    "{context} uses unsupported multiple Poetry constraints; dependency arrays cannot be represented without environment-specific resolution"
                ),
            ));
        }
        let table = value.as_table().ok_or_else(|| {
            invalid(
                path,
                format!("{context} must be a string or dependency table"),
            )
        })?;
        validate_dependency_fields(table, path, context)?;
        let version = optional_string(table, "version", path, context)?
            .map(|raw| PoetryConstraint::parse(raw, path, context))
            .transpose()?;
        let source = PoetrySource::parse(table, policy, path, context)?;
        if version.is_some() && source.is_direct_origin() {
            return Err(invalid(
                path,
                format!("{context} cannot combine version with a git, path, or URL source"),
            ));
        }
        Ok(Self { version, source })
    }

    pub(super) fn enrichable(&self, policy: &PoetrySourcePolicy) -> bool {
        self.source.enrichable(policy)
    }

    pub(super) fn into_package(
        self,
        display_name: &str,
        dev: bool,
        policy: &PoetrySourcePolicy,
        path: &Path,
        context: &str,
    ) -> Result<Package, ParseError> {
        let version_display = self
            .version
            .as_ref()
            .map(|version| version.raw.clone())
            .or_else(|| self.source.display())
            .ok_or_else(|| {
                invalid(
                    path,
                    format!("{context} must define a version or direct git, path, or URL source"),
                )
            })?;
        let mut package = Package::new(
            Ecosystem::PyPI,
            display_name,
            version_display,
            path.to_path_buf(),
        );
        package.direct = true;
        package.dev = dev;
        package.enrichable = self.source.enrichable(policy);
        if let Some(version) = self.version {
            package.set_normalized_manifest_constraint(version.raw, version.normalized);
        }
        Ok(package)
    }
}

fn validate_dependency_fields(table: &Table, path: &Path, context: &str) -> Result<(), ParseError> {
    for key in table.keys() {
        if !matches!(
            key.as_str(),
            "version"
                | "extras"
                | "optional"
                | "python"
                | "markers"
                | "platform"
                | "allow-prereleases"
                | "source"
                | "git"
                | "branch"
                | "rev"
                | "tag"
                | "subdirectory"
                | "path"
                | "develop"
                | "url"
        ) {
            return Err(invalid(
                path,
                format!("{context} contains unsupported field {key:?}"),
            ));
        }
    }
    if let Some(extras) = table.get("extras") {
        validate_string_array(extras, path, &format!("{context}.extras"))?;
    }
    if let Some(value) = table.get("optional")
        && value.as_bool().is_none()
    {
        return Err(invalid(
            path,
            format!("{context}.optional must be a boolean"),
        ));
    }
    if let Some(value) = table.get("allow-prereleases") {
        if value.as_bool().is_none() {
            return Err(invalid(
                path,
                format!("{context}.allow-prereleases must be a boolean"),
            ));
        }
        return Err(invalid(
            path,
            format!(
                "{context}.allow-prereleases is unsupported because its candidate-selection policy cannot be represented safely"
            ),
        ));
    }
    if let Some(value) = table.get("python") {
        let raw = nonempty_string(value, path, context, "python")?;
        PoetryConstraint::parse(raw, path, &format!("{context}.python condition"))?;
        tracing::warn!(
            source_file = %path.display(),
            dependency = context,
            "Poetry Python-version condition is assumed true"
        );
    }
    if let Some(value) = table.get("markers") {
        let raw = nonempty_string(value, path, context, "markers")?;
        raw.parse::<pep508_rs::MarkerTree>().map_err(|error| {
            invalid(
                path,
                format!("{context}.markers is not a valid PEP 508 marker: {error}"),
            )
        })?;
        tracing::warn!(
            source_file = %path.display(),
            dependency = context,
            "Poetry environment marker is assumed true"
        );
    }
    if let Some(value) = table.get("platform") {
        nonempty_string(value, path, context, "platform")?;
        tracing::warn!(
            source_file = %path.display(),
            dependency = context,
            "Poetry platform condition is assumed true"
        );
    }
    if let Some(value) = table.get("develop")
        && value.as_bool().is_none()
    {
        return Err(invalid(
            path,
            format!("{context}.develop must be a boolean"),
        ));
    }
    Ok(())
}

fn nonempty_string<'a>(
    value: &'a Toml,
    path: &Path,
    context: &str,
    field: &str,
) -> Result<&'a str, ParseError> {
    value
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            invalid(
                path,
                format!("{context}.{field} must be a non-empty string"),
            )
        })
}
