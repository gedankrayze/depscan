use crate::{Ecosystem, normalize_name};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

/// Merges duplicate package coordinates (same ecosystem, name, and version) into one entry per
/// key, combining their metadata. The single owner of the dedup algorithm used by both the
/// parsers and the CLI consolidation pass.
pub fn dedup_packages(packages: Vec<Package>) -> Vec<Package> {
    let mut merged = BTreeMap::<String, Package>::new();
    for package in packages {
        merged
            .entry(package.key())
            .and_modify(|existing| existing.merge_metadata(&package))
            .or_insert(package);
    }
    merged.into_values().collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestConstraint {
    /// Exact source spelling, retained for diagnostics and reports.
    pub raw: String,
    /// Registry-standard constraint consumed by the ecosystem evaluator.
    pub normalized: String,
}

impl ManifestConstraint {
    pub fn new(raw: impl Into<String>) -> Self {
        let raw = raw.into();
        Self {
            normalized: raw.clone(),
            raw,
        }
    }

    pub fn with_normalized(raw: impl Into<String>, normalized: impl Into<String>) -> Self {
        Self {
            raw: raw.into(),
            normalized: normalized.into(),
        }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn normalized(&self) -> &str {
        &self.normalized
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    pub ecosystem: Ecosystem,
    /// Normalized package identity, also suitable for registry lookups.
    pub name: String,
    /// Source-preserved spelling used for display and case-sensitive provider lookups.
    pub display_name: String,
    /// A resolved version, or a range in manifest-only mode.
    pub version: String,
    pub direct: bool,
    /// Whether `direct` is an observed classification rather than a conservative default.
    #[serde(default = "classification_known")]
    pub direct_known: bool,
    pub dev: bool,
    /// Whether `dev` is an observed classification rather than a conservative default.
    #[serde(default = "classification_known")]
    pub dev_known: bool,
    pub source_file: PathBuf,
    pub enrichable: bool,
    pub resolved_from_range: bool,
    /// Manifest-only constraint provenance. `normalized` may differ from `raw` when a manifest
    /// uses an ecosystem-specific shorthand such as Poetry's caret requirements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_constraint: Option<ManifestConstraint>,
}

impl Package {
    pub fn new(
        ecosystem: Ecosystem,
        name: impl Into<String>,
        version: impl Into<String>,
        source_file: PathBuf,
    ) -> Self {
        let display_name = name.into();
        let name = normalize_name(ecosystem, &display_name);
        Self {
            ecosystem,
            name,
            display_name,
            version: version.into(),
            direct: false,
            direct_known: true,
            dev: false,
            dev_known: true,
            source_file,
            enrichable: true,
            resolved_from_range: false,
            manifest_constraint: None,
        }
    }

    pub fn set_manifest_constraint(&mut self, raw: impl Into<String>) {
        self.manifest_constraint = Some(ManifestConstraint::new(raw));
        self.resolved_from_range = true;
    }

    pub fn set_normalized_manifest_constraint(
        &mut self,
        raw: impl Into<String>,
        normalized: impl Into<String>,
    ) {
        self.manifest_constraint = Some(ManifestConstraint::with_normalized(raw, normalized));
        self.resolved_from_range = true;
    }
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.ecosystem.osv_name(),
            self.name,
            self.version
        )
    }

    /// Merge parser metadata for the same package coordinate without turning unknown
    /// classifications into false certainty. Provider eligibility is existential:
    /// one proven public-registry occurrence is sufficient to query that coordinate.
    pub fn merge_metadata(&mut self, other: &Self) {
        merge_directness(
            &mut self.direct,
            &mut self.direct_known,
            other.direct,
            other.direct_known,
        );
        merge_development_scope(
            &mut self.dev,
            &mut self.dev_known,
            other.dev,
            other.dev_known,
        );
        self.enrichable |= other.enrichable;
        self.resolved_from_range &= other.resolved_from_range;
    }
}

const fn classification_known() -> bool {
    true
}

fn merge_directness(value: &mut bool, known: &mut bool, other_value: bool, other_known: bool) {
    if (*known && *value) || (other_known && other_value) {
        *value = true;
        *known = true;
    } else if *known && other_known {
        *value = false;
    } else {
        *value = false;
        *known = false;
    }
}

fn merge_development_scope(
    value: &mut bool,
    known: &mut bool,
    other_value: bool,
    other_known: bool,
) {
    if (*known && !*value) || (other_known && !other_value) {
        *value = false;
        *known = true;
    } else if *known && other_known {
        *value = true;
    } else {
        *value = false;
        *known = false;
    }
}
