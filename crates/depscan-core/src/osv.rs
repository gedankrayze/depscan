use crate::{Ecosystem, Package, compare_versions, normalize_name};
use pep440_rs::Version as Pep440Version;
use semver::Version as SemverVersion;
use serde::Deserialize;
use serde_json::Value;
use std::cmp::Ordering;
use thiserror::Error;

/// The result of evaluating one package version against an OSV `affected` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsvAffectedEvaluation {
    pub affected: bool,
    /// The first closing `fixed` boundary for every matching range, in version order.
    pub fixed_versions: Vec<String>,
}

/// An OSV affected range could not be evaluated without risking a false-clean result.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OsvEvaluationError {
    #[error("malformed matching affected entry: {0}")]
    MalformedAffected(String),
    #[error("unsupported OSV range type {0:?} for a package-version query")]
    UnsupportedRangeType(String),
    #[error("invalid {ordering} version {version:?}: {reason}")]
    InvalidVersion {
        ordering: &'static str,
        version: String,
        reason: String,
    },
}

#[derive(Debug, Deserialize)]
struct AffectedEntry {
    package: AffectedPackage,
    #[serde(default)]
    ranges: Vec<AffectedRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AffectedPackage {
    ecosystem: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct AffectedRange {
    #[serde(rename = "type")]
    range_type: String,
    events: Vec<AffectedEvent>,
}

#[derive(Debug, Deserialize)]
struct AffectedEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
    limit: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EventKind {
    Introduced,
    LastAffected,
    Fixed,
    Limit,
}

#[derive(Debug)]
struct ParsedEvent {
    kind: EventKind,
    raw_version: String,
    version: EventVersion,
}

#[derive(Debug)]
enum EventVersion {
    BeforeAll,
    Finite(ParsedVersion),
    AfterAll,
}

impl EventVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::BeforeAll, Self::BeforeAll) | (Self::AfterAll, Self::AfterAll) => {
                Ordering::Equal
            }
            (Self::BeforeAll, _) | (_, Self::AfterAll) => Ordering::Less,
            (Self::AfterAll, _) | (_, Self::BeforeAll) => Ordering::Greater,
            (Self::Finite(left), Self::Finite(right)) => left.cmp(right),
        }
    }
}

#[derive(Debug)]
enum ParsedVersion {
    Semver(SemverVersion),
    Pep440(Pep440Version),
    NuGet(String),
}

impl ParsedVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Semver(left), Self::Semver(right)) => left.cmp_precedence(right),
            (Self::Pep440(left), Self::Pep440(right)) => left.cmp(right),
            (Self::NuGet(left), Self::NuGet(right)) => {
                compare_versions(Ecosystem::NuGet, left, right)
            }
            _ => unreachable!("a range is parsed with one version ordering"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum VersionOrdering {
    Semver,
    Ecosystem(Ecosystem),
}

impl VersionOrdering {
    fn label(self) -> &'static str {
        match self {
            Self::Semver => "SEMVER",
            Self::Ecosystem(Ecosystem::Npm) => "npm ECOSYSTEM",
            Self::Ecosystem(Ecosystem::PyPI) => "PyPI ECOSYSTEM",
            Self::Ecosystem(Ecosystem::NuGet) => "NuGet ECOSYSTEM",
            Self::Ecosystem(Ecosystem::CratesIo) => "crates.io ECOSYSTEM",
        }
    }

    fn parse(self, version: &str) -> Result<ParsedVersion, OsvEvaluationError> {
        let invalid = |reason: String| OsvEvaluationError::InvalidVersion {
            ordering: self.label(),
            version: version.to_owned(),
            reason,
        };

        match self {
            Self::Semver | Self::Ecosystem(Ecosystem::Npm | Ecosystem::CratesIo) => version
                .parse::<SemverVersion>()
                .map(ParsedVersion::Semver)
                .map_err(|error| invalid(error.to_string())),
            Self::Ecosystem(Ecosystem::PyPI) => version
                .parse::<Pep440Version>()
                .map(ParsedVersion::Pep440)
                .map_err(|error| invalid(error.to_string())),
            Self::Ecosystem(Ecosystem::NuGet) => {
                validate_nuget_version(version).map_err(invalid)?;
                Ok(ParsedVersion::NuGet(version.to_owned()))
            }
        }
    }
}

/// Evaluate an installed package against an OSV advisory's `affected` entries.
///
/// Identity is checked before an entry is parsed, so an unrelated malformed entry cannot poison a
/// package result. A matching malformed or unsupported range is returned as an error rather than
/// being interpreted as an unaffected package.
pub fn evaluate_osv_affected(
    package: &Package,
    affected: &[Value],
) -> Result<OsvAffectedEvaluation, OsvEvaluationError> {
    let mut is_affected = false;
    let mut fixed_versions = Vec::new();

    for raw_entry in affected
        .iter()
        .filter(|entry| affected_identity_matches(entry, package))
    {
        let entry: AffectedEntry = serde_json::from_value(raw_entry.clone())
            .map_err(|error| OsvEvaluationError::MalformedAffected(error.to_string()))?;

        // Confirm that deserialization did not change the identity assumptions used above.
        if entry.package.ecosystem != package.ecosystem.osv_name()
            || (entry.package.name != "*"
                && normalize_name(package.ecosystem, &entry.package.name) != package.name)
        {
            continue;
        }

        if explicit_versions_match(package, &entry.versions) {
            is_affected = true;
        }

        for range in &entry.ranges {
            let evaluation = evaluate_range(package, range)?;
            if evaluation.affected {
                is_affected = true;
                if let Some(fixed) = evaluation.fixed_version {
                    fixed_versions.push(fixed);
                }
            }
        }
    }

    let ordering = VersionOrdering::Ecosystem(package.ecosystem);
    let mut parsed_fixes = fixed_versions
        .into_iter()
        .map(|version| ordering.parse(&version).map(|parsed| (version, parsed)))
        .collect::<Result<Vec<_>, _>>()?;
    parsed_fixes.sort_by(|left, right| left.1.cmp(&right.1));
    parsed_fixes.dedup_by(|left, right| left.1.cmp(&right.1) == Ordering::Equal);
    let fixed_versions = parsed_fixes
        .into_iter()
        .map(|(version, _)| version)
        .collect();

    Ok(OsvAffectedEvaluation {
        affected: is_affected,
        fixed_versions,
    })
}

fn affected_identity_matches(entry: &Value, package: &Package) -> bool {
    let Some(affected_package) = entry.get("package") else {
        return false;
    };
    let Some(ecosystem) = affected_package.get("ecosystem").and_then(Value::as_str) else {
        return false;
    };
    let Some(name) = affected_package.get("name").and_then(Value::as_str) else {
        return false;
    };

    ecosystem == package.ecosystem.osv_name()
        && (name == "*" || normalize_name(package.ecosystem, name) == package.name)
}

fn explicit_versions_match(package: &Package, versions: &[String]) -> bool {
    versions.iter().any(|version| version == &package.version)
}

#[derive(Debug)]
struct RangeEvaluation {
    affected: bool,
    fixed_version: Option<String>,
}

fn evaluate_range(
    package: &Package,
    range: &AffectedRange,
) -> Result<RangeEvaluation, OsvEvaluationError> {
    let ordering = match range.range_type.as_str() {
        "SEMVER" => VersionOrdering::Semver,
        "ECOSYSTEM" => VersionOrdering::Ecosystem(package.ecosystem),
        unsupported => {
            return Err(OsvEvaluationError::UnsupportedRangeType(
                unsupported.to_owned(),
            ));
        }
    };

    if range.events.is_empty() {
        return Err(OsvEvaluationError::MalformedAffected(format!(
            "{} range has no events",
            range.range_type
        )));
    }

    let installed = EventVersion::Finite(ordering.parse(&package.version)?);
    let mut timeline = Vec::new();
    let mut limits = Vec::new();
    let mut has_introduced = false;
    let mut has_fixed = false;
    let mut has_last_affected = false;

    for event in &range.events {
        let (kind, raw_version) = parse_event(event)?;
        has_introduced |= kind == EventKind::Introduced;
        has_fixed |= kind == EventKind::Fixed;
        has_last_affected |= kind == EventKind::LastAffected;

        let version = match (kind, raw_version.as_str()) {
            (EventKind::Introduced, "0") => EventVersion::BeforeAll,
            (EventKind::Limit, value) if value.contains('*') => EventVersion::AfterAll,
            _ => EventVersion::Finite(ordering.parse(&raw_version)?),
        };
        let parsed = ParsedEvent {
            kind,
            raw_version,
            version,
        };
        if kind == EventKind::Limit {
            limits.push(parsed);
        } else {
            timeline.push(parsed);
        }
    }

    if !has_introduced {
        return Err(OsvEvaluationError::MalformedAffected(format!(
            "{} range has no introduced event",
            range.range_type
        )));
    }
    if has_fixed && has_last_affected {
        return Err(OsvEvaluationError::MalformedAffected(format!(
            "{} range mixes fixed and last_affected events",
            range.range_type
        )));
    }

    let before_a_limit = limits.is_empty()
        || limits
            .iter()
            .any(|limit| installed.cmp(&limit.version) == Ordering::Less);
    if !before_a_limit {
        return Ok(RangeEvaluation {
            affected: false,
            fixed_version: None,
        });
    }

    // OSV orders equal-version events as introduced, last_affected, fixed, then limit.
    timeline.sort_by(|left, right| {
        left.version
            .cmp(&right.version)
            .then_with(|| left.kind.cmp(&right.kind))
    });

    let mut active = false;
    let mut fixed_version = None;
    for event in timeline {
        let installed_cmp = installed.cmp(&event.version);
        match event.kind {
            EventKind::Introduced if installed_cmp != Ordering::Less => {
                active = true;
                fixed_version = None;
            }
            EventKind::Fixed if installed_cmp != Ordering::Less => {
                active = false;
                fixed_version = None;
            }
            EventKind::Fixed if active && fixed_version.is_none() => {
                fixed_version = Some(event.raw_version);
            }
            EventKind::LastAffected if installed_cmp == Ordering::Greater => {
                active = false;
            }
            EventKind::Introduced | EventKind::Fixed | EventKind::LastAffected => {}
            EventKind::Limit => unreachable!("limit events are evaluated separately"),
        }
    }

    Ok(RangeEvaluation {
        affected: active,
        fixed_version: active.then_some(fixed_version).flatten(),
    })
}

fn parse_event(event: &AffectedEvent) -> Result<(EventKind, String), OsvEvaluationError> {
    let values = [
        (EventKind::Introduced, event.introduced.as_ref()),
        (EventKind::LastAffected, event.last_affected.as_ref()),
        (EventKind::Fixed, event.fixed.as_ref()),
        (EventKind::Limit, event.limit.as_ref()),
    ];
    let present = values
        .into_iter()
        .filter_map(|(kind, value)| value.map(|value| (kind, value)))
        .collect::<Vec<_>>();
    if present.len() != 1 {
        return Err(OsvEvaluationError::MalformedAffected(
            "each range event must contain exactly one of introduced, fixed, last_affected, or limit"
                .to_owned(),
        ));
    }
    let (kind, version) = present[0];
    if version.is_empty() {
        return Err(OsvEvaluationError::MalformedAffected(format!(
            "{} event has an empty version",
            match kind {
                EventKind::Introduced => "introduced",
                EventKind::LastAffected => "last_affected",
                EventKind::Fixed => "fixed",
                EventKind::Limit => "limit",
            }
        )));
    }
    Ok((kind, version.to_owned()))
}

fn validate_nuget_version(version: &str) -> Result<(), String> {
    if version.is_empty() {
        return Err("version is empty".to_owned());
    }
    let (core, build) = version.split_once('+').unwrap_or((version, ""));
    if build.contains('+') {
        return Err("version contains more than one build metadata separator".to_owned());
    }
    if version.contains('+') {
        validate_nuget_identifiers(build, "build metadata")?;
    }

    let (release, prerelease) = core.split_once('-').unwrap_or((core, ""));
    if core.contains('-') {
        validate_nuget_identifiers(prerelease, "prerelease")?;
    }

    let release = release.split('.').collect::<Vec<_>>();
    if release.is_empty() || release.len() > 4 {
        return Err("release must contain between one and four numeric components".to_owned());
    }
    if release.iter().any(|component| {
        component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        return Err("release components must be non-empty decimal integers".to_owned());
    }
    Ok(())
}

fn validate_nuget_identifiers(value: &str, label: &str) -> Result<(), String> {
    if value.split('.').any(|identifier| {
        identifier.is_empty()
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(format!(
            "{label} identifiers must be non-empty ASCII alphanumeric or hyphen strings"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;

    fn package(ecosystem: Ecosystem, name: &str, version: &str) -> Package {
        Package::new(ecosystem, name, version, PathBuf::from("fixture.lock"))
    }

    fn evaluate(package: &Package, entries: Value) -> OsvAffectedEvaluation {
        evaluate_osv_affected(package, entries.as_array().unwrap()).unwrap()
    }

    #[test]
    fn evaluates_schema_range_examples_and_boundaries() {
        let npm = package(Ecosystem::Npm, "schema-example", "1.0.1");
        let fixed = json!([{
            "package": {"ecosystem": "npm", "name": "schema-example"},
            "ranges": [{
                "type": "SEMVER",
                "events": [{"introduced": "0"}, {"fixed": "1.0.2"}]
            }]
        }]);
        assert_eq!(
            evaluate(&npm, fixed.clone()),
            OsvAffectedEvaluation {
                affected: true,
                fixed_versions: vec!["1.0.2".to_owned()]
            }
        );

        let at_fix = package(Ecosystem::Npm, "schema-example", "1.0.2");
        assert!(!evaluate(&at_fix, fixed).affected);

        let last_affected = json!([{
            "package": {"ecosystem": "npm", "name": "schema-example"},
            "ranges": [{
                "type": "SEMVER",
                "events": [{"last_affected": "2.1.214"}, {"introduced": "0"}]
            }]
        }]);
        let ceiling = package(Ecosystem::Npm, "schema-example", "2.1.214");
        assert!(evaluate(&ceiling, last_affected.clone()).affected);
        let above = package(Ecosystem::Npm, "schema-example", "2.1.215");
        assert!(!evaluate(&above, last_affected).affected);

        let build_metadata = json!([{
            "package": {"ecosystem": "npm", "name": "schema-example"},
            "ranges": [{
                "type": "SEMVER",
                "events": [
                    {"introduced": "1.0.0+advisory-build"},
                    {"fixed": "1.0.1"}
                ]
            }]
        }]);
        let equivalent_build = package(Ecosystem::Npm, "schema-example", "1.0.0+installed-build");
        assert!(evaluate(&equivalent_build, build_metadata).affected);
    }

    #[test]
    fn unsorted_django_style_intervals_keep_the_matching_interval_active() {
        let django = package(Ecosystem::PyPI, "Django", "4.2.17");
        let entries = json!([{
            "package": {"ecosystem": "PyPI", "name": "django"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [
                    {"fixed": "5.1.4"},
                    {"introduced": "5.1"},
                    {"fixed": "4.2.18"},
                    {"introduced": "4.2"},
                    {"fixed": "5.0.10"},
                    {"introduced": "5.0"}
                ]
            }]
        }]);

        assert_eq!(
            evaluate(&django, entries),
            OsvAffectedEvaluation {
                affected: true,
                fixed_versions: vec!["4.2.18".to_owned()]
            }
        );
    }

    #[test]
    fn limit_is_exclusive_and_wildcard_is_infinite() {
        let range = |limit: &str| {
            json!([{
                "package": {"ecosystem": "NuGet", "name": "Example.Package"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"limit": limit}]
                }]
            }])
        };
        let before = package(Ecosystem::NuGet, "example.package", "1.9.9.9");
        assert!(evaluate(&before, range("2.0.0.0")).affected);
        let at = package(Ecosystem::NuGet, "example.package", "2.0.0.0");
        assert!(!evaluate(&at, range("2.0.0.0")).affected);
        let future = package(Ecosystem::NuGet, "example.package", "999.0.0");
        assert!(evaluate(&future, range("2.*")).affected);
    }

    #[test]
    fn explicit_versions_and_identity_are_restricted_to_the_package() {
        let serde_package = package(Ecosystem::CratesIo, "serde", "1.0.200");
        let entries = json!([
            {
                "package": {"ecosystem": "crates.io", "name": "serde"},
                "versions": ["1.0.199", "1.0.200"]
            },
            {
                "package": {"ecosystem": "npm", "name": "serde"},
                "versions": ["1.0.200"]
            },
            {
                "package": {"ecosystem": "crates.io", "name": "not-serde"},
                "versions": ["1.0.200"]
            }
        ]);
        assert!(evaluate(&serde_package, entries).affected);

        let other = package(Ecosystem::CratesIo, "serde_json", "1.0.200");
        assert!(!evaluate(&other, json!([])).affected);

        let pypi = package(Ecosystem::PyPI, "exact-versions", "1.0.0");
        let semantically_equal = json!([{
            "package": {"ecosystem": "PyPI", "name": "exact-versions"},
            "versions": ["1.0"]
        }]);
        assert!(!evaluate(&pypi, semantically_equal).affected);
    }

    #[test]
    fn wildcard_name_matches_every_package_only_in_its_ecosystem() {
        let npm = package(Ecosystem::Npm, "any-npm-package", "1.5.0");
        let wildcard = json!([{
            "package": {"ecosystem": "npm", "name": "*"},
            "ranges": [{
                "type": "SEMVER",
                "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]
            }]
        }]);
        assert!(evaluate(&npm, wildcard.clone()).affected);

        let pypi = package(Ecosystem::PyPI, "any-python-package", "1.5.0");
        assert!(!evaluate(&pypi, wildcard).affected);
    }

    #[test]
    fn uses_every_supported_ecosystem_comparator() {
        let cases = [
            (Ecosystem::Npm, "npm-package", "1.2.3-beta.2", "1.2.3"),
            (Ecosystem::CratesIo, "crate", "1.0.0-rc.1", "1.0.0"),
            (Ecosystem::PyPI, "python-package", "1.0rc1", "1.0"),
            (Ecosystem::NuGet, "NuGet.Package", "1.0.0.4", "1.0.0.5"),
        ];

        for (ecosystem, name, installed, fixed) in cases {
            let package = package(ecosystem, name, installed);
            let entries = json!([{
                "package": {"ecosystem": ecosystem.osv_name(), "name": name},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": fixed}]
                }]
            }]);
            let evaluation = evaluate(&package, entries);
            assert!(evaluation.affected, "{ecosystem:?} did not match");
            assert_eq!(evaluation.fixed_versions, [fixed]);
        }
    }

    #[test]
    fn reports_unsupported_and_malformed_matching_ranges() {
        let package = package(Ecosystem::Npm, "example", "1.0.0");
        let range = |range_type: &str, events: Value| {
            json!([{
                "package": {"ecosystem": "npm", "name": "example"},
                "ranges": [{"type": range_type, "events": events}]
            }])
        };

        for range_type in ["GIT", "FUTURE"] {
            let entries = range(range_type, json!([{"introduced": "0"}]));
            assert!(matches!(
                evaluate_osv_affected(&package, entries.as_array().unwrap()),
                Err(OsvEvaluationError::UnsupportedRangeType(kind)) if kind == range_type
            ));
        }

        let malformed = [
            range("SEMVER", json!([])),
            range("SEMVER", json!([{"fixed": "2.0.0"}])),
            range(
                "SEMVER",
                json!([{"introduced": "0"}, {"fixed": "2.0.0", "limit": "3.0.0"}]),
            ),
            range(
                "SEMVER",
                json!([{"introduced": "0"}, {"fixed": "not-semver"}]),
            ),
            range(
                "SEMVER",
                json!([{"introduced": "0"}, {"fixed": "2.0.0"}, {"last_affected": "1.9.9"}]),
            ),
        ];
        for entries in malformed {
            assert!(evaluate_osv_affected(&package, entries.as_array().unwrap()).is_err());
        }
    }

    #[test]
    fn unrelated_malformed_entries_do_not_poison_a_package() {
        let package = package(Ecosystem::Npm, "example", "1.0.0");
        let entries = json!([
            {
                "package": {"ecosystem": "PyPI", "name": "broken"},
                "ranges": "not-an-array"
            },
            {
                "package": {"ecosystem": "npm", "name": "example"},
                "versions": ["1.0.0"]
            }
        ]);
        assert!(evaluate(&package, entries).affected);
    }
}
