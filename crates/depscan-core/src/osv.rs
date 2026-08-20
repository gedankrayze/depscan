use crate::{Ecosystem, NuGetVersion, Package, normalize_name};
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
    NuGet(NuGetVersion),
}

impl ParsedVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Semver(left), Self::Semver(right)) => left.cmp_precedence(right),
            (Self::Pep440(left), Self::Pep440(right)) => left.cmp(right),
            (Self::NuGet(left), Self::NuGet(right)) => left.cmp(right),
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
            Self::Ecosystem(Ecosystem::NuGet) => NuGetVersion::parse(version)
                .map(ParsedVersion::NuGet)
                .map_err(|error| invalid(error.reason().to_owned())),
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

#[cfg(test)]
#[path = "osv/tests.rs"]
mod tests;
