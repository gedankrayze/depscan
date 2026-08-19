use crate::{Ecosystem, NuGetVersion};
use js_semver::{Range as NpmRange, Version as NpmVersion};
use pep440_rs::{Version as Pep440Version, VersionSpecifiers};
use semver::{Version, VersionReq};
use std::fmt::Display;
use thiserror::Error;

/// A manifest constraint cannot be evaluated without inventing ecosystem semantics.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid {ecosystem} manifest constraint {constraint:?}: {reason}")]
pub struct VersionConstraintError {
    ecosystem: &'static str,
    constraint: String,
    reason: String,
}

impl VersionConstraintError {
    fn new(ecosystem: Ecosystem, constraint: &str, reason: impl Display) -> Self {
        Self {
            ecosystem: ecosystem.display_name(),
            constraint: constraint.to_owned(),
            reason: reason.to_string(),
        }
    }
}

/// Return the newest published version satisfying an ecosystem-native manifest constraint.
///
/// Invalid registry version strings are ignored: they cannot displace a valid candidate. An
/// invalid or unsupported manifest constraint is instead returned as a typed error so callers can
/// surface a per-package soft failure rather than inventing a match.
pub fn latest_matching_version<'a>(
    ecosystem: Ecosystem,
    constraint: &str,
    versions: impl IntoIterator<Item = &'a str>,
) -> Result<Option<String>, VersionConstraintError> {
    let candidates = versions.into_iter().collect::<Vec<_>>();
    match ecosystem {
        Ecosystem::Npm => latest_npm(constraint, candidates),
        Ecosystem::CratesIo => latest_cargo(constraint, candidates),
        Ecosystem::PyPI => latest_pypi(constraint, candidates),
        Ecosystem::NuGet => latest_nuget(constraint, candidates),
    }
}

fn latest_npm(
    constraint: &str,
    versions: Vec<&str>,
) -> Result<Option<String>, VersionConstraintError> {
    let range = NpmRange::parse(constraint.trim())
        .map_err(|error| VersionConstraintError::new(Ecosystem::Npm, constraint, error))?;
    Ok(versions
        .into_iter()
        .filter_map(|raw| NpmVersion::parse(raw).ok().map(|version| (raw, version)))
        .filter(|(_, version)| range.satisfies(version))
        .max_by(|(left_raw, left), (right_raw, right)| {
            left.cmp(right).then_with(|| left_raw.cmp(right_raw))
        })
        .map(|(raw, _)| raw.to_owned()))
}

fn latest_cargo(
    constraint: &str,
    versions: Vec<&str>,
) -> Result<Option<String>, VersionConstraintError> {
    let requirement = constraint
        .trim()
        .parse::<VersionReq>()
        .map_err(|error| VersionConstraintError::new(Ecosystem::CratesIo, constraint, error))?;
    Ok(versions
        .into_iter()
        .filter_map(|raw| Version::parse(raw).ok().map(|version| (raw, version)))
        .filter(|(_, version)| requirement.matches(version))
        .max_by(|(left_raw, left), (right_raw, right)| {
            left.cmp(right).then_with(|| left_raw.cmp(right_raw))
        })
        .map(|(raw, _)| raw.to_owned()))
}

fn latest_pypi(
    constraint: &str,
    versions: Vec<&str>,
) -> Result<Option<String>, VersionConstraintError> {
    let specifiers = constraint
        .trim()
        .parse::<VersionSpecifiers>()
        .map_err(|error| VersionConstraintError::new(Ecosystem::PyPI, constraint, error))?;
    let explicitly_allows_prerelease = specifiers
        .iter()
        .any(|specifier| specifier.any_prerelease());
    let matching = versions
        .into_iter()
        .filter_map(|raw| {
            raw.parse::<Pep440Version>()
                .ok()
                .map(|version| (raw, version))
        })
        .filter(|(_, version)| specifiers.contains(version))
        .collect::<Vec<_>>();
    let eligible = matching
        .iter()
        .filter(|(_, version)| explicitly_allows_prerelease || version.is_stable());
    let best = eligible
        .max_by(|(left_raw, left), (right_raw, right)| {
            left.cmp(right).then_with(|| left_raw.cmp(right_raw))
        })
        .or_else(|| {
            (!explicitly_allows_prerelease).then(|| {
                matching
                    .iter()
                    .max_by(|(left_raw, left), (right_raw, right)| {
                        left.cmp(right).then_with(|| left_raw.cmp(right_raw))
                    })
            })?
        });
    Ok(best.map(|(raw, _)| (*raw).to_owned()))
}

#[derive(Debug)]
enum NuGetRequirement {
    Interval {
        lower: Option<(NuGetVersion, bool)>,
        upper: Option<(NuGetVersion, bool)>,
        include_prerelease: bool,
    },
    Floating(NuGetFloating),
}

#[derive(Debug)]
struct NuGetFloating {
    release_prefix: Vec<u32>,
    release_exact: bool,
    prerelease_prefix: Option<Vec<String>>,
}

impl NuGetRequirement {
    fn parse(constraint: &str) -> Result<Self, String> {
        let candidate = constraint.trim();
        if candidate.is_empty() {
            return Err("constraint is empty".to_owned());
        }
        if candidate.contains("$(") {
            return Err("unexpanded MSBuild properties are unsupported".to_owned());
        }
        if candidate.contains('*') {
            return Self::parse_floating(candidate).map(Self::Floating);
        }
        if candidate.starts_with(['[', '(']) {
            return Self::parse_interval(candidate);
        }
        let lower = NuGetVersion::parse(candidate).map_err(|error| error.to_string())?;
        let include_prerelease = lower.is_prerelease();
        Ok(Self::Interval {
            lower: Some((lower, true)),
            upper: None,
            include_prerelease,
        })
    }

    fn parse_interval(candidate: &str) -> Result<Self, String> {
        let lower_inclusive = candidate.starts_with('[');
        let upper_inclusive = candidate.ends_with(']');
        if !candidate.ends_with([']', ')']) || candidate.len() < 3 {
            return Err("NuGet interval must have paired [] or () delimiters".to_owned());
        }
        let inner = &candidate[1..candidate.len() - 1];
        if !inner.contains(',') {
            if !lower_inclusive || !upper_inclusive {
                return Err("a single-version NuGet interval must use [version]".to_owned());
            }
            let version = NuGetVersion::parse(inner.trim()).map_err(|error| error.to_string())?;
            let include_prerelease = version.is_prerelease();
            return Ok(Self::Interval {
                lower: Some((version.clone(), true)),
                upper: Some((version, true)),
                include_prerelease,
            });
        }
        let mut bounds = inner.split(',');
        let lower_raw = bounds.next().expect("split yields a first item").trim();
        let upper_raw = bounds
            .next()
            .expect("comma guarantees a second item")
            .trim();
        if bounds.next().is_some() {
            return Err("NuGet intervals contain exactly one comma".to_owned());
        }
        let lower = (!lower_raw.is_empty())
            .then(|| NuGetVersion::parse(lower_raw).map(|version| (version, lower_inclusive)))
            .transpose()
            .map_err(|error| error.to_string())?;
        let upper = (!upper_raw.is_empty())
            .then(|| NuGetVersion::parse(upper_raw).map(|version| (version, upper_inclusive)))
            .transpose()
            .map_err(|error| error.to_string())?;
        if lower.is_none() && upper.is_none() {
            return Err("NuGet interval must define at least one bound".to_owned());
        }
        if let (Some((lower, _)), Some((upper, _))) = (&lower, &upper)
            && lower > upper
        {
            return Err("NuGet interval lower bound exceeds its upper bound".to_owned());
        }
        let include_prerelease = lower
            .as_ref()
            .is_some_and(|(version, _)| version.is_prerelease())
            || upper
                .as_ref()
                .is_some_and(|(version, _)| version.is_prerelease());
        Ok(Self::Interval {
            lower,
            upper,
            include_prerelease,
        })
    }

    fn parse_floating(candidate: &str) -> Result<NuGetFloating, String> {
        let (release, prerelease) = candidate
            .split_once('-')
            .map_or((candidate, None), |(release, prerelease)| {
                (release, Some(prerelease))
            });
        let release_parts = release.split('.').collect::<Vec<_>>();
        if release_parts.is_empty() || release_parts.len() > 4 {
            return Err("NuGet floating release must contain one to four components".to_owned());
        }
        let wildcard = release_parts
            .iter()
            .position(|component| *component == "*")
            .unwrap_or(release_parts.len());
        if wildcard < release_parts.len()
            && release_parts[wildcard..]
                .iter()
                .any(|component| *component != "*")
        {
            return Err("NuGet release wildcards must occupy trailing components".to_owned());
        }
        let release_exact = wildcard == release_parts.len();
        let mut release_prefix = Vec::with_capacity(wildcard);
        for component in &release_parts[..wildcard] {
            let parsed = component
                .parse::<u32>()
                .map_err(|_| "NuGet floating release components must be integers".to_owned())?;
            if parsed > i32::MAX as u32 {
                return Err(
                    "NuGet floating release components exceed System.Version limits".to_owned(),
                );
            }
            release_prefix.push(parsed);
        }
        let prerelease_prefix = prerelease
            .map(|value| {
                if value.is_empty() {
                    return Err("NuGet floating prerelease cannot be empty".to_owned());
                }
                let components = value.split('.').collect::<Vec<_>>();
                let wildcard = components
                    .iter()
                    .position(|component| *component == "*")
                    .ok_or_else(|| "NuGet floating prerelease must end in a wildcard".to_owned())?;
                if components[wildcard..]
                    .iter()
                    .any(|component| *component != "*")
                {
                    return Err(
                        "NuGet prerelease wildcards must occupy trailing components".to_owned()
                    );
                }
                let prefix = components[..wildcard]
                    .iter()
                    .map(|component| {
                        component
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                            .then(|| component.to_ascii_lowercase())
                            .ok_or_else(|| {
                                "NuGet floating prerelease identifiers must be ASCII alphanumeric or hyphen strings".to_owned()
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if prefix.iter().any(|component| component.is_empty()) {
                    return Err("NuGet floating prerelease identifiers cannot be empty".to_owned());
                }
                Ok(prefix)
            })
            .transpose()?;
        Ok(NuGetFloating {
            release_prefix,
            release_exact,
            prerelease_prefix,
        })
    }

    fn matches(&self, version: &NuGetVersion) -> bool {
        match self {
            Self::Interval {
                lower,
                upper,
                include_prerelease,
            } => {
                if version.is_prerelease() && !include_prerelease {
                    return false;
                }
                let above_lower = lower.as_ref().is_none_or(|(bound, inclusive)| {
                    version > bound || (*inclusive && version == bound)
                });
                let below_upper = upper.as_ref().is_none_or(|(bound, inclusive)| {
                    version < bound || (*inclusive && version == bound)
                });
                above_lower && below_upper
            }
            Self::Floating(floating) => floating.matches(version),
        }
    }
}

impl NuGetFloating {
    fn matches(&self, version: &NuGetVersion) -> bool {
        if !version.release_segments().starts_with(&self.release_prefix)
            || (self.release_exact
                && version.release_segments()[self.release_prefix.len()..]
                    .iter()
                    .any(|component| *component != 0))
        {
            return false;
        }
        match &self.prerelease_prefix {
            None => !version.is_prerelease(),
            Some(prefix) if !version.is_prerelease() => true,
            Some(prefix) => {
                let normalized = version.to_normalized_string();
                let prerelease = normalized
                    .split_once('-')
                    .map(|(_, prerelease)| prerelease)
                    .unwrap_or_default();
                let actual = prerelease
                    .split('.')
                    .map(str::to_ascii_lowercase)
                    .collect::<Vec<_>>();
                actual.starts_with(prefix)
            }
        }
    }
}

fn latest_nuget(
    constraint: &str,
    versions: Vec<&str>,
) -> Result<Option<String>, VersionConstraintError> {
    let requirement = NuGetRequirement::parse(constraint)
        .map_err(|error| VersionConstraintError::new(Ecosystem::NuGet, constraint, error))?;
    Ok(versions
        .into_iter()
        .filter_map(|raw| NuGetVersion::parse(raw).ok().map(|version| (raw, version)))
        .filter(|(_, version)| requirement.matches(version))
        .max_by(|(left_raw, left), (right_raw, right)| {
            left.cmp(right).then_with(|| left_raw.cmp(right_raw))
        })
        .map(|(raw, _)| raw.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_latest_matching_versions_with_native_ecosystem_semantics() {
        let cases = [
            (
                Ecosystem::Npm,
                "^1.2.0",
                vec!["1.2.0", "1.9.9", "2.0.0-beta.1", "2.0.0"],
                Some("1.9.9"),
            ),
            (
                Ecosystem::Npm,
                "1.2.3 - 1.4.x || 3.x",
                vec!["1.4.9", "2.9.0", "3.2.0", "4.0.0"],
                Some("3.2.0"),
            ),
            (
                Ecosystem::CratesIo,
                "^0.2.3",
                vec!["0.2.3", "0.2.9", "0.3.0-alpha.1", "0.3.0"],
                Some("0.2.9"),
            ),
            (
                Ecosystem::PyPI,
                ">=1.0,<2.0,!=1.9",
                vec!["1.8", "1.9", "1.10rc1", "1.10", "2.0"],
                Some("1.10"),
            ),
            (
                Ecosystem::NuGet,
                "[1.0,2.0)",
                vec!["1.9.0", "1.9.0.5", "2.0.0-beta.1", "2.0.0"],
                Some("1.9.0.5"),
            ),
            (
                Ecosystem::NuGet,
                "1.2.*",
                vec!["1.2.8", "1.2.9-beta.1", "1.3.0", "2.0.0"],
                Some("1.2.8"),
            ),
            (
                Ecosystem::NuGet,
                "1.2",
                vec!["1.1.9", "1.2.0", "2.0.0-beta.1", "2.0.0"],
                Some("2.0.0"),
            ),
        ];

        for (ecosystem, constraint, versions, expected) in cases {
            assert_eq!(
                latest_matching_version(ecosystem, constraint, versions).unwrap(),
                expected.map(str::to_owned),
                "unexpected match for {ecosystem:?} {constraint:?}"
            );
        }
    }

    #[test]
    fn handles_prereleases_according_to_each_constraint_language() {
        assert_eq!(
            latest_matching_version(
                Ecosystem::Npm,
                ">=1.2.3-rc.1 <1.2.3",
                ["1.2.3-beta.1", "1.2.3-rc.2", "1.2.4-rc.1"]
            )
            .unwrap(),
            Some("1.2.3-rc.2".to_owned())
        );
        assert_eq!(
            latest_matching_version(
                Ecosystem::CratesIo,
                ">=1.2.3-alpha.1, <1.2.3",
                ["1.2.3-alpha.2", "1.2.3-beta.1", "1.2.4-alpha.1"]
            )
            .unwrap(),
            Some("1.2.3-beta.1".to_owned())
        );
        assert_eq!(
            latest_matching_version(Ecosystem::PyPI, ">=2.0,<3", ["2.1a1", "2.2rc1"]).unwrap(),
            Some("2.2rc1".to_owned()),
            "PEP 440 permits prereleases when no final/post release matches"
        );
        assert_eq!(
            latest_matching_version(
                Ecosystem::NuGet,
                "1.2.0-rc.*",
                ["1.2.0-rc.1", "1.2.0-rc.2", "1.2.0", "1.2.0.5", "1.2.1"]
            )
            .unwrap(),
            Some("1.2.0".to_owned())
        );
    }

    #[test]
    fn invalid_or_unsupported_constraints_fail_instead_of_matching_partially() {
        let cases = [
            (Ecosystem::Npm, "workspace:*"),
            (Ecosystem::Npm, ">=1.2.3 garbage"),
            (Ecosystem::CratesIo, "not a cargo requirement"),
            (Ecosystem::PyPI, "^1.2"),
            (Ecosystem::NuGet, "(1.0)"),
            (Ecosystem::NuGet, "$(CentralVersion)"),
        ];
        for (ecosystem, constraint) in cases {
            let error = latest_matching_version(ecosystem, constraint, ["1.2.3"])
                .expect_err("invalid constraint unexpectedly produced a match");
            assert!(error.to_string().contains(constraint));
        }
    }
}
