use depscan_core::ParseError;
use pep440_rs::{Version as Pep440Version, VersionSpecifiers};
use std::path::Path;

use crate::invalid;

#[derive(Debug)]
pub(super) struct PoetryConstraint {
    pub(super) raw: String,
    pub(super) normalized: String,
}

impl PoetryConstraint {
    pub(super) fn parse(raw: &str, path: &Path, context: &str) -> Result<Self, ParseError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(invalid(
                path,
                format!("{context} version constraint cannot be empty"),
            ));
        }
        let normalized = normalize_poetry_constraint(raw).map_err(|reason| {
            invalid(
                path,
                format!("{context} has unsupported Poetry constraint {raw:?}: {reason}"),
            )
        })?;
        Ok(Self {
            raw: raw.to_owned(),
            normalized,
        })
    }
}

fn normalize_poetry_constraint(raw: &str) -> Result<String, String> {
    if raw.contains('|') {
        return Err("union constraints are not representable by the current matcher".to_owned());
    }
    let clauses = raw
        .split(',')
        .map(str::trim)
        .map(normalize_poetry_clause)
        .collect::<Result<Vec<_>, _>>()?;
    if clauses.is_empty() || clauses.iter().any(String::is_empty) {
        return Err("constraint contains an empty clause".to_owned());
    }
    clauses
        .join(",")
        .parse::<VersionSpecifiers>()
        .map(|specifiers| specifiers.to_string())
        .map_err(|error| error.to_string())
}

fn normalize_poetry_clause(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("constraint contains an empty clause".to_owned());
    }
    if raw == "*" {
        return Ok(">=0".to_owned());
    }
    if let Some(version) = raw.strip_prefix('^') {
        return bounded_poetry_constraint(version, PoetryBound::Caret);
    }
    if let Some(version) = raw.strip_prefix('~')
        && !raw.starts_with("~=")
    {
        return bounded_poetry_constraint(version, PoetryBound::Tilde);
    }
    if let Some(release) = raw.strip_suffix(".*") {
        validate_release_prefix(release)?;
        return Ok(format!("=={release}.*"));
    }
    if raw.starts_with(['<', '>', '!', '=', '~']) {
        return raw
            .parse::<pep440_rs::VersionSpecifier>()
            .map(|specifier| specifier.to_string())
            .map_err(|error| error.to_string());
    }
    let version = raw
        .parse::<Pep440Version>()
        .map_err(|error| error.to_string())?;
    Ok(format!("=={version}"))
}

fn validate_release_prefix(raw: &str) -> Result<(), String> {
    if raw.is_empty()
        || raw.split('.').any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err("wildcards must follow one or more numeric release components".to_owned());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum PoetryBound {
    Caret,
    Tilde,
}

fn bounded_poetry_constraint(raw: &str, bound: PoetryBound) -> Result<String, String> {
    let raw = raw.trim();
    let lower = raw
        .parse::<Pep440Version>()
        .map_err(|error| error.to_string())?;
    if lower.epoch() != 0 || lower.is_local() {
        return Err(
            "caret and tilde constraints do not support epochs or local versions".to_owned(),
        );
    }
    let mut upper = lower.release().to_vec();
    if upper.is_empty() {
        return Err("constraint has no release components".to_owned());
    }
    let increment = match bound {
        PoetryBound::Caret => upper
            .iter()
            .position(|component| *component != 0)
            .unwrap_or(upper.len() - 1),
        PoetryBound::Tilde if upper.len() == 1 => 0,
        PoetryBound::Tilde => 1,
    };
    upper[increment] = upper[increment]
        .checked_add(1)
        .ok_or_else(|| "constraint upper bound overflows".to_owned())?;
    upper
        .iter_mut()
        .skip(increment + 1)
        .for_each(|part| *part = 0);
    while upper.len() < 3 {
        upper.push(0);
    }
    let upper = upper
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".");
    Ok(format!(">={lower},<{upper}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use depscan_core::{Ecosystem, latest_matching_version};

    #[test]
    fn poetry_constraints_select_the_documented_release_sets() {
        let cases = [
            ("^1.2.3", vec!["1.2.3", "1.9.9", "2.0.0"], "1.9.9"),
            ("^0.2.3", vec!["0.2.3", "0.2.9", "0.3.0"], "0.2.9"),
            ("^0.0.3", vec!["0.0.3", "0.0.4", "0.1.0"], "0.0.3"),
            ("^0.0", vec!["0.0.0", "0.0.9", "0.1.0"], "0.0.9"),
            ("^0", vec!["0.0.0", "0.9.9", "1.0.0"], "0.9.9"),
            ("~1.2.3", vec!["1.2.3", "1.2.9", "1.3.0"], "1.2.9"),
            ("~1.2", vec!["1.2.0", "1.2.9", "1.3.0"], "1.2.9"),
            ("~1", vec!["1.0.0", "1.9.9", "2.0.0"], "1.9.9"),
            ("1.*", vec!["1.0.0", "1.9.9", "2.0.0"], "1.9.9"),
            ("1.2.*", vec!["1.2.0", "1.2.9", "1.3.0"], "1.2.9"),
        ];
        for (raw, candidates, expected) in cases {
            let normalized = normalize_poetry_constraint(raw).unwrap();
            assert_eq!(
                latest_matching_version(Ecosystem::PyPI, &normalized, candidates).unwrap(),
                Some(expected.to_owned()),
                "unexpected release set for {raw:?} normalized as {normalized:?}"
            );
        }
    }

    #[test]
    fn poetry_constraint_upper_bounds_are_exclusive() {
        for (raw, excluded) in [
            ("^1.2.3", "2.0.0"),
            ("^0.0.3", "0.0.4"),
            ("~1.2", "1.3.0"),
            ("1.2.*", "1.3.0"),
        ] {
            let normalized = normalize_poetry_constraint(raw).unwrap();
            assert_eq!(
                latest_matching_version(Ecosystem::PyPI, &normalized, [excluded]).unwrap(),
                None,
                "{excluded} must be outside {raw:?} normalized as {normalized:?}"
            );
        }
    }

    #[test]
    fn rejects_unrepresentable_poetry_unions_and_malformed_wildcards() {
        for raw in ["^1 || ^2", "1.2*", "1..*"] {
            assert!(
                normalize_poetry_constraint(raw).is_err(),
                "accepted {raw:?}"
            );
        }
    }
}
