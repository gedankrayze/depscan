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
#[path = "constraint/tests.rs"]
mod tests;
