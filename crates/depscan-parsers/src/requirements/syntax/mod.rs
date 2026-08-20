use pep440_rs::Operator;
use pep508_rs::{Requirement, VerbatimUrl, VersionOrUrl};
use std::{borrow::Cow, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IncludeKind {
    Requirement,
    Constraint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GlobalOption {
    Ignored,
    AmbiguousRegistry,
    AmbiguousRangeResolution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PackageSpec {
    pub display_name: String,
    pub version: String,
    pub enrichable: bool,
    pub resolved_from_range: bool,
    pub has_marker: bool,
    pub constraint_compatible: bool,
    pub registry_constraint: Option<ConstraintSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ConstraintSpec {
    pub raw: String,
    pub normalized: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ParsedLine {
    Empty,
    Include { kind: IncludeKind, target: String },
    Global(GlobalOption),
    Package(PackageSpec),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LogicalLine {
    pub number: usize,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SyntaxError(String);

impl SyntaxError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    pub(super) fn message(&self) -> &str {
        &self.0
    }
}

pub(super) fn logical_lines(text: &str) -> Result<Vec<LogicalLine>, SyntaxError> {
    let mut output = Vec::new();
    let mut buffer = String::new();
    let mut start_line = 1;
    let mut continuing = false;

    for (index, physical) in text.split_terminator('\n').enumerate() {
        let number = index + 1;
        let physical = physical.strip_suffix('\r').unwrap_or(physical);
        if !continuing {
            start_line = number;
        }

        if has_unescaped_continuation(physical) {
            buffer.push_str(&physical[..physical.len() - 1]);
            continuing = true;
        } else {
            buffer.push_str(physical);
            output.push(LogicalLine {
                number: start_line,
                text: std::mem::take(&mut buffer),
            });
            continuing = false;
        }
    }

    if continuing {
        return Err(SyntaxError::new(format!(
            "line {start_line} ends with an unterminated continuation"
        )));
    }
    Ok(output)
}

fn has_unescaped_continuation(line: &str) -> bool {
    line.as_bytes()
        .iter()
        .rev()
        .take_while(|byte| **byte == b'\\')
        .count()
        % 2
        == 1
}

pub(super) fn parse_line(line: &str, base: &Path) -> Result<ParsedLine, SyntaxError> {
    let line = strip_comment(line).trim();
    if line.is_empty() {
        return Ok(ParsedLine::Empty);
    }

    if let Some(value) = option_value(line, Some("-r"), "--requirement") {
        return Ok(ParsedLine::Include {
            kind: IncludeKind::Requirement,
            target: single_value(value, "requirements include")?,
        });
    }
    if let Some(value) = option_value(line, Some("-c"), "--constraint") {
        return Ok(ParsedLine::Include {
            kind: IncludeKind::Constraint,
            target: single_value(value, "constraints include")?,
        });
    }
    if let Some(value) = option_value(line, Some("-e"), "--editable") {
        let target = whole_value(value, "editable requirement")?;
        return parse_direct(&target, base, true).map(ParsedLine::Package);
    }

    for (short, long, effect) in [
        (Some("-i"), "--index-url", GlobalOption::AmbiguousRegistry),
        (None, "--pypi-url", GlobalOption::AmbiguousRegistry),
        (None, "--extra-index-url", GlobalOption::AmbiguousRegistry),
        (Some("-f"), "--find-links", GlobalOption::AmbiguousRegistry),
        (None, "--no-binary", GlobalOption::AmbiguousRangeResolution),
        (
            None,
            "--only-binary",
            GlobalOption::AmbiguousRangeResolution,
        ),
        (None, "--trusted-host", GlobalOption::Ignored),
        (
            None,
            "--use-feature",
            GlobalOption::AmbiguousRangeResolution,
        ),
    ] {
        if let Some(value) = option_value(line, short, long) {
            single_value(value, long)?;
            return Ok(ParsedLine::Global(effect));
        }
    }

    for (flag, effect) in [
        ("--no-index", GlobalOption::AmbiguousRegistry),
        ("--prefer-binary", GlobalOption::AmbiguousRangeResolution),
        ("--require-hashes", GlobalOption::Ignored),
        ("--no-require-hashes", GlobalOption::Ignored),
        ("--pre", GlobalOption::AmbiguousRangeResolution),
        ("--all-releases", GlobalOption::AmbiguousRangeResolution),
        ("--only-final", GlobalOption::AmbiguousRangeResolution),
    ] {
        if line == flag {
            return Ok(ParsedLine::Global(effect));
        }
    }

    if line.starts_with('-') {
        let option = leading_option_name(line);
        return Err(SyntaxError::new(format!(
            "unsupported requirements option {option:?}; refusing to ignore an option that may change dependency resolution"
        )));
    }

    let requirement = strip_per_requirement_options(line)?;
    parse_requirement(requirement, base).map(ParsedLine::Package)
}

mod options;
mod requirement;

use options::*;
use requirement::*;

#[cfg(test)]
mod tests;
