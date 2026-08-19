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

fn strip_comment(line: &str) -> &str {
    for (index, character) in line.char_indices() {
        if character == '#'
            && (index == 0
                || line[..index]
                    .chars()
                    .next_back()
                    .is_some_and(char::is_whitespace))
        {
            return &line[..index];
        }
    }
    line
}

fn option_value<'a>(line: &'a str, short: Option<&str>, long: &str) -> Option<&'a str> {
    if let Some(rest) = line.strip_prefix(long) {
        return match rest.as_bytes().first() {
            None => Some(""),
            Some(b'=') => Some(&rest[1..]),
            Some(byte) if byte.is_ascii_whitespace() => Some(rest.trim_start()),
            Some(_) => None,
        };
    }
    let short = short?;
    let rest = line.strip_prefix(short)?;
    match rest.as_bytes().first() {
        None => Some(""),
        Some(byte) if byte.is_ascii_whitespace() => Some(rest.trim_start()),
        Some(_) => Some(rest),
    }
}

fn single_value(value: &str, option: &str) -> Result<String, SyntaxError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(SyntaxError::new(format!("{option} requires a value")));
    }
    if let Some(quote) = value.chars().next().filter(|ch| matches!(ch, '\'' | '"')) {
        if value.len() < 2 || !value.ends_with(quote) {
            return Err(SyntaxError::new(format!(
                "{option} has an unterminated quoted value"
            )));
        }
        let inner = &value[quote.len_utf8()..value.len() - quote.len_utf8()];
        if inner.contains(quote) {
            return Err(SyntaxError::new(format!(
                "{option} contains unsupported nested quoting"
            )));
        }
        if inner.is_empty() {
            return Err(SyntaxError::new(format!("{option} requires a value")));
        }
        return Ok(inner.to_owned());
    }
    if value.chars().any(char::is_whitespace) {
        return Err(SyntaxError::new(format!(
            "{option} accepts exactly one value"
        )));
    }
    Ok(value.to_owned())
}

fn whole_value(value: &str, option: &str) -> Result<String, SyntaxError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(SyntaxError::new(format!("{option} requires a value")));
    }
    if value.starts_with(['\'', '"']) {
        single_value(value, option)
    } else {
        Ok(value.to_owned())
    }
}

fn leading_option_name(line: &str) -> &str {
    line.split_ascii_whitespace()
        .next()
        .unwrap_or(line)
        .split_once('=')
        .map_or_else(
            || line.split_ascii_whitespace().next().unwrap_or(line),
            |x| x.0,
        )
}

fn strip_per_requirement_options(line: &str) -> Result<&str, SyntaxError> {
    let Some(start) = find_option_start(line) else {
        return Ok(line.trim());
    };
    let requirement = line[..start].trim();
    if requirement.is_empty() {
        return Err(SyntaxError::new(
            "a per-requirement option is missing its requirement",
        ));
    }
    let mut options = line[start..].trim();
    while !options.is_empty() {
        if let Some(rest) = options.strip_prefix("--hash=") {
            let (value, remaining) = take_token(rest, "--hash")?;
            validate_hash(value)?;
            options = remaining.trim_start();
        } else if let Some(rest) = option_word(options, "--hash") {
            let (value, remaining) = take_token(rest.trim_start(), "--hash")?;
            validate_hash(value)?;
            options = remaining.trim_start();
        } else if let Some(rest) = options.strip_prefix("--config-settings=") {
            let (value, remaining) = take_token(rest, "--config-settings")?;
            validate_config_setting(value)?;
            options = remaining.trim_start();
        } else if let Some(rest) = option_word(options, "--config-settings") {
            let (value, remaining) = take_token(rest.trim_start(), "--config-settings")?;
            validate_config_setting(value)?;
            options = remaining.trim_start();
        } else if let Some(rest) = options.strip_prefix("-C") {
            let (value, remaining) = take_token(rest.trim_start(), "-C")?;
            validate_config_setting(value)?;
            options = remaining.trim_start();
        } else {
            let option = leading_option_name(options);
            return Err(SyntaxError::new(format!(
                "unsupported per-requirement option {option:?}"
            )));
        }
    }
    Ok(requirement)
}

fn find_option_start(line: &str) -> Option<usize> {
    let mut quote = None;
    for (index, character) in line.char_indices() {
        match (quote, character) {
            (Some(active), ch) if ch == active => quote = None,
            (None, '\'' | '"') => quote = Some(character),
            (None, ch) if ch.is_whitespace() => {
                let rest = line[index..].trim_start();
                if rest.starts_with("--") || rest.starts_with("-C") {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn option_word<'a>(input: &'a str, option: &str) -> Option<&'a str> {
    let rest = input.strip_prefix(option)?;
    rest.as_bytes()
        .first()
        .is_some_and(u8::is_ascii_whitespace)
        .then_some(rest)
}

fn take_token<'a>(input: &'a str, option: &str) -> Result<(&'a str, &'a str), SyntaxError> {
    if input.is_empty() {
        return Err(SyntaxError::new(format!("{option} requires a value")));
    }
    let end = input
        .char_indices()
        .find_map(|(index, character)| character.is_whitespace().then_some(index))
        .unwrap_or(input.len());
    let value = &input[..end];
    if value.is_empty() {
        return Err(SyntaxError::new(format!("{option} requires a value")));
    }
    Ok((value, &input[end..]))
}

fn validate_hash(value: &str) -> Result<(), SyntaxError> {
    let Some((algorithm, digest)) = value.split_once(':') else {
        return Err(SyntaxError::new(
            "--hash must use the ALGORITHM:DIGEST form",
        ));
    };
    if algorithm.is_empty()
        || !algorithm
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || digest.is_empty()
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(SyntaxError::new(
            "--hash must contain a valid algorithm and hexadecimal digest",
        ));
    }
    Ok(())
}

fn validate_config_setting(value: &str) -> Result<(), SyntaxError> {
    let Some((key, _)) = value.split_once('=') else {
        return Err(SyntaxError::new(
            "--config-settings must use the KEY=VALUE form",
        ));
    };
    if key.is_empty() {
        return Err(SyntaxError::new(
            "--config-settings must have a non-empty key",
        ));
    }
    Ok(())
}

fn parse_requirement(input: &str, base: &Path) -> Result<PackageSpec, SyntaxError> {
    match Requirement::<VerbatimUrl>::parse(input, base) {
        Ok(requirement) => package_from_requirement(input, requirement),
        Err(_) if looks_like_direct(input) => parse_direct(input, base, false),
        Err(_) => Err(SyntaxError::new(
            "invalid PEP 508 requirement; expected a package name with an optional version, extras, marker, or named direct URL",
        )),
    }
}

fn package_from_requirement(
    input: &str,
    requirement: Requirement<VerbatimUrl>,
) -> Result<PackageSpec, SyntaxError> {
    let display_name = source_distribution_name(input)
        .unwrap_or_else(|| requirement.name.as_ref())
        .to_owned();
    let has_marker = requirement.marker.contents().is_some();
    let has_extras = !requirement.extras.is_empty();

    match requirement.version_or_url {
        Some(VersionOrUrl::Url(url)) => Ok(PackageSpec {
            display_name,
            version: url.to_string(),
            enrichable: false,
            resolved_from_range: true,
            has_marker,
            constraint_compatible: false,
            registry_constraint: None,
        }),
        Some(VersionOrUrl::VersionSpecifier(specifiers)) => {
            let mut iter = specifiers.iter();
            let first = iter.next();
            let exact = first
                .filter(|specifier| *specifier.operator() == Operator::Equal)
                .filter(|_| iter.next().is_none());
            let normalized = specifiers.to_string();
            let raw = raw_registry_constraint(input).unwrap_or_else(|| normalized.clone());
            let (version, resolved_from_range) = if let Some(specifier) = exact {
                (
                    raw_exact_version(input).unwrap_or_else(|| specifier.version().to_string()),
                    false,
                )
            } else {
                (raw.clone(), true)
            };
            Ok(PackageSpec {
                display_name,
                version,
                enrichable: true,
                resolved_from_range,
                has_marker,
                constraint_compatible: !has_extras,
                registry_constraint: Some(ConstraintSpec { raw, normalized }),
            })
        }
        None => Ok(PackageSpec {
            display_name,
            version: "*".to_owned(),
            enrichable: true,
            resolved_from_range: true,
            has_marker,
            constraint_compatible: !has_extras,
            registry_constraint: Some(ConstraintSpec {
                raw: "*".to_owned(),
                normalized: ">=0".to_owned(),
            }),
        }),
    }
}

fn source_distribution_name(input: &str) -> Option<&str> {
    let end = input
        .char_indices()
        .take_while(|(_, character)| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
        })
        .map(|(index, character)| index + character.len_utf8())
        .last()?;
    Some(&input[..end])
}

fn raw_registry_constraint(input: &str) -> Option<String> {
    let before_marker = input.split_once(';').map_or(input, |parts| parts.0);
    let name_end = source_distribution_name(before_marker)?.len();
    let mut remainder = before_marker[name_end..].trim_start();
    if let Some(after_open) = remainder.strip_prefix('[') {
        let close = after_open.find(']')?;
        remainder = after_open[close + 1..].trim_start();
    }
    (!remainder.is_empty()).then(|| remainder.trim().to_owned())
}

fn raw_exact_version(input: &str) -> Option<String> {
    let before_marker = input.split_once(';').map_or(input, |parts| parts.0);
    let (_, version) = before_marker.split_once("==")?;
    let version = version.trim().trim_end_matches(')').trim();
    (!version.is_empty() && !version.contains(',') && !version.ends_with(".*"))
        .then(|| version.to_owned())
}

fn parse_direct(input: &str, base: &Path, editable: bool) -> Result<PackageSpec, SyntaxError> {
    if let Ok(requirement) = Requirement::<VerbatimUrl>::parse(input, base)
        && matches!(requirement.version_or_url, Some(VersionOrUrl::Url(_)))
    {
        return package_from_requirement(input, requirement);
    }

    let display_name = infer_direct_name(input, base).ok_or_else(|| {
        let kind = if editable { "editable" } else { "direct" };
        SyntaxError::new(format!(
            "unnamed {kind} requirement cannot be represented; use `name @ URL` or a VCS URL with `#egg=name`"
        ))
    })?;
    Ok(PackageSpec {
        display_name,
        version: input.to_owned(),
        enrichable: false,
        resolved_from_range: true,
        has_marker: false,
        constraint_compatible: false,
        registry_constraint: None,
    })
}

fn looks_like_direct(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    let bytes = input.as_bytes();
    let windows_drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    input.starts_with(['/', '.', '~', '\\'])
        || windows_drive
        || lower.starts_with("file:")
        || ["git+", "hg+", "svn+", "bzr+"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        || lower.contains("://")
        || [".whl", ".zip", ".tar.gz", ".tar.bz2", ".tar.xz"]
            .iter()
            .any(|suffix| {
                lower
                    .split(['#', '?'])
                    .next()
                    .map(strip_archive_extras)
                    .is_some_and(|x| x.ends_with(suffix))
            })
}

fn infer_direct_name(input: &str, base: &Path) -> Option<String> {
    if let Some(fragment) = input.split_once('#').map(|parts| parts.1) {
        for field in fragment.split('&') {
            if let Some(egg) = field.strip_prefix("egg=") {
                let name = egg.split_once('[').map_or(egg, |parts| parts.0);
                if valid_distribution_name(name) {
                    return Some(name.to_owned());
                }
            }
        }
    }

    let without_fragment = input.split_once('#').map_or(input, |parts| parts.0);
    let without_query = without_fragment
        .split_once('?')
        .map_or(without_fragment, |parts| parts.0);
    let raw_name = without_query
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()?;
    let raw_name = strip_archive_extras(raw_name);
    let raw_name = if matches!(raw_name, "." | ".." | "") {
        let resolved = base.join(raw_name);
        Cow::Owned(
            resolved
                .components()
                .next_back()?
                .as_os_str()
                .to_str()?
                .to_owned(),
        )
    } else {
        Cow::Borrowed(raw_name)
    };
    let raw_name = raw_name.trim_end_matches(".git");
    let lower = raw_name.to_ascii_lowercase();
    let artifact = [".tar.bz2", ".tar.gz", ".tar.xz", ".whl", ".zip"]
        .iter()
        .find_map(|suffix| {
            lower
                .ends_with(suffix)
                .then(|| &raw_name[..raw_name.len() - suffix.len()])
        });
    let candidate = if let Some(artifact) = artifact {
        if lower.ends_with(".whl") {
            artifact.split('-').next().unwrap_or(artifact)
        } else {
            artifact.rsplit_once('-').map_or(artifact, |parts| parts.0)
        }
    } else {
        raw_name
    };
    valid_distribution_name(candidate).then(|| candidate.to_owned())
}

fn strip_archive_extras(value: &str) -> &str {
    let Some(without_close) = value.strip_suffix(']') else {
        return value;
    };
    let Some(open) = without_close.rfind('[') else {
        return value;
    };
    let candidate = &without_close[..open];
    let candidate_lower = candidate.to_ascii_lowercase();
    if [".whl", ".zip", ".tar.gz", ".tar.bz2", ".tar.xz"]
        .iter()
        .any(|suffix| candidate_lower.ends_with(suffix))
    {
        candidate
    } else {
        value
    }
}

fn valid_distribution_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && name
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_continuations_before_removing_comments() {
        let input = ["alpha==1 \\", " --hash=sha256:aa # hash", "beta==2\\\\"].join("\n");
        let lines = logical_lines(&input).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].number, 1);
        assert_eq!(lines[0].text, "alpha==1  --hash=sha256:aa # hash");
        assert_eq!(lines[1].text, "beta==2\\\\");
    }

    #[test]
    fn parses_attached_and_separated_includes() {
        assert_eq!(
            parse_line("-rnested.txt", Path::new(".")),
            Ok(ParsedLine::Include {
                kind: IncludeKind::Requirement,
                target: "nested.txt".to_owned(),
            })
        );
        assert_eq!(
            parse_line("--requirement=nested.txt", Path::new(".")),
            Ok(ParsedLine::Include {
                kind: IncludeKind::Requirement,
                target: "nested.txt".to_owned(),
            })
        );
    }

    #[test]
    fn parses_exact_range_extras_and_direct_sources() {
        let exact = parse_line(
            "Requests[security,Socks]==2.32.5 ; python_version >= '3.9' --hash=sha256:aa",
            Path::new("."),
        )
        .unwrap();
        let ParsedLine::Package(exact) = exact else {
            panic!("expected package");
        };
        assert_eq!(exact.display_name, "Requests");
        assert_eq!(exact.version, "2.32.5");
        assert!(!exact.resolved_from_range);
        assert!(exact.has_marker);

        let range = parse_line("urllib3>=2,<3", Path::new(".")).unwrap();
        let ParsedLine::Package(range) = range else {
            panic!("expected package");
        };
        assert!(range.resolved_from_range);
        assert_eq!(range.version, ">=2,<3");
        assert_eq!(
            range.registry_constraint,
            Some(ConstraintSpec {
                raw: ">=2,<3".to_owned(),
                normalized: ">=2, <3".to_owned(),
            })
        );

        let direct = parse_line(
            "urllib3 @ https://example.invalid/urllib3.zip",
            Path::new("."),
        )
        .unwrap();
        let ParsedLine::Package(direct) = direct else {
            panic!("expected package");
        };
        assert!(!direct.enrichable);
        assert!(direct.resolved_from_range);

        let windows_path =
            parse_line(r"C:\src\Win_Pkg-1.0-py3-none-any.whl", Path::new(".")).unwrap();
        let ParsedLine::Package(windows_path) = windows_path else {
            panic!("expected package");
        };
        assert_eq!(windows_path.display_name, "Win_Pkg");
        assert!(!windows_path.enrichable);
    }

    #[test]
    fn rejects_unknown_options_and_malformed_hashes() {
        let unknown = parse_line("--proxy=https://secret.invalid", Path::new("."))
            .unwrap_err()
            .message()
            .to_owned();
        assert!(unknown.contains("--proxy"));
        assert!(!unknown.contains("secret.invalid"));

        let hash = parse_line("safe==1 --hash=sha256:not-hex", Path::new("."))
            .unwrap_err()
            .message()
            .to_owned();
        assert!(hash.contains("hexadecimal digest"));
    }
}
