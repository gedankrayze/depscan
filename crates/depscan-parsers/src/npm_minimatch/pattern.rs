use super::*;

pub(super) fn normalize_repeated_slashes(pattern: &str) -> String {
    let mut normalized = String::with_capacity(pattern.len());
    let mut previous_was_slash = false;
    for character in pattern.chars() {
        if character == '/' {
            if previous_was_slash {
                continue;
            }
            previous_was_slash = true;
        } else {
            previous_was_slash = false;
        }
        normalized.push(character);
    }
    normalized
}

pub(super) fn validate_pattern_text(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("npm workspace pattern must not be empty".to_owned());
    }
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(format!(
            "npm workspace pattern exceeds the {MAX_PATTERN_BYTES}-byte limit"
        ));
    }
    if pattern.contains('\0') {
        return Err("npm workspace pattern contains a NUL byte".to_owned());
    }
    if pattern.contains('\\') {
        return Err("npm workspace pattern must use normalized forward slashes".to_owned());
    }
    Ok(())
}

pub(super) fn validate_candidate(candidate: &str) -> Result<(), String> {
    if candidate.is_empty() {
        return Err("npm workspace candidate must not be empty".to_owned());
    }
    if candidate.len() > MAX_CANDIDATE_BYTES {
        return Err(format!(
            "npm workspace candidate exceeds the {MAX_CANDIDATE_BYTES}-byte limit"
        ));
    }
    if candidate.contains(['\0', '\\']) {
        return Err("npm workspace candidate is not a normalized package-map key".to_owned());
    }
    let mut components = 0usize;
    for component in candidate.split('/') {
        components += 1;
        if component.is_empty() || matches!(component, "." | "..") {
            return Err("npm workspace candidate contains an invalid path component".to_owned());
        }
    }
    if components > MAX_COMPONENTS {
        return Err(format!(
            "npm workspace candidate exceeds the {MAX_COMPONENTS}-component limit"
        ));
    }
    Ok(())
}

pub(super) fn parse_path_pattern(
    pattern: &str,
    node_count: &mut usize,
) -> Result<PathPattern, String> {
    reject_cross_component_extglobs(pattern)?;
    let raw_components = pattern.split('/').collect::<Vec<_>>();
    if raw_components.len() > MAX_COMPONENTS {
        return Err(format!(
            "npm workspace pattern exceeds the {MAX_COMPONENTS}-component limit"
        ));
    }
    if raw_components
        .iter()
        .any(|component| component.is_empty() || *component == "..")
    {
        return Err("npm workspace pattern contains an invalid path component".to_owned());
    }

    let mut raw_pattern_components = Vec::with_capacity(raw_components.len());
    for component in raw_components {
        if component == "**" {
            if !matches!(raw_pattern_components.last(), Some(PathComponent::GlobStar)) {
                raw_pattern_components.push(PathComponent::GlobStar);
            }
            continue;
        }
        let mut parser = ComponentParser::new(component, node_count);
        let sequence = parser.parse_top_level()?;
        sequence.validate_empty_quantifiers()?;
        sequence.validate_repeat_clone_sensitive_empty_exact()?;
        let unit_mode = if sequence.requires_unicode_regexp() {
            UnitMode::UnicodeScalar
        } else {
            UnitMode::Utf16
        };
        if unit_mode == UnitMode::UnicodeScalar
            && sequence.contains_invalid_unicode_identity_escape()
        {
            return Err(
                "npm workspace pattern is invalid under minimatch's Unicode regular-expression rules"
                    .to_owned(),
            );
        }
        raw_pattern_components.push(PathComponent::Pattern {
            sequence,
            unit_mode,
        });
    }

    let mut components = Vec::with_capacity(raw_pattern_components.len());
    for component in raw_pattern_components {
        components.push(match component {
            PathComponent::GlobStar => PathComponent::GlobStar,
            PathComponent::Pattern {
                sequence,
                unit_mode,
            } => PathComponent::Pattern {
                sequence: lower_sequence(
                    &sequence,
                    true,
                    true,
                    true,
                    RawRemainder::empty(),
                    node_count,
                )?,
                unit_mode,
            },
        });
    }
    Ok(PathPattern { components })
}

pub(super) fn reject_cross_component_extglobs(pattern: &str) -> Result<(), String> {
    let chars = pattern.chars().collect::<Vec<_>>();
    let mut extglob_depth = 0usize;
    let mut in_class = false;
    let mut index = 0usize;
    while index < chars.len() {
        let current = chars[index];
        match current {
            '[' => in_class = true,
            ']' => in_class = false,
            '@' | '?' | '+' | '*' | '!' if !in_class && chars.get(index + 1) == Some(&'(') => {
                extglob_depth += 1;
                index += 1;
            }
            ')' if !in_class && extglob_depth > 0 => extglob_depth -= 1,
            '/' if !in_class && extglob_depth > 0 => {
                return Err(
                    "npm workspace extglob alternatives must not cross path separators".to_owned(),
                );
            }
            _ => {}
        }
        index += 1;
    }
    Ok(())
}

pub(super) fn mark_plain_star_parts(tokens: &mut [Token]) {
    let mut part_start = 0usize;
    for index in 0..=tokens.len() {
        let at_boundary = index == tokens.len() || matches!(tokens[index], Token::Extglob { .. });
        if !at_boundary {
            continue;
        }
        if index == part_start + 1
            && let Token::Star { sole_in_part, .. } = &mut tokens[part_start]
        {
            *sole_in_part = true;
        }
        part_start = index.saturating_add(1);
    }
}

pub(super) const MAX_REMAINDER_PARTS: usize = MAX_NESTING + 1;

#[derive(Clone, Copy)]
pub(super) struct RawRemainder<'a> {
    pub(super) parts: [&'a [Token]; MAX_REMAINDER_PARTS],
    pub(super) len: usize,
}

impl<'a> RawRemainder<'a> {
    pub(super) fn empty() -> Self {
        Self {
            parts: [&[]; MAX_REMAINDER_PARTS],
            len: 0,
        }
    }

    pub(super) fn prepend(mut self, tokens: &'a [Token]) -> Result<Self, String> {
        if tokens.is_empty() {
            return Ok(self);
        }
        if self.len == MAX_REMAINDER_PARTS {
            return Err(format!(
                "npm workspace extglob remainder exceeds the {MAX_REMAINDER_PARTS}-part limit"
            ));
        }
        self.parts.copy_within(0..self.len, 1);
        self.parts[0] = tokens;
        self.len += 1;
        Ok(self)
    }
}
