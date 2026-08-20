use super::*;

pub(super) fn expand_braces(pattern: &str) -> Result<Vec<String>, String> {
    let mut pending = vec![pattern.to_owned()];
    let mut complete = Vec::new();
    let mut seen = HashSet::new();

    while let Some(candidate) = pending.pop() {
        if !seen.insert(candidate.clone()) {
            continue;
        }
        let chars = candidate.chars().collect::<Vec<_>>();
        if let Some((open, close, replacements)) = find_expandable_brace(&chars)? {
            if pending.len() + complete.len() + replacements.len() > MAX_BRACE_EXPANSIONS {
                return Err(format!(
                    "npm workspace brace expansion exceeds the {MAX_BRACE_EXPANSIONS}-result limit"
                ));
            }
            let prefix = chars[..open].iter().collect::<String>();
            let suffix = chars[close + 1..].iter().collect::<String>();
            for replacement in replacements.into_iter().rev() {
                pending.push(format!("{prefix}{replacement}{suffix}"));
            }
        } else {
            complete.push(candidate);
        }
    }

    complete.sort();
    if complete.len() > MAX_BRACE_EXPANSIONS {
        return Err(format!(
            "npm workspace brace expansion exceeds the {MAX_BRACE_EXPANSIONS}-result limit"
        ));
    }
    Ok(complete)
}

pub(super) fn find_expandable_brace(
    chars: &[char],
) -> Result<Option<(usize, usize, Vec<String>)>, String> {
    let mut stack = Vec::new();
    let mut protected_depth = 0usize;
    for (index, current) in chars.iter().copied().enumerate() {
        if protected_depth > 0 {
            match current {
                '{' => protected_depth += 1,
                '}' => protected_depth -= 1,
                _ => {}
            }
            continue;
        }
        match current {
            '{' if index > 0 && chars[index - 1] == '$' => protected_depth = 1,
            '{' => {
                if stack.len() >= MAX_NESTING {
                    return Err(format!(
                        "npm workspace brace expression exceeds the {MAX_NESTING}-level nesting limit"
                    ));
                }
                stack.push(index);
            }
            '}' => {
                let Some(open) = stack.pop() else {
                    continue;
                };
                let inner = &chars[open + 1..index];
                if let Some(replacements) = brace_replacements(inner)? {
                    return Ok(Some((open, index, replacements)));
                }
            }
            _ => {}
        }
    }
    Ok(None)
}

pub(super) fn brace_replacements(inner: &[char]) -> Result<Option<Vec<String>>, String> {
    let comma_parts = split_top_level(inner, ',');
    if comma_parts.len() > 1 {
        return Ok(Some(
            comma_parts
                .into_iter()
                .map(|part| part.iter().collect::<String>())
                .collect(),
        ));
    }

    let range_parts = split_range_parts(inner);
    if range_parts.len() != 2 && range_parts.len() != 3 {
        return Ok(None);
    }
    if range_parts.iter().any(|part| part.starts_with('+')) {
        return Ok(None);
    }
    if let Some((start, end)) = parse_integer(&range_parts[0]).zip(parse_integer(&range_parts[1])) {
        return expand_numeric_range(&range_parts, start, end).map(Some);
    }
    if let Some((start, end)) =
        parse_alpha_endpoint(&range_parts[0]).zip(parse_alpha_endpoint(&range_parts[1]))
    {
        return expand_alpha_range(&range_parts, start, end).map(Some);
    }
    Ok(None)
}

pub(super) fn range_step(parts: &[String], kind: &str) -> Result<u64, String> {
    if parts.len() != 3 {
        return Ok(1);
    }
    let Some(step) = parse_integer(&parts[2]) else {
        return Err(format!(
            "npm workspace {kind} brace range has a non-numeric step"
        ));
    };
    if step == 0 {
        return Err(format!("npm workspace {kind} brace range has a zero step"));
    }
    Ok(step.unsigned_abs())
}

pub(super) fn expand_numeric_range(
    parts: &[String],
    start: i64,
    end: i64,
) -> Result<Vec<String>, String> {
    let step = range_step(parts, "numeric")?;

    let distance = start.abs_diff(end);
    let result_count = distance / step + 1;
    if result_count > MAX_BRACE_EXPANSIONS as u64 {
        return Err(format!(
            "npm workspace numeric brace range exceeds the {MAX_BRACE_EXPANSIONS}-result limit"
        ));
    }

    let width = numeric_padding_width(&parts[0]).max(numeric_padding_width(&parts[1]));
    let direction = if start <= end { 1_i128 } else { -1_i128 };
    let signed_step = direction * i128::from(step);
    let mut value = i128::from(start);
    let end = i128::from(end);
    let mut replacements = Vec::with_capacity(result_count as usize);
    loop {
        replacements.push(format_range_value(value, width));
        if value == end {
            break;
        }
        let next = value + signed_step;
        if (direction > 0 && next > end) || (direction < 0 && next < end) {
            break;
        }
        value = next;
    }
    Ok(replacements)
}

pub(super) fn parse_alpha_endpoint(value: &str) -> Option<char> {
    let mut chars = value.chars();
    let endpoint = chars.next()?;
    if chars.next().is_none() && endpoint.is_ascii_alphabetic() {
        Some(endpoint)
    } else {
        None
    }
}

pub(super) fn expand_alpha_range(
    parts: &[String],
    start: char,
    end: char,
) -> Result<Vec<String>, String> {
    let step = range_step(parts, "alphabetic")?;
    let start = u32::from(start);
    let end = u32::from(end);
    let distance = start.abs_diff(end);
    let result_count = u64::from(distance) / step + 1;
    if result_count > MAX_BRACE_EXPANSIONS as u64 {
        return Err(format!(
            "npm workspace alphabetic brace range exceeds the {MAX_BRACE_EXPANSIONS}-result limit"
        ));
    }

    let direction = if start <= end { 1_i64 } else { -1_i64 };
    let signed_step = direction
        * i64::try_from(step)
            .map_err(|_| "npm workspace alphabetic brace range step is too large".to_owned())?;
    let mut value = i64::from(start);
    let end = i64::from(end);
    let mut replacements = Vec::with_capacity(result_count as usize);
    loop {
        let character = char::from_u32(u32::try_from(value).map_err(|_| {
            "npm workspace alphabetic brace range produced an invalid character".to_owned()
        })?)
        .ok_or_else(|| {
            "npm workspace alphabetic brace range produced an invalid character".to_owned()
        })?;
        replacements.push(character.to_string());
        if value == end {
            break;
        }
        let next = value + signed_step;
        if (direction > 0 && next > end) || (direction < 0 && next < end) {
            break;
        }
        value = next;
    }
    Ok(replacements)
}

pub(super) fn split_top_level(chars: &[char], delimiter: char) -> Vec<&[char]> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut braces = 0usize;
    for (index, current) in chars.iter().copied().enumerate() {
        match current {
            '{' => braces += 1,
            '}' => braces = braces.saturating_sub(1),
            value if value == delimiter && braces == 0 => {
                parts.push(&chars[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&chars[start..]);
    parts
}

pub(super) fn split_range_parts(chars: &[char]) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    while index + 1 < chars.len() {
        if chars[index] == '.' && chars[index + 1] == '.' {
            parts.push(chars[start..index].iter().collect());
            index += 2;
            start = index;
        } else {
            index += 1;
        }
    }
    parts.push(chars[start..].iter().collect());
    parts
}

pub(super) fn parse_integer(value: &str) -> Option<i64> {
    if value.is_empty() || value.starts_with('+') || value == "-" {
        return None;
    }
    value.parse().ok()
}

pub(super) fn numeric_padding_width(value: &str) -> usize {
    let digits = value.trim_start_matches(['+', '-']);
    if digits.len() > 1 && digits.starts_with('0') {
        value.len()
    } else {
        0
    }
}

pub(super) fn format_range_value(value: i128, width: usize) -> String {
    if width == 0 {
        return value.to_string();
    }
    if value < 0 {
        let digit_width = width.saturating_sub(1);
        format!("-{:0digit_width$}", value.unsigned_abs())
    } else {
        format!("{value:0width$}")
    }
}

pub(super) fn deduplicate_positions(positions: Vec<usize>, ceiling: usize) -> Vec<usize> {
    let mut seen = vec![false; ceiling + 1];
    let mut deduplicated = Vec::new();
    for position in positions {
        if !seen[position] {
            seen[position] = true;
            deduplicated.push(position);
        }
    }
    deduplicated
}

#[derive(Debug, Default)]
pub(super) struct MatchContext {
    work: usize,
}

impl MatchContext {
    pub(super) fn bump(&mut self, amount: usize) -> Result<(), String> {
        self.work = self.work.saturating_add(amount);
        if self.work > MAX_MATCH_WORK {
            return Err(format!(
                "npm workspace match exceeds the {MAX_MATCH_WORK}-operation limit"
            ));
        }
        Ok(())
    }
}
