use super::*;

pub(super) fn strip_comment(line: &str) -> &str {
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

pub(super) fn option_value<'a>(line: &'a str, short: Option<&str>, long: &str) -> Option<&'a str> {
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

pub(super) fn single_value(value: &str, option: &str) -> Result<String, SyntaxError> {
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

pub(super) fn whole_value(value: &str, option: &str) -> Result<String, SyntaxError> {
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

pub(super) fn leading_option_name(line: &str) -> &str {
    line.split_ascii_whitespace()
        .next()
        .unwrap_or(line)
        .split_once('=')
        .map_or_else(
            || line.split_ascii_whitespace().next().unwrap_or(line),
            |x| x.0,
        )
}

pub(super) fn strip_per_requirement_options(line: &str) -> Result<&str, SyntaxError> {
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

pub(super) fn find_option_start(line: &str) -> Option<usize> {
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

pub(super) fn option_word<'a>(input: &'a str, option: &str) -> Option<&'a str> {
    let rest = input.strip_prefix(option)?;
    rest.as_bytes()
        .first()
        .is_some_and(u8::is_ascii_whitespace)
        .then_some(rest)
}

pub(super) fn take_token<'a>(
    input: &'a str,
    option: &str,
) -> Result<(&'a str, &'a str), SyntaxError> {
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

pub(super) fn validate_hash(value: &str) -> Result<(), SyntaxError> {
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

pub(super) fn validate_config_setting(value: &str) -> Result<(), SyntaxError> {
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
