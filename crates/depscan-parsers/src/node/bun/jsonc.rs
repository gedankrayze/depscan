pub(crate) fn strip_jsonc(input: &str) -> Result<String, String> {
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    let mut quoted = false;
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if quoted {
            result.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
            continue;
        }
        if ch == '"' {
            quoted = true;
            result.push(ch);
        } else if ch == '/' && chars.peek() == Some(&'/') {
            let _ = chars.next();
            for comment in chars.by_ref() {
                if comment == '\n' {
                    result.push('\n');
                    break;
                }
            }
        } else if ch == '/' && chars.peek() == Some(&'*') {
            let _ = chars.next();
            // JSONC comments are whitespace. Preserve a separator so removing a
            // comment cannot accidentally join two otherwise-invalid tokens.
            result.push(' ');
            let mut closed = false;
            let mut previous = '\0';
            for comment in chars.by_ref() {
                if comment == '\n' {
                    result.push('\n');
                }
                if previous == '*' && comment == '/' {
                    closed = true;
                    break;
                }
                previous = comment;
            }
            if !closed {
                return Err("unterminated block comment in Bun lockfile".to_owned());
            }
            result.push(' ');
        } else {
            result.push(ch);
        }
    }
    if quoted {
        return Err("unterminated string in Bun lockfile".to_owned());
    }

    let mut out = String::new();
    let mut iter = result.chars().peekable();
    let mut quoted = false;
    let mut escaped = false;
    while let Some(ch) = iter.next() {
        if quoted {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
            out.push(ch);
        } else if ch == ',' {
            let mut spaces = String::new();
            while matches!(iter.peek(), Some(c) if c.is_whitespace()) {
                if let Some(space) = iter.next() {
                    spaces.push(space);
                }
            }
            if matches!(iter.peek(), Some('}' | ']')) {
                out.push_str(&spaces);
                continue;
            }
            out.push(',');
            out.push_str(&spaces);
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}
