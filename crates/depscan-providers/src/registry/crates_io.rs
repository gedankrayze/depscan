use super::*;

pub(crate) fn invalid_crates_io_name(name: &str, reason: impl Into<String>) -> ProviderError {
    ProviderError::InvalidPackageName {
        ecosystem: Ecosystem::CratesIo,
        name: name.to_owned(),
        reason: reason.into(),
    }
}

/// Builds the lowercase crates.io sparse-index path after applying the registry's structural
/// package-name restrictions. Reserved-name and collision policies are registry concerns; this
/// validation covers the grammar needed to construct one safe index path.
pub(crate) fn crates_io_sparse_path(name: &str) -> Result<String, ProviderError> {
    if name.is_empty() {
        return Err(invalid_crates_io_name(name, "the name cannot be empty"));
    }
    if !name.is_ascii() {
        return Err(invalid_crates_io_name(
            name,
            "only ASCII characters are allowed",
        ));
    }
    if name.len() > CRATES_IO_MAX_NAME_LEN {
        return Err(invalid_crates_io_name(
            name,
            format!("the name exceeds {CRATES_IO_MAX_NAME_LEN} ASCII characters"),
        ));
    }

    let first = name
        .as_bytes()
        .first()
        .copied()
        .ok_or_else(|| invalid_crates_io_name(name, "the name cannot be empty"))?;
    if !first.is_ascii_alphabetic() {
        return Err(invalid_crates_io_name(
            name,
            "the first character must be an ASCII letter",
        ));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid_crates_io_name(
            name,
            "only ASCII letters, digits, '-' and '_' are allowed",
        ));
    }

    let normalized = name.to_ascii_lowercase();
    Ok(match normalized.len() {
        1 => format!("1/{normalized}"),
        2 => format!("2/{normalized}"),
        3 => {
            let first: String = normalized.chars().take(1).collect();
            format!("3/{first}/{normalized}")
        }
        _ => {
            let first_two: String = normalized.chars().take(2).collect();
            let second_two: String = normalized.chars().skip(2).take(2).collect();
            format!("{first_two}/{second_two}/{normalized}")
        }
    })
}
