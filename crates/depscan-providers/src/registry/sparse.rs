use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CratesIndexEntry {
    pub(crate) name: String,
    pub(crate) vers: String,
    pub(crate) yanked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CratesIndexCache {
    pub(crate) schema_version: u32,
    pub(crate) entries: Vec<CratesIndexEntry>,
}

pub(crate) fn invalid_sparse_index(source: &str, message: impl std::fmt::Display) -> ProviderError {
    ProviderError::InvalidResponse(format!("{source}: {message}"))
}

pub(crate) fn invalid_sparse_index_line(
    source: &str,
    line_number: usize,
    message: impl std::fmt::Display,
) -> ProviderError {
    invalid_sparse_index(
        source,
        format_args!("sparse-index line {line_number}: {message}"),
    )
}

pub(crate) fn validate_crates_index_entries<'a>(
    entries: impl IntoIterator<Item = (usize, &'a CratesIndexEntry)>,
    expected_name: &str,
    source: &str,
) -> Result<(), ProviderError> {
    let mut seen_versions: HashMap<&'a str, usize> = HashMap::new();
    let mut entry_count = 0_usize;

    for (line_number, entry) in entries {
        entry_count += 1;
        if !entry.name.eq_ignore_ascii_case(expected_name) {
            return Err(invalid_sparse_index_line(
                source,
                line_number,
                format_args!(
                    "crate name {:?} does not match requested crate {expected_name:?}",
                    entry.name
                ),
            ));
        }
        semver::Version::parse(&entry.vers).map_err(|error| {
            invalid_sparse_index_line(
                source,
                line_number,
                format_args!("field `vers` is not valid SemVer: {error}"),
            )
        })?;
        if let Some(first_line) = seen_versions.insert(&entry.vers, line_number) {
            return Err(invalid_sparse_index_line(
                source,
                line_number,
                format_args!(
                    "duplicate version {:?}; first declared on line {first_line}",
                    entry.vers
                ),
            ));
        }
    }

    if entry_count == 0 {
        return Err(invalid_sparse_index(
            source,
            "sparse index contains no version entries",
        ));
    }
    Ok(())
}

pub(crate) fn decode_crates_index(
    bytes: &[u8],
    expected_name: &str,
    source: &str,
) -> Result<Vec<CratesIndexEntry>, ProviderError> {
    if bytes.len() > CRATES_IO_MAX_INDEX_RESPONSE_BYTES {
        return Err(invalid_sparse_index(
            source,
            format_args!("response exceeds the {CRATES_IO_MAX_INDEX_RESPONSE_BYTES}-byte limit"),
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|error| {
        let line_number = bytes[..error.valid_up_to()]
            .iter()
            .filter(|&&byte| byte == b'\n')
            .count()
            + 1;
        invalid_sparse_index_line(source, line_number, "line is not valid UTF-8")
    })?;
    let mut parsed = Vec::new();

    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if line.is_empty() {
            continue;
        }
        if line.len() > CRATES_IO_MAX_INDEX_LINE_BYTES {
            return Err(invalid_sparse_index_line(
                source,
                line_number,
                format_args!("line exceeds the {CRATES_IO_MAX_INDEX_LINE_BYTES}-byte limit"),
            ));
        }
        let entry = serde_json::from_str::<CratesIndexEntry>(line).map_err(|error| {
            invalid_sparse_index_line(source, line_number, format_args!("invalid JSON: {error}"))
        })?;
        parsed.push((line_number, entry));
    }

    validate_crates_index_entries(
        parsed
            .iter()
            .map(|(line_number, entry)| (*line_number, entry)),
        expected_name,
        source,
    )?;
    Ok(parsed.into_iter().map(|(_, entry)| entry).collect())
}

pub(crate) fn validated_cached_crates_index(
    entry: &CacheLookup,
    expected_name: &str,
) -> Option<CratesIndexCache> {
    let cached = serde_json::from_value::<CratesIndexCache>(entry.value.clone()).ok()?;
    (cached.schema_version == CRATES_IO_INDEX_CACHE_SCHEMA_VERSION
        && validate_crates_index_entries(
            cached
                .entries
                .iter()
                .enumerate()
                .map(|(index, entry)| (index + 1, entry)),
            expected_name,
            "cached crates.io sparse index",
        )
        .is_ok())
    .then_some(cached)
}
