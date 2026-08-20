use super::*;

pub(crate) fn validate_osv_dump_document<'a>(
    entry_name: &str,
    document: &'a Value,
) -> Result<ValidatedOsvDocument<'a>, String> {
    let validated = validate_osv_document(document, None).map_err(|error| error.to_string())?;
    if entry_name != format!("{}.json", validated.id) {
        return Err(format!(
            "filename does not match advisory id {:?}",
            validated.id
        ));
    }
    Ok(validated)
}

pub(crate) fn visit_osv_dump_file<F>(
    file: File,
    context: OsvDumpValidationContext<'_>,
    limits: OsvDumpLimits,
    allow_empty: bool,
    mut visit: F,
) -> Result<(), ProviderError>
where
    F: for<'a> FnMut(&str, &'a Value, &ValidatedOsvDocument<'a>) -> Result<(), ProviderError>,
{
    let compressed_bytes = file
        .metadata()
        .map_err(|error| context.invalid(format_args!("cannot inspect archive: {error}")))?
        .len();
    if compressed_bytes > limits.max_compressed_bytes {
        return Err(context.invalid(format_args!(
            "compressed size exceeds {} bytes",
            limits.max_compressed_bytes
        )));
    }
    let mut archive =
        ZipArchive::new(file).map_err(|error| context.invalid(format_args!("bad ZIP: {error}")))?;
    if archive.len() > limits.max_entries {
        return Err(context.invalid(format_args!("entry count exceeds {}", limits.max_entries)));
    }

    let mut json_entries = 0usize;
    let mut declared_uncompressed_bytes = 0u64;
    let mut actual_uncompressed_bytes = 0u64;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| {
            context.invalid(format_args!("cannot open entry at index {index}: {error}"))
        })?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_owned();
        if !name.ends_with(".json") {
            return Err(context.invalid(format_args!("unexpected non-JSON entry {name:?}")));
        }
        if entry.size() > limits.max_entry_bytes {
            return Err(context.invalid(format_args!(
                "entry {name:?} exceeds {} declared uncompressed bytes",
                limits.max_entry_bytes
            )));
        }
        declared_uncompressed_bytes = declared_uncompressed_bytes
            .checked_add(entry.size())
            .ok_or_else(|| context.invalid("declared uncompressed size overflowed"))?;
        if declared_uncompressed_bytes > limits.max_uncompressed_bytes {
            return Err(context.invalid(format_args!(
                "declared uncompressed size exceeds {} bytes at entry {name:?}",
                limits.max_uncompressed_bytes
            )));
        }

        let entry_read_limit = limits.max_entry_bytes.saturating_add(1);
        let mut limited = (&mut entry).take(entry_read_limit);
        let mut deserializer = serde_json::Deserializer::from_reader(&mut limited);
        let parsed = Value::deserialize(&mut deserializer).and_then(|document| {
            deserializer.end()?;
            Ok(document)
        });
        drop(deserializer);
        let actual_entry_bytes = entry_read_limit.saturating_sub(limited.limit());
        if actual_entry_bytes > limits.max_entry_bytes {
            return Err(context.invalid(format_args!(
                "entry {name:?} exceeds {} actual uncompressed bytes",
                limits.max_entry_bytes
            )));
        }
        actual_uncompressed_bytes = actual_uncompressed_bytes
            .checked_add(actual_entry_bytes)
            .ok_or_else(|| context.invalid("actual uncompressed size overflowed"))?;
        if actual_uncompressed_bytes > limits.max_uncompressed_bytes {
            return Err(context.invalid(format_args!(
                "actual uncompressed size exceeds {} bytes at entry {name:?}",
                limits.max_uncompressed_bytes
            )));
        }
        let document = parsed.map_err(|error| {
            context.invalid(format_args!(
                "entry {name:?} is not complete valid UTF-8 JSON: {error}"
            ))
        })?;
        let validated = validate_osv_dump_document(&name, &document).map_err(|error| {
            context.invalid(format_args!(
                "entry {name:?} is not an OSV document: {error}"
            ))
        })?;
        visit(&name, &document, &validated)?;
        json_entries += 1;
    }
    if json_entries == 0 && !allow_empty {
        return Err(context.invalid("archive contains no JSON entries"));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn validate_osv_dump(
    path: &Path,
    ecosystem: Ecosystem,
    config: &OsvSyncConfig,
) -> Result<(), ProviderError> {
    let file = File::open(path).map_err(|error| ProviderError::Cache(error.to_string()))?;
    validate_osv_dump_file(file, ecosystem, config)
}

pub(crate) fn validate_osv_dump_file(
    file: File,
    ecosystem: Ecosystem,
    config: &OsvSyncConfig,
) -> Result<(), ProviderError> {
    visit_osv_dump_file(
        file,
        OsvDumpValidationContext::Sync(ecosystem),
        config.dump_limits(),
        false,
        |_, _, _| Ok(()),
    )
}
