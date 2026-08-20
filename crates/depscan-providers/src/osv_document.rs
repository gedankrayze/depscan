use chrono::{DateTime, Utc};
use depscan_core::ProviderError;
use serde_json::{Map, Value};

#[derive(Debug)]
pub(super) struct ValidatedOsvDocument<'a> {
    pub(super) id: &'a str,
    pub(super) modified: DateTime<Utc>,
    pub(super) affected: &'a [Value],
    pub(super) withdrawn: bool,
}

pub(super) fn valid_osv_id(id: &str) -> bool {
    let Some((database, entry)) = id.split_once('-') else {
        return false;
    };

    let valid_component =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_');

    !database.is_empty()
        && !entry.is_empty()
        && database.bytes().any(|byte| byte.is_ascii_alphanumeric())
        && entry.bytes().any(|byte| byte.is_ascii_alphanumeric())
        && database.bytes().all(valid_component)
        && entry.bytes().all(valid_component)
}

fn document_error(expected_id: Option<&str>, reason: impl std::fmt::Display) -> ProviderError {
    let subject = expected_id.map_or_else(
        || "OSV document".to_owned(),
        |id| format!("OSV advisory {id}"),
    );
    ProviderError::InvalidResponse(format!("{subject} is invalid: {reason}"))
}

fn string_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    path: &str,
) -> Result<&'a str, String> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path}.{field} must be a string"))?;
    if value.is_empty() {
        return Err(format!("{path}.{field} must not be empty"));
    }
    Ok(value)
}

fn timestamp(value: &Value, path: &str) -> Result<DateTime<Utc>, String> {
    let raw = value
        .as_str()
        .ok_or_else(|| format!("{path} must be an RFC 3339 string"))?;
    DateTime::parse_from_rfc3339(raw)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| format!("{path} must be a valid RFC 3339 timestamp"))
}

fn optional_timestamp(
    object: &Map<String, Value>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, String> {
    object
        .get(field)
        .map(|value| timestamp(value, field))
        .transpose()
}

fn optional_string(object: &Map<String, Value>, field: &str, path: &str) -> Result<(), String> {
    if let Some(value) = object.get(field)
        && !value.is_string()
    {
        return Err(format!("{path}.{field} must be a string"));
    }
    Ok(())
}

fn string_array(value: &Value, path: &str, nullable: bool) -> Result<(), String> {
    if nullable && value.is_null() {
        return Ok(());
    }
    let entries = value
        .as_array()
        .ok_or_else(|| format!("{path} must be an array of strings"))?;
    for (index, entry) in entries.iter().enumerate() {
        let Some(entry) = entry.as_str() else {
            return Err(format!("{path}[{index}] must be a string"));
        };
        if entry.is_empty() {
            return Err(format!("{path}[{index}] must not be empty"));
        }
    }
    Ok(())
}

fn severity(value: &Value, path: &str) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let entries = value
        .as_array()
        .ok_or_else(|| format!("{path} must be an array"))?;
    for (index, entry) in entries.iter().enumerate() {
        let entry_path = format!("{path}[{index}]");
        let object = entry
            .as_object()
            .ok_or_else(|| format!("{entry_path} must be an object"))?;
        string_field(object, "type", &entry_path)?;
        string_field(object, "score", &entry_path)?;
        optional_string(object, "source", &entry_path)?;
    }
    Ok(())
}

fn range(value: &Value, path: &str) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{path} must be an object"))?;
    let range_type = string_field(object, "type", path)?;
    optional_string(object, "repo", path)?;
    if range_type == "GIT" && object.get("repo").is_none() {
        return Err(format!("{path}.repo is required for a GIT range"));
    }
    if let Some(database_specific) = object.get("database_specific")
        && !database_specific.is_object()
    {
        return Err(format!("{path}.database_specific must be an object"));
    }

    let events = object
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{path}.events must be an array"))?;
    if events.is_empty() {
        return Err(format!("{path}.events must not be empty"));
    }
    let mut introduced = false;
    let mut fixed = false;
    let mut last_affected = false;
    for (index, event) in events.iter().enumerate() {
        let event_path = format!("{path}.events[{index}]");
        let event = event
            .as_object()
            .ok_or_else(|| format!("{event_path} must be an object"))?;
        let known = ["introduced", "fixed", "last_affected", "limit"]
            .into_iter()
            .filter_map(|field| event.get(field).map(|value| (field, value)))
            .collect::<Vec<_>>();
        if known.len() != 1 {
            return Err(format!(
                "{event_path} must contain exactly one of introduced, fixed, last_affected, or limit"
            ));
        }
        let (field, value) = known[0];
        let version = value
            .as_str()
            .ok_or_else(|| format!("{event_path}.{field} must be a string"))?;
        if version.is_empty() {
            return Err(format!("{event_path}.{field} must not be empty"));
        }
        introduced |= field == "introduced";
        fixed |= field == "fixed";
        last_affected |= field == "last_affected";
    }
    if !introduced {
        return Err(format!("{path}.events must contain an introduced event"));
    }
    if fixed && last_affected {
        return Err(format!(
            "{path}.events must not mix fixed and last_affected events"
        ));
    }
    Ok(())
}

fn affected_entry(value: &Value, index: usize) -> Result<(), String> {
    let path = format!("affected[{index}]");
    let object = value
        .as_object()
        .ok_or_else(|| format!("{path} must be an object"))?;
    let package = object
        .get("package")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{path}.package must be an object"))?;
    let package_path = format!("{path}.package");
    string_field(package, "ecosystem", &package_path)?;
    string_field(package, "name", &package_path)?;
    optional_string(package, "purl", &package_path)?;
    if let Some(value) = object.get("severity") {
        severity(value, &format!("{path}.severity"))?;
    }
    for field in ["ecosystem_specific", "database_specific"] {
        if let Some(value) = object.get(field)
            && !value.is_object()
        {
            return Err(format!("{path}.{field} must be an object"));
        }
    }

    if let Some(versions) = object.get("versions") {
        string_array(versions, &format!("{path}.versions"), false)?;
    }
    if let Some(ranges) = object.get("ranges") {
        let ranges = ranges
            .as_array()
            .ok_or_else(|| format!("{path}.ranges must be an array"))?;
        for (range_index, value) in ranges.iter().enumerate() {
            range(value, &format!("{path}.ranges[{range_index}]"))?;
        }
    }
    Ok(())
}

fn references(value: &Value) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let references = value
        .as_array()
        .ok_or_else(|| "references must be an array".to_owned())?;
    for (index, reference) in references.iter().enumerate() {
        let path = format!("references[{index}]");
        let object = reference
            .as_object()
            .ok_or_else(|| format!("{path} must be an object"))?;
        string_field(object, "type", &path)?;
        string_field(object, "url", &path)?;
    }
    Ok(())
}

pub(super) fn validate_osv_document<'a>(
    doc: &'a Value,
    expected_id: Option<&str>,
) -> Result<ValidatedOsvDocument<'a>, ProviderError> {
    let validate = || -> Result<ValidatedOsvDocument<'a>, String> {
        let object = doc
            .as_object()
            .ok_or_else(|| "top-level value must be an object".to_owned())?;
        let id = string_field(object, "id", "document")?;
        if !valid_osv_id(id) {
            return Err("document.id is not a valid OSV identifier".to_owned());
        }
        if let Some(expected_id) = expected_id
            && id != expected_id
        {
            return Err(format!("document.id is {id:?}, expected {expected_id:?}"));
        }
        let modified = object
            .get("modified")
            .ok_or_else(|| "document.modified is required".to_owned())
            .and_then(|value| timestamp(value, "document.modified"))?;
        if let Some(schema_version) = object.get("schema_version") {
            let schema_version = schema_version
                .as_str()
                .ok_or_else(|| "schema_version must be a string".to_owned())?;
            let parsed = schema_version
                .parse::<semver::Version>()
                .map_err(|_| "schema_version must be a semantic version".to_owned())?;
            if parsed.major != 1 {
                return Err(format!(
                    "schema_version {schema_version:?} has an unsupported major version"
                ));
            }
        }
        optional_timestamp(object, "published")?;
        let withdrawn = optional_timestamp(object, "withdrawn")?.is_some();
        for field in ["summary", "details"] {
            optional_string(object, field, "document")?;
        }
        for field in ["aliases", "related", "upstream"] {
            if let Some(value) = object.get(field) {
                string_array(value, field, field == "aliases")?;
            }
        }
        if let Some(value) = object.get("severity") {
            severity(value, "severity")?;
        }
        if let Some(value) = object.get("references") {
            references(value)?;
        }
        if let Some(database_specific) = object.get("database_specific")
            && !database_specific.is_object()
        {
            return Err("database_specific must be an object".to_owned());
        }
        let affected = object
            .get("affected")
            .and_then(Value::as_array)
            .ok_or_else(|| "affected must be a present array".to_owned())?;
        for (index, value) in affected.iter().enumerate() {
            affected_entry(value, index)?;
        }

        Ok(ValidatedOsvDocument {
            id,
            modified,
            affected,
            withdrawn,
        })
    };

    validate().map_err(|reason| document_error(expected_id, reason))
}

pub(super) fn affected_entry_is_evaluable(affected: &Value) -> bool {
    affected
        .get("versions")
        .and_then(Value::as_array)
        .is_some_and(|versions| !versions.is_empty())
        || affected
            .get("ranges")
            .and_then(Value::as_array)
            .is_some_and(|ranges| !ranges.is_empty())
}

#[cfg(test)]
mod tests;
