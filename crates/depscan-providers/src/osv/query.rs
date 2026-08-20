use super::*;

pub(crate) fn osv_query_name(package: &Package) -> &str {
    match package.ecosystem {
        Ecosystem::NuGet => &package.display_name,
        _ => &package.name,
    }
}

pub(crate) fn osv_query_cache_key(package: &Package) -> String {
    format!(
        "{}:{}:{}",
        package.ecosystem.osv_name(),
        osv_query_name(package),
        package.version
    )
}

pub(crate) fn osv_query_body_with_tokens(queries: &[(&Package, Option<&str>)]) -> Value {
    json!({
        "queries": queries
            .iter()
            .map(|(package, page_token)| {
                let mut query = json!({
                    "package": {
                        "name": osv_query_name(package),
                        "ecosystem": package.ecosystem.osv_name()
                    },
                    "version": package.version
                });
                if let Some(page_token) = page_token {
                    query
                        .as_object_mut()
                        .expect("OSV query is an object")
                        .insert("page_token".to_owned(), json!(page_token));
                }
                query
            })
            .collect::<Vec<_>>()
    })
}

#[cfg(test)]
pub(crate) fn osv_query_body(packages: &[Package]) -> Value {
    let queries = packages
        .iter()
        .map(|package| (package, None))
        .collect::<Vec<_>>();
    osv_query_body_with_tokens(&queries)
}

pub(crate) fn invalid_osv_batch_response(message: impl Into<String>) -> ProviderError {
    ProviderError::InvalidResponse(format!(
        "OSV querybatch response is invalid: {}",
        message.into()
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OsvVulnerabilityRevision {
    pub(crate) id: String,
    pub(crate) modified: DateTime<Utc>,
}

impl OsvVulnerabilityRevision {
    pub(crate) fn cache_key(&self) -> String {
        format!(
            "{}@{}",
            self.id,
            self.modified.to_rfc3339_opts(SecondsFormat::AutoSi, true)
        )
    }
}

pub(crate) fn canonical_osv_revisions(value: Value) -> Option<Vec<OsvVulnerabilityRevision>> {
    let parsed = serde_json::from_value::<Vec<OsvVulnerabilityRevision>>(value).ok()?;
    let mut revisions = BTreeMap::<String, DateTime<Utc>>::new();
    for revision in parsed {
        if !valid_osv_id(&revision.id) {
            return None;
        }
        revisions
            .entry(revision.id)
            .and_modify(|modified| *modified = std::cmp::max(*modified, revision.modified))
            .or_insert(revision.modified);
    }
    Some(
        revisions
            .into_iter()
            .map(|(id, modified)| OsvVulnerabilityRevision { id, modified })
            .collect(),
    )
}

pub(crate) fn parse_osv_modified(
    value: &Value,
    context: impl std::fmt::Display,
) -> Result<DateTime<Utc>, ProviderError> {
    let raw = value.as_str().ok_or_else(|| {
        invalid_osv_batch_response(format!("{context} has no string modified timestamp"))
    })?;
    DateTime::parse_from_rfc3339(raw)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| {
            invalid_osv_batch_response(format!("{context} has an invalid modified timestamp"))
        })
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OsvQueryBatchPage {
    pub(crate) revisions: Vec<OsvVulnerabilityRevision>,
    pub(crate) next_page_token: Option<String>,
}

pub(crate) fn parse_osv_query_batch_response(
    response: &Value,
    expected_results: usize,
) -> Result<Vec<Result<OsvQueryBatchPage, ProviderError>>, ProviderError> {
    let object = response
        .as_object()
        .ok_or_else(|| invalid_osv_batch_response("the top-level value is not an object"))?;
    let results = object
        .get("results")
        .ok_or_else(|| invalid_osv_batch_response("the required results field is missing"))?
        .as_array()
        .ok_or_else(|| invalid_osv_batch_response("the results field is not an array"))?;

    if results.len() != expected_results {
        return Err(invalid_osv_batch_response(format!(
            "returned {} results for {expected_results} queries",
            results.len()
        )));
    }

    Ok(results
        .iter()
        .enumerate()
        .map(|(result_index, result)| {
            let result = result.as_object().ok_or_else(|| {
                invalid_osv_batch_response(format!("result {result_index} is not an object"))
            })?;
            let next_page_token = result
                .get("next_page_token")
                .map(|token| {
                    let token = token.as_str().ok_or_else(|| {
                        invalid_osv_batch_response(format!(
                            "result {result_index} has a non-string next_page_token field"
                        ))
                    })?;
                    if token.is_empty() {
                        return Err(invalid_osv_batch_response(format!(
                            "result {result_index} has an empty next_page_token field"
                        )));
                    }
                    Ok(token.to_owned())
                })
                .transpose()?;
            let Some(vulns) = result.get("vulns") else {
                // OSV's protobuf JSON encoding represents a legitimate empty result as `{}`.
                return if result.is_empty() || (result.len() == 1 && next_page_token.is_some()) {
                    Ok(OsvQueryBatchPage {
                        revisions: Vec::new(),
                        next_page_token,
                    })
                } else {
                    Err(invalid_osv_batch_response(format!(
                        "result {result_index} is non-empty but has no vulns field"
                    )))
                };
            };
            let vulns = vulns.as_array().ok_or_else(|| {
                invalid_osv_batch_response(format!(
                    "result {result_index} has a non-array vulns field"
                ))
            })?;

            let revisions = vulns
                .iter()
                .enumerate()
                .map(|(vuln_index, vulnerability)| {
                    let vulnerability = vulnerability.as_object().ok_or_else(|| {
                        invalid_osv_batch_response(format!(
                            "result {result_index} vulnerability {vuln_index} is not an object"
                        ))
                    })?;
                    let id = vulnerability
                        .get("id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            invalid_osv_batch_response(format!(
                                "result {result_index} vulnerability {vuln_index} has no string id"
                            ))
                        })?;
                    if !valid_osv_id(id) {
                        return Err(invalid_osv_batch_response(format!(
                            "result {result_index} vulnerability {vuln_index} has an invalid id"
                        )));
                    }
                    let modified = parse_osv_modified(
                        vulnerability.get("modified").unwrap_or(&Value::Null),
                        format_args!("result {result_index} vulnerability {vuln_index}"),
                    )?;
                    Ok(OsvVulnerabilityRevision {
                        id: id.to_owned(),
                        modified,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(OsvQueryBatchPage {
                revisions,
                next_page_token,
            })
        })
        .collect())
}
