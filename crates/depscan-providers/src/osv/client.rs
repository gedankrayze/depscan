use super::*;

#[derive(Clone, Debug)]
pub struct OsvClient {
    pub(crate) http: HttpClient,
    pub(crate) cache: Cache,
    pub(crate) concurrency: Arc<Semaphore>,
    pub(crate) base_url: String,
    pub(crate) batch_deadline: StdDuration,
}
impl OsvClient {
    pub fn new(http: HttpClient, cache: Cache) -> Self {
        Self::with_base_url(http, cache, "https://api.osv.dev")
    }

    pub(crate) fn with_base_url(
        http: HttpClient,
        cache: Cache,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            http,
            cache,
            concurrency: Arc::new(Semaphore::new(16)),
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            batch_deadline: OSV_QUERY_BATCH_DEADLINE,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_batch_deadline(mut self, deadline: StdDuration) -> Self {
        self.batch_deadline = deadline;
        self
    }
    #[cfg(test)]
    pub(crate) async fn query_batch(
        &self,
        batch: &[Package],
    ) -> Result<Vec<Vec<OsvVulnerabilityRevision>>, ProviderError> {
        self.query_batch_outcomes(batch).await.into_iter().collect()
    }

    pub(crate) async fn query_batch_outcomes(
        &self,
        batch: &[Package],
    ) -> Vec<Result<Vec<OsvVulnerabilityRevision>, ProviderError>> {
        let url = format!("{}/v1/querybatch", self.base_url);
        let mut revisions = vec![BTreeMap::<String, DateTime<Utc>>::new(); batch.len()];
        let mut failures = vec![None::<ProviderError>; batch.len()];
        let mut seen_tokens = vec![BTreeSet::new(); batch.len()];
        let mut pages_seen = vec![0usize; batch.len()];
        let mut pending = (0..batch.len())
            .map(|index| (index, None::<String>))
            .collect::<Vec<_>>();

        let started = tokio::time::Instant::now();
        while !pending.is_empty() {
            // Checked between round-trips; each in-flight request is separately bounded by the
            // HTTP request timeout, so the practical bound is the deadline plus one request.
            if started.elapsed() > self.batch_deadline {
                let error = ProviderError::Network(format!(
                    "OSV batch query exceeded its {}-second pagination deadline",
                    self.batch_deadline.as_secs()
                ));
                for (index, _) in &pending {
                    failures[*index] = Some(error.clone());
                }
                break;
            }
            let queries = pending
                .iter()
                .map(|(index, page_token)| (&batch[*index], page_token.as_deref()))
                .collect::<Vec<_>>();
            let body = osv_query_body_with_tokens(&queries);
            let _permit = match self.concurrency.acquire().await {
                Ok(permit) => permit,
                Err(error) => {
                    let error = ProviderError::Network(error.to_string());
                    for (index, _) in &pending {
                        failures[*index] = Some(error.clone());
                    }
                    break;
                }
            };
            let response = match self.http.post_json(&url, body).await {
                Ok(response) => response,
                Err(error) => {
                    for (index, _) in &pending {
                        failures[*index] = Some(error.clone());
                    }
                    break;
                }
            };
            drop(_permit);
            let pages = match parse_osv_query_batch_response(&response, pending.len()) {
                Ok(pages) => pages,
                Err(error) => {
                    for (index, _) in &pending {
                        failures[*index] = Some(error.clone());
                    }
                    break;
                }
            };
            let mut next = Vec::new();
            for ((index, _), page) in pending.into_iter().zip(pages) {
                let page = match page {
                    Ok(page) => page,
                    Err(error) => {
                        failures[index] = Some(error);
                        continue;
                    }
                };
                pages_seen[index] += 1;
                for revision in page.revisions {
                    revisions[index]
                        .entry(revision.id)
                        .and_modify(|modified| {
                            *modified = std::cmp::max(*modified, revision.modified)
                        })
                        .or_insert(revision.modified);
                }
                if let Some(token) = page.next_page_token {
                    if !seen_tokens[index].insert(token.clone()) {
                        failures[index] = Some(invalid_osv_batch_response(format!(
                            "result for query {index} repeated a next_page_token"
                        )));
                        continue;
                    }
                    if pages_seen[index] >= OSV_MAX_QUERY_PAGES {
                        failures[index] = Some(invalid_osv_batch_response(format!(
                            "result for query {index} exceeded the {OSV_MAX_QUERY_PAGES}-page limit"
                        )));
                        continue;
                    }
                    next.push((index, Some(token)));
                }
            }
            pending = next;
        }

        revisions
            .into_iter()
            .zip(failures)
            .map(|(revisions, failure)| {
                failure.map_or_else(
                    || {
                        Ok(revisions
                            .into_iter()
                            .map(|(id, modified)| OsvVulnerabilityRevision { id, modified })
                            .collect())
                    },
                    Err,
                )
            })
            .collect()
    }
    pub(crate) async fn publish_hydrated_document(
        &self,
        cache_key: &str,
        id: &str,
        value: &Value,
        etag: Option<String>,
        candidate_reusable: bool,
    ) -> Result<PublishedHydration, ProviderError> {
        let candidate_modified = validate_osv_document(value, Some(id))?.modified;
        let ttl = Duration::hours(24 * 3650);
        let mut generation = self.cache.snapshot("osv/vuln", cache_key, ttl).await;
        for _ in 0..CACHE_COMMIT_ATTEMPTS {
            if let Some(current) = &generation
                && let Ok(current_modified) = validate_osv_document(&current.value, Some(id))
                    .map(|document| document.modified)
                && current_modified >= candidate_modified
            {
                return Ok(PublishedHydration {
                    value: current.value.clone(),
                    reusable: self.cache.policy.read && current.fresh,
                });
            }
            match self
                .cache
                .put_if_unchanged(
                    "osv/vuln",
                    cache_key,
                    generation.clone(),
                    value,
                    etag.clone(),
                    ttl,
                )
                .await?
            {
                CacheCommit::Written => {
                    return Ok(PublishedHydration {
                        value: value.clone(),
                        reusable: candidate_reusable,
                    });
                }
                CacheCommit::Conflict(current) => generation = current,
            }
        }
        Err(ProviderError::Cache(format!(
            "OSV hydration cache entry for {id} changed repeatedly during publication"
        )))
    }
    pub(crate) async fn hydrate(
        &self,
        revision: &OsvVulnerabilityRevision,
    ) -> Result<HydratedDocument, ProviderError> {
        let cache_key = revision.cache_key();
        if let Some((value, _)) = self
            .cache
            .get_if_fresh("osv/vuln", &cache_key, Duration::hours(24 * 3650))
            .await
        {
            match validate_osv_document(&value, Some(&revision.id)) {
                Ok(document) if document.modified >= revision.modified => {
                    return Ok(HydratedDocument {
                        value,
                        cache_warning: None,
                    });
                }
                Ok(_) => debug!(
                    id = %revision.id,
                    "ignoring hydrated OSV cache entry older than its query revision"
                ),
                Err(error) => debug!(
                    id = %revision.id,
                    %error,
                    "ignoring invalid hydrated OSV cache entry"
                ),
            }
        }
        let _permit = self
            .concurrency
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let url = format!("{}/v1/vulns/{}", self.base_url, revision.id);
        let (value, etag) = self.http.get_json(&url, HeaderMap::new()).await?;
        let actual_modified = validate_osv_document(&value, Some(&revision.id))?.modified;
        if actual_modified < revision.modified {
            return Err(ProviderError::InvalidResponse(format!(
                "OSV hydration for {} is older than query revision {}",
                revision.id, revision.modified
            )));
        }
        let actual_revision = OsvVulnerabilityRevision {
            id: revision.id.clone(),
            modified: actual_modified,
        };
        let mut published = match self
            .publish_hydrated_document(
                &actual_revision.cache_key(),
                &revision.id,
                &value,
                etag,
                true,
            )
            .await
        {
            Ok(published) => published,
            Err(error) => {
                return Ok(HydratedDocument {
                    value,
                    cache_warning: Some(error),
                });
            }
        };
        if actual_revision != *revision {
            published = match self
                .publish_hydrated_document(
                    &cache_key,
                    &revision.id,
                    &published.value,
                    None,
                    published.reusable,
                )
                .await
            {
                Ok(published) => published,
                Err(error) => {
                    let value = if self.cache.policy.read && published.reusable {
                        published.value
                    } else {
                        value
                    };
                    return Ok(HydratedDocument {
                        value,
                        cache_warning: Some(error),
                    });
                }
            };
        }
        let value = if self.cache.policy.read && published.reusable {
            published.value
        } else {
            value
        };
        Ok(HydratedDocument {
            value,
            cache_warning: None,
        })
    }
}

pub(crate) fn record_osv_failure(
    errors: &mut HashMap<String, Vec<EnrichError>>,
    first_failure: &mut Option<ProviderError>,
    package_key: &str,
    context: &str,
    error: ProviderError,
) {
    if first_failure.is_none() {
        *first_failure = Some(error.clone());
    }
    record_osv_warning(errors, package_key, context, error);
}

pub(crate) fn record_osv_warning(
    errors: &mut HashMap<String, Vec<EnrichError>>,
    package_key: &str,
    context: &str,
    error: ProviderError,
) {
    errors
        .entry(package_key.to_owned())
        .or_default()
        .push(EnrichError {
            provider: "osv".to_owned(),
            message: format!("{context}: {error}"),
        });
}
