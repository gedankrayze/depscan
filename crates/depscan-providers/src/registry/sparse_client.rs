use super::*;

// crates.io sparse-index entries are newline-delimited JSON. Decode and validate the entire
// response before writing the versioned cache envelope, so a truncated response cannot be reused.
//
// With cache reads enabled, one logical lookup performs at most one network fetch (the HTTP
// client's DS-031 retry policy applies inside it); cache-commit conflicts are resolved locally
// by adopting a fresh, valid concurrent winner or retrying the commit of our validated result.
// Under --no-cache the winner can be neither served nor clobbered with an older response, so
// each conflict refetches instead — bounded by the same commit-attempt budget.
impl RegistryClient {
    pub(crate) async fn crates_metadata_for_index(
        &self,
        key: &str,
        expected_name: &str,
        url: &str,
    ) -> Result<Vec<CratesIndexEntry>, ProviderError> {
        let ttl = Duration::seconds(REGISTRY_TTL_SECS);
        let mut generation = self.cache.snapshot("registry", key, ttl).await;
        let cached = self
            .cache
            .policy
            .read
            .then(|| {
                generation
                    .as_ref()
                    .and_then(|entry| validated_cached_crates_index(entry, expected_name))
            })
            .flatten();
        if let (Some(entry), Some(cached)) = (&generation, &cached)
            && entry.fresh
        {
            return Ok(cached.entries.clone());
        }
        if cached.is_none() && generation.is_some() && self.cache.policy.read {
            debug!(%key, "ignoring legacy or invalid crates.io sparse-index cache entry");
        }
        let (mut entries, mut value, mut etag) = self
            .fetch_crates_index(url, expected_name, cached, generation.as_ref())
            .await?;
        for _ in 0..CACHE_COMMIT_ATTEMPTS {
            match self
                .cache
                .put_if_unchanged(
                    "registry",
                    key,
                    generation.clone(),
                    &value,
                    etag.clone(),
                    ttl,
                )
                .await?
            {
                CacheCommit::Written => return Ok(entries),
                CacheCommit::Conflict(current) => {
                    generation = current;
                    if self.cache.policy.read {
                        if let Some(entry) = &generation
                            && entry.fresh
                            && let Some(current) =
                                validated_cached_crates_index(entry, expected_name)
                        {
                            return Ok(current.entries);
                        }
                    } else {
                        (entries, value, etag) = self
                            .fetch_crates_index(url, expected_name, None, None)
                            .await?;
                    }
                }
            }
        }
        Err(ProviderError::Cache(format!(
            "crates.io cache entry {key:?} changed repeatedly during publication"
        )))
    }

    async fn fetch_crates_index(
        &self,
        url: &str,
        expected_name: &str,
        cached: Option<CratesIndexCache>,
        snapshot: Option<&CacheLookup>,
    ) -> Result<(Vec<CratesIndexEntry>, Value, Option<String>), ProviderError> {
        let mut headers = HeaderMap::new();
        let conditional = add_if_none_match(&mut headers, cached.as_ref().and(snapshot));
        let response = self
            .http
            .get_bytes_limited_revalidated(url, CRATES_IO_MAX_INDEX_RESPONSE_BYTES, headers)
            .await?;
        match response {
            Revalidated::Modified { value: bytes, etag } => {
                let entries = decode_crates_index(&bytes, expected_name, url)?;
                let value = serde_json::to_value(CratesIndexCache {
                    schema_version: CRATES_IO_INDEX_CACHE_SCHEMA_VERSION,
                    entries: entries.clone(),
                })
                .map_err(|error| ProviderError::Cache(error.to_string()))?;
                Ok((entries, value, etag))
            }
            Revalidated::NotModified { etag } => {
                if !conditional {
                    return Err(ProviderError::InvalidResponse(format!(
                        "{url}: received HTTP 304 without sending If-None-Match"
                    )));
                }
                let cached = cached.ok_or_else(|| {
                    ProviderError::InvalidResponse(format!(
                        "{url}: received HTTP 304 without a valid cached sparse index"
                    ))
                })?;
                let snapshot = snapshot.expect("conditional cache exists");
                let value = snapshot.value.clone();
                let etag = etag.or_else(|| snapshot.etag.clone());
                Ok((cached.entries, value, etag))
            }
        }
    }
}
