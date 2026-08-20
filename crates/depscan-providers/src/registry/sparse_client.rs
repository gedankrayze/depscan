use super::*;

// crates.io sparse-index entries are newline-delimited JSON. Decode and validate the entire
// response before writing the versioned cache envelope, so a truncated response cannot be reused.
impl RegistryClient {
    pub(crate) async fn crates_metadata_for_index(
        &self,
        key: &str,
        expected_name: &str,
        url: &str,
    ) -> Result<Vec<CratesIndexEntry>, ProviderError> {
        let ttl = Duration::seconds(REGISTRY_TTL_SECS);
        let mut generation = self.cache.snapshot("registry", key, ttl);
        let mut force_revalidate = false;
        for _ in 0..CACHE_COMMIT_ATTEMPTS {
            let cached = self.cache.policy.read.then(|| {
                generation
                    .as_ref()
                    .and_then(|entry| validated_cached_crates_index(entry, expected_name))
            });
            let cached = cached.flatten();
            if !force_revalidate
                && let (Some(entry), Some(cached)) = (&generation, &cached)
                && entry.fresh
            {
                return Ok(cached.entries.clone());
            }
            force_revalidate = false;
            if cached.is_none() && generation.is_some() && self.cache.policy.read {
                debug!(%key, "ignoring legacy or invalid crates.io sparse-index cache entry");
            }
            let mut headers = HeaderMap::new();
            let conditional =
                add_if_none_match(&mut headers, cached.as_ref().and(generation.as_ref()));
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
                    match self.cache.put_if_unchanged(
                        "registry",
                        key,
                        generation.as_ref(),
                        &value,
                        etag,
                        ttl,
                    )? {
                        CacheCommit::Written => return Ok(entries),
                        CacheCommit::Conflict(current) => {
                            generation = current;
                            force_revalidate = true;
                        }
                    }
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
                    let snapshot = generation.as_ref().expect("conditional cache exists");
                    let value = snapshot.value.clone();
                    let etag = etag.or_else(|| snapshot.etag.clone());
                    match self.cache.put_if_unchanged(
                        "registry",
                        key,
                        Some(snapshot),
                        &value,
                        etag,
                        ttl,
                    )? {
                        CacheCommit::Written => return Ok(cached.entries),
                        CacheCommit::Conflict(current) => {
                            generation = current;
                            if self.cache.policy.read
                                && let Some(entry) = &generation
                                && entry.fresh
                                && let Some(current) =
                                    validated_cached_crates_index(entry, expected_name)
                            {
                                return Ok(current.entries);
                            }
                        }
                    }
                }
            }
        }
        Err(ProviderError::Cache(format!(
            "crates.io cache entry {key:?} changed repeatedly during revalidation"
        )))
    }
}
