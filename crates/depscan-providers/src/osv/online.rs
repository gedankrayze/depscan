use super::*;

#[async_trait]
impl VulnProvider for OsvClient {
    async fn query(&self, packages: &[Package]) -> Result<VulnQueryOutcome, ProviderError> {
        let query_ttl = Duration::seconds(OSV_QUERY_TTL_SECS);
        let mut revisions_by_package = HashMap::<String, Vec<OsvVulnerabilityRevision>>::new();
        let mut errors = HashMap::<String, Vec<EnrichError>>::new();
        let mut first_failure = None;
        let mut missing = Vec::new();
        let eligible = packages
            .iter()
            .filter(|p| p.enrichable && !p.resolved_from_range)
            .collect::<Vec<_>>();
        let eligible_count = eligible.len();
        for package in eligible.iter().copied() {
            let query_cache_key = osv_query_cache_key(package);
            let generation = self
                .cache
                .snapshot("osv/query", &query_cache_key, query_ttl)
                .await;
            if self.cache.policy.read
                && let Some(cached) = &generation
                && cached.fresh
            {
                if let Some(revisions) = canonical_osv_revisions(cached.value.clone()) {
                    revisions_by_package.insert(package.key(), revisions);
                } else {
                    debug!(
                        package = %package.display_name,
                        "ignoring legacy or invalid OSV query cache entry"
                    );
                    missing.push((package.clone(), generation, true));
                }
            } else {
                missing.push((package.clone(), generation, self.cache.policy.read));
            }
        }

        // A cache-commit conflict deliberately re-queries the batch (bounded by
        // CACHE_COMMIT_ATTEMPTS) instead of converging locally: the re-query re-enforces the
        // revision-regression check against the server rather than trusting a concurrent local
        // write, and the concurrent-refresh race tests pin that behavior. Batch queries make the
        // bounded extra round-trips cheap relative to the per-package registry paths.
        for _ in 0..CACHE_COMMIT_ATTEMPTS {
            if missing.is_empty() {
                break;
            }
            let mut conflicts = Vec::new();
            for chunk in missing.chunks(1000) {
                let batch = chunk
                    .iter()
                    .map(|(package, _, _)| package.clone())
                    .collect::<Vec<_>>();
                let lists = self.query_batch_outcomes(&batch).await;
                for ((package, generation, enforce_regression), outcome) in
                    chunk.iter().cloned().zip(lists)
                {
                    let revisions = match outcome {
                        Ok(revisions) => revisions,
                        Err(error) => {
                            record_osv_failure(
                                &mut errors,
                                &mut first_failure,
                                &package.key(),
                                "query failed",
                                error,
                            );
                            continue;
                        }
                    };
                    if let Some(previous) = enforce_regression
                        .then(|| {
                            generation
                                .as_ref()
                                .and_then(|entry| canonical_osv_revisions(entry.value.clone()))
                        })
                        .flatten()
                    {
                        let next = revisions
                            .iter()
                            .map(|revision| (revision.id.as_str(), revision.modified))
                            .collect::<HashMap<_, _>>();
                        if let Some(regressed) = previous.iter().find(|revision| {
                            next.get(revision.id.as_str())
                                .is_some_and(|modified| *modified < revision.modified)
                        }) {
                            let error = ProviderError::InvalidResponse(format!(
                                "OSV query revision for {} regressed below {}",
                                regressed.id, regressed.modified
                            ));
                            record_osv_failure(
                                &mut errors,
                                &mut first_failure,
                                &package.key(),
                                "query failed",
                                error,
                            );
                            continue;
                        }
                    }
                    let package_key = package.key();
                    revisions_by_package.insert(package_key.clone(), revisions.clone());
                    let value = match serde_json::to_value(&revisions) {
                        Ok(value) => value,
                        Err(error) => {
                            record_osv_warning(
                                &mut errors,
                                &package_key,
                                "query cache serialization failed",
                                ProviderError::Cache(error.to_string()),
                            );
                            continue;
                        }
                    };
                    match self
                        .cache
                        .put_if_unchanged(
                            "osv/query",
                            &osv_query_cache_key(&package),
                            generation,
                            &value,
                            None,
                            query_ttl,
                        )
                        .await
                    {
                        Ok(CacheCommit::Written) => {
                            // The validated network result was already retained for this scan.
                        }
                        Ok(CacheCommit::Conflict(current)) => {
                            if self.cache.policy.read
                                && let Some(current) = &current
                                && current.fresh
                                && let Some(winner) = canonical_osv_revisions(current.value.clone())
                            {
                                revisions_by_package.insert(package_key, winner);
                            }
                            conflicts.push((package, current, true));
                        }
                        Err(error) => record_osv_warning(
                            &mut errors,
                            &package.key(),
                            "query cache publication failed",
                            error,
                        ),
                    }
                }
            }
            missing = conflicts;
        }
        if !missing.is_empty() {
            for (package, _, _) in missing {
                record_osv_warning(
                    &mut errors,
                    &package.key(),
                    "query cache publication failed",
                    ProviderError::Cache(
                        "OSV query cache changed repeatedly during refresh".to_owned(),
                    ),
                );
            }
        }

        // A provider error is hard only when no eligible package produced a complete query from
        // either a fresh cache entry or the network. Any completed query (including a legitimate
        // empty result) makes failures for other packages soft and visible in the outcome.
        if eligible_count > 0 && revisions_by_package.is_empty() {
            return Err(first_failure.unwrap_or_else(|| {
                ProviderError::InvalidResponse(
                    "OSV returned no usable result for any eligible package".to_owned(),
                )
            }));
        }

        let mut latest_revisions = BTreeMap::<String, OsvVulnerabilityRevision>::new();
        for revisions in revisions_by_package.values() {
            for revision in revisions {
                latest_revisions
                    .entry(revision.id.clone())
                    .and_modify(|current| {
                        if revision.modified > current.modified {
                            *current = revision.clone();
                        }
                    })
                    .or_insert_with(|| revision.clone());
            }
        }
        let hydrated = stream::iter(latest_revisions.into_values().map(|revision| {
            let client = self.clone();
            async move {
                let id = revision.id.clone();
                (id, client.hydrate(&revision).await)
            }
        }))
        .buffer_unordered(16)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<HashMap<_, _>>();

        let mut vulnerabilities = VulnMap::new();
        let mut usable_packages = 0usize;
        for package in eligible {
            let key = package.key();
            let Some(revisions) = revisions_by_package.get(&key) else {
                continue;
            };
            let mut evaluated = Vec::with_capacity(revisions.len());
            let mut successful_evaluations = 0usize;
            for revision in revisions {
                let Some(document) = hydrated.get(&revision.id) else {
                    record_osv_failure(
                        &mut errors,
                        &mut first_failure,
                        &key,
                        &format!("advisory {} hydration failed", revision.id),
                        ProviderError::InvalidResponse(format!(
                            "OSV advisory {} has no hydration outcome",
                            revision.id
                        )),
                    );
                    continue;
                };
                let document = match document {
                    Ok(document) => document,
                    Err(error) => {
                        record_osv_failure(
                            &mut errors,
                            &mut first_failure,
                            &key,
                            &format!("advisory {} hydration failed", revision.id),
                            error.clone(),
                        );
                        continue;
                    }
                };
                if let Some(error) = &document.cache_warning {
                    record_osv_warning(
                        &mut errors,
                        &key,
                        &format!("advisory {} cache publication failed", revision.id),
                        error.clone(),
                    );
                }
                match vulnerability_from_osv_query_hit(&document.value, package) {
                    Ok(Some(vulnerability)) => {
                        successful_evaluations += 1;
                        evaluated.push(vulnerability);
                    }
                    Ok(None) => successful_evaluations += 1,
                    Err(error) => record_osv_failure(
                        &mut errors,
                        &mut first_failure,
                        &key,
                        &format!("advisory {} evaluation failed", revision.id),
                        error,
                    ),
                }
            }
            if revisions.is_empty() || successful_evaluations > 0 {
                usable_packages += 1;
            }
            vulnerabilities.insert(key, evaluated);
        }

        // A package with only failed advisory hydrations/evaluations has no trustworthy
        // vulnerability result. If that is true for every completed query, the provider is wholly
        // unusable and must retain the hard-failure exit path.
        if eligible_count > 0 && usable_packages == 0 {
            return Err(first_failure.unwrap_or_else(|| {
                ProviderError::InvalidResponse(
                    "OSV returned no usable vulnerability result for any eligible package"
                        .to_owned(),
                )
            }));
        }
        Ok(VulnQueryOutcome {
            vulnerabilities,
            errors,
        })
    }
}
