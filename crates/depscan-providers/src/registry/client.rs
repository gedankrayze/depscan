use super::*;

// One semaphore per ecosystem; the match in `semaphore` makes a new `Ecosystem` variant a
// compile error here instead of a runtime lookup panic.
pub(crate) struct RegistryLimits {
    npm: Semaphore,
    pypi: Semaphore,
    nuget: Semaphore,
    crates_io: Semaphore,
}

impl RegistryLimits {
    fn new() -> Self {
        Self {
            npm: Semaphore::new(16),
            pypi: Semaphore::new(16),
            nuget: Semaphore::new(16),
            crates_io: Semaphore::new(8),
        }
    }

    pub(crate) fn semaphore(&self, ecosystem: Ecosystem) -> &Semaphore {
        match ecosystem {
            Ecosystem::Npm => &self.npm,
            Ecosystem::PyPI => &self.pypi,
            Ecosystem::NuGet => &self.nuget,
            Ecosystem::CratesIo => &self.crates_io,
        }
    }
}

#[derive(Clone)]
pub struct RegistryClient {
    pub(crate) http: HttpClient,
    pub(crate) cache: Cache,
    pub(crate) limits: Arc<RegistryLimits>,
    pub(crate) npm_base_url: String,
    pub(crate) pypi_base_url: String,
    pub(crate) nuget_base_url: String,
    pub(crate) nuget_registration_base_url: String,
    pub(crate) crates_index_base_url: String,
}
impl RegistryClient {
    pub fn new(http: HttpClient, cache: Cache) -> Self {
        Self::with_registry_base_urls(
            http,
            cache,
            NPM_REGISTRY_BASE_URL,
            PYPI_REGISTRY_BASE_URL,
            NUGET_REGISTRY_BASE_URL,
            NUGET_REGISTRATION_BASE_URL,
            CRATES_IO_INDEX_BASE_URL,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_crates_index_base_url(
        http: HttpClient,
        cache: Cache,
        crates_index_base_url: impl Into<String>,
    ) -> Self {
        Self::with_registry_base_urls(
            http,
            cache,
            NPM_REGISTRY_BASE_URL,
            PYPI_REGISTRY_BASE_URL,
            NUGET_REGISTRY_BASE_URL,
            NUGET_REGISTRATION_BASE_URL,
            crates_index_base_url,
        )
    }

    pub(crate) fn with_registry_base_urls(
        http: HttpClient,
        cache: Cache,
        npm_base_url: impl Into<String>,
        pypi_base_url: impl Into<String>,
        nuget_base_url: impl Into<String>,
        nuget_registration_base_url: impl Into<String>,
        crates_index_base_url: impl Into<String>,
    ) -> Self {
        Self {
            http,
            cache,
            limits: Arc::new(RegistryLimits::new()),
            npm_base_url: npm_base_url.into().trim_end_matches('/').to_owned(),
            pypi_base_url: pypi_base_url.into().trim_end_matches('/').to_owned(),
            nuget_base_url: nuget_base_url.into().trim_end_matches('/').to_owned(),
            nuget_registration_base_url: nuget_registration_base_url
                .into()
                .trim_end_matches('/')
                .to_owned(),
            crates_index_base_url: crates_index_base_url
                .into()
                .trim_end_matches('/')
                .to_owned(),
        }
    }
    pub(crate) async fn metadata(
        &self,
        namespace: &str,
        url: &str,
        headers: HeaderMap,
    ) -> Result<Value, ProviderError> {
        self.metadata_with_limit(namespace, url, headers, None)
            .await
    }

    pub(crate) async fn metadata_limited(
        &self,
        namespace: &str,
        url: &str,
        headers: HeaderMap,
        max_bytes: usize,
    ) -> Result<Value, ProviderError> {
        self.metadata_with_limit(namespace, url, headers, Some(max_bytes))
            .await
    }

    pub(crate) async fn metadata_with_limit(
        &self,
        namespace: &str,
        url: &str,
        headers: HeaderMap,
        max_bytes: Option<usize>,
    ) -> Result<Value, ProviderError> {
        let ttl = Duration::seconds(REGISTRY_TTL_SECS);
        let mut generation = self.cache.snapshot("registry", namespace, ttl).await;
        let mut cached = self.cache.policy.read.then(|| generation.clone()).flatten();
        let mut force_revalidate = false;
        for _ in 0..CACHE_COMMIT_ATTEMPTS {
            if !force_revalidate
                && let Some(cached) = &cached
                && cached.fresh
            {
                return Ok(cached.value.clone());
            }
            force_revalidate = false;
            let mut request_headers = headers.clone();
            let conditional = add_if_none_match(&mut request_headers, cached.as_ref());
            let response = if let Some(max_bytes) = max_bytes {
                self.http
                    .get_json_limited_revalidated(url, max_bytes, request_headers)
                    .await?
            } else {
                self.http.get_json_revalidated(url, request_headers).await?
            };
            match response {
                Revalidated::Modified { value, etag } => {
                    match self
                        .cache
                        .put_if_unchanged(
                            "registry",
                            namespace,
                            generation.clone(),
                            &value,
                            etag,
                            ttl,
                        )
                        .await?
                    {
                        CacheCommit::Written => return Ok(value),
                        CacheCommit::Conflict(current) => {
                            generation = current;
                            cached = self.cache.policy.read.then(|| generation.clone()).flatten();
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
                    let snapshot = cached.as_ref().ok_or_else(|| {
                        ProviderError::InvalidResponse(format!(
                            "{url}: received HTTP 304 without a cached registry value"
                        ))
                    })?;
                    let value = snapshot.value.clone();
                    let etag = etag.or_else(|| snapshot.etag.clone());
                    match self
                        .cache
                        .put_if_unchanged(
                            "registry",
                            namespace,
                            generation.clone(),
                            &value,
                            etag,
                            ttl,
                        )
                        .await?
                    {
                        CacheCommit::Written => return Ok(value),
                        CacheCommit::Conflict(Some(current)) if current.fresh => {
                            if self.cache.policy.read {
                                return Ok(current.value);
                            }
                            generation = Some(current);
                            cached = None;
                        }
                        CacheCommit::Conflict(current) => {
                            generation = current;
                            cached = self.cache.policy.read.then(|| generation.clone()).flatten();
                        }
                    }
                }
            }
        }
        Err(ProviderError::Cache(format!(
            "registry cache entry {namespace:?} changed repeatedly during revalidation"
        )))
    }

    pub(crate) async fn nuget_canonical_name(
        &self,
        package: &Package,
        target_version: &str,
    ) -> Result<String, ProviderError> {
        let index_url =
            nuget_registration_url_with_base(&self.nuget_registration_base_url, package);
        let index = self
            .metadata_limited(
                &nuget_registration_cache_key(package),
                &index_url,
                HeaderMap::new(),
                NUGET_REGISTRATION_MAX_RESPONSE_BYTES,
            )
            .await?;
        let page = match nuget_registration_page_for_version(&index, target_version)? {
            NugetRegistrationPageSource::Inline(page) => page,
            NugetRegistrationPageSource::Linked { lower, upper, url } => {
                let url = validated_nuget_registration_page_url(
                    &self.nuget_registration_base_url,
                    package,
                    &url,
                )?;
                self.metadata_limited(
                    &nuget_registration_page_cache_key(package, &lower, &upper),
                    &url,
                    HeaderMap::new(),
                    NUGET_REGISTRATION_MAX_RESPONSE_BYTES,
                )
                .await?
            }
        };
        canonical_nuget_name_from_registration_page(package, target_version, &page)
    }

    pub(crate) async fn npm(&self, p: &Package) -> Result<RegistryEnrichment, ProviderError> {
        let _permit = self
            .limits
            .semaphore(Ecosystem::Npm)
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let url = format!("{}/{}", self.npm_base_url, encode_path_segment(&p.name));
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.npm.install-v1+json"),
        );
        let data = self
            .metadata(&format!("npm:{}", p.name), &url, headers)
            .await?;
        npm_version_result(p, &data).map(RegistryEnrichment::versions_only)
    }
    pub(crate) async fn pypi(&self, p: &Package) -> Result<RegistryEnrichment, ProviderError> {
        let _permit = self
            .limits
            .semaphore(Ecosystem::PyPI)
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let url = format!(
            "{}/{}/json",
            self.pypi_base_url,
            encode_path_segment(&p.name)
        );
        let data = self
            .metadata(&format!("pypi:{}", p.name), &url, HeaderMap::new())
            .await?;
        pypi_version_result(p, &data).map(RegistryEnrichment::versions_only)
    }
    pub(crate) async fn nuget(&self, p: &Package) -> Result<RegistryEnrichment, ProviderError> {
        let _permit = self
            .limits
            .semaphore(Ecosystem::NuGet)
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let url = nuget_registry_url_with_base(&self.nuget_base_url, p);
        let cache_key = nuget_registry_cache_key(p);
        let data = self.metadata(&cache_key, &url, HeaderMap::new()).await?;
        let latest = nuget_version_result(p, &data)?;
        let target_version = latest
            .latest_matching
            .as_deref()
            .unwrap_or(p.version.as_str());
        let canonical_name = self.nuget_canonical_name(p, target_version).await?;
        Ok(RegistryEnrichment {
            latest,
            canonical_name: Some(canonical_name),
        })
    }
    pub(crate) async fn crates(&self, p: &Package) -> Result<RegistryEnrichment, ProviderError> {
        let path = crates_io_sparse_path(&p.name)?;
        let _permit = self
            .limits
            .semaphore(Ecosystem::CratesIo)
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let name = &p.name;
        let url = format!("{}/{path}", self.crates_index_base_url);
        let entries = self
            .crates_metadata_for_index(&format!("crates:{}", name), name, &url)
            .await?;
        crates_version_result(p, &entries).map(RegistryEnrichment::versions_only)
    }
}
#[async_trait]
impl VersionProvider for RegistryClient {
    async fn latest(&self, package: &Package) -> Result<RegistryEnrichment, ProviderError> {
        match package.ecosystem {
            Ecosystem::Npm => self.npm(package).await,
            Ecosystem::PyPI => self.pypi(package).await,
            Ecosystem::NuGet => self.nuget(package).await,
            Ecosystem::CratesIo => self.crates(package).await,
        }
    }
}
