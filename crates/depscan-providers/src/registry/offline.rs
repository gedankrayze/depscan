use super::*;

#[derive(Clone, Debug)]
pub struct RegistryOffline {
    pub(crate) cache: Cache,
    pub(crate) now: DateTime<Utc>,
}

impl RegistryOffline {
    pub fn new(cache: Cache) -> Self {
        Self {
            cache,
            now: Utc::now(),
        }
    }

    pub(crate) fn cache_key(package: &Package) -> String {
        match package.ecosystem {
            Ecosystem::Npm => format!("npm:{}", package.name),
            Ecosystem::PyPI => format!("pypi:{}", package.name),
            Ecosystem::NuGet => nuget_registry_cache_key(package),
            Ecosystem::CratesIo => format!("crates:{}", package.name),
        }
    }

    pub(crate) fn cached_value_at(
        &self,
        package: &Package,
        now: DateTime<Utc>,
    ) -> Result<Value, ProviderError> {
        let key = Self::cache_key(package);
        if !self.cache.policy.read {
            return Err(ProviderError::Offline(format!(
                "registry metadata for {} is unknown because cache reads are disabled by --no-cache",
                package.display_name
            )));
        }
        let path = self.cache.filename("registry", &key);
        let namespace = path.parent().expect("registry cache path has a parent");
        let namespace_metadata = fs::symlink_metadata(namespace).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ProviderError::Offline(format!(
                    "registry metadata for {} is unknown because no cached entry exists",
                    package.display_name
                ))
            } else {
                ProviderError::Offline(format!(
                    "registry metadata for {} is unknown because the cache namespace cannot be inspected: {error}",
                    package.display_name
                ))
            }
        })?;
        if namespace_metadata.file_type().is_symlink() || !namespace_metadata.is_dir() {
            return Err(ProviderError::Offline(format!(
                "registry metadata for {} is unknown because the cache namespace is not a real directory",
                package.display_name
            )));
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ProviderError::Offline(format!(
                    "registry metadata for {} is unknown because no cached entry exists",
                    package.display_name
                ))
            } else {
                ProviderError::Offline(format!(
                    "registry metadata for {} is unknown because the cached entry cannot be inspected: {error}",
                    package.display_name
                ))
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ProviderError::Offline(format!(
                "registry metadata for {} is unknown because the cached entry is not a real regular file",
                package.display_name
            )));
        }
        let raw = fs::read_to_string(&path).map_err(|error| {
            ProviderError::Offline(format!(
                "registry metadata for {} is unknown because the cached entry cannot be read: {error}",
                package.display_name
            ))
        })?;
        let entry = serde_json::from_str::<CacheEntry>(&raw).map_err(|error| {
            ProviderError::Offline(format!(
                "registry metadata for {} is unknown because the cached entry is corrupt: {error}",
                package.display_name
            ))
        })?;
        if entry.stored_at > now {
            return Err(ProviderError::Offline(format!(
                "registry metadata for {} is unknown because its cache timestamp is in the future ({} > {})",
                package.display_name, entry.stored_at, now
            )));
        }
        let age = now - entry.stored_at;
        let max_age = self
            .cache
            .policy
            .max_age
            .unwrap_or_else(|| Duration::seconds(REGISTRY_TTL_SECS));
        if age > max_age {
            return Err(ProviderError::Offline(format!(
                "registry metadata for {} is unknown because the cached entry is stale ({} seconds old; maximum {} seconds)",
                package.display_name,
                age.num_seconds(),
                max_age.num_seconds()
            )));
        }
        Ok(entry.value)
    }

    pub(crate) fn latest_at(
        &self,
        package: &Package,
        now: DateTime<Utc>,
    ) -> Result<LatestVersions, ProviderError> {
        let value = self.cached_value_at(package, now)?;
        let result = (|| -> Result<LatestVersions, ProviderError> {
            match package.ecosystem {
                Ecosystem::Npm => npm_version_result(package, &value),
                Ecosystem::PyPI => pypi_version_result(package, &value),
                Ecosystem::NuGet => nuget_version_result(package, &value),
                Ecosystem::CratesIo => {
                    let cached =
                        serde_json::from_value::<CratesIndexCache>(value).map_err(|error| {
                            ProviderError::InvalidResponse(format!(
                                "cached crates.io sparse index has an invalid envelope: {error}"
                            ))
                        })?;
                    if cached.schema_version != CRATES_IO_INDEX_CACHE_SCHEMA_VERSION {
                        return Err(ProviderError::InvalidResponse(format!(
                            "cached crates.io schema version {} is unsupported",
                            cached.schema_version
                        )));
                    }
                    validate_crates_index_entries(
                        cached
                            .entries
                            .iter()
                            .enumerate()
                            .map(|(index, entry)| (index + 1, entry)),
                        &package.name,
                        "cached crates.io sparse index",
                    )?;
                    crates_version_result(package, &cached.entries)
                }
            }
        })();
        result.map_err(|error| {
            ProviderError::Offline(format!(
                "registry metadata for {} is unknown because the cached entry is invalid: {error}",
                package.display_name
            ))
        })
    }
}

#[async_trait]
impl VersionProvider for RegistryOffline {
    async fn latest(&self, package: &Package) -> Result<RegistryEnrichment, ProviderError> {
        let this = self.clone();
        let package = package.clone();
        tokio::task::spawn_blocking(move || this.latest_at(&package, this.now))
            .await
            .map_err(|error| ProviderError::Offline(error.to_string()))?
            .map(RegistryEnrichment::versions_only)
    }
}
