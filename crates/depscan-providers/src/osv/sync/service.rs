use super::*;

pub async fn sync_osv_dumps(
    http: &HttpClient,
    cache: &Cache,
    ecosystems: &[Ecosystem],
) -> Result<Vec<PathBuf>, ProviderError> {
    sync_osv_dumps_with_options(http, cache, ecosystems, OsvSyncOptions::default()).await
}

pub async fn sync_osv_dumps_with_options(
    http: &HttpClient,
    cache: &Cache,
    ecosystems: &[Ecosystem],
    options: OsvSyncOptions,
) -> Result<Vec<PathBuf>, ProviderError> {
    let config = OsvSyncConfig::new(options)?;
    sync_osv_dumps_with_config(http, cache, ecosystems, &config).await
}

pub(crate) async fn sync_osv_dumps_with_config(
    http: &HttpClient,
    cache: &Cache,
    ecosystems: &[Ecosystem],
    config: &OsvSyncConfig,
) -> Result<Vec<PathBuf>, ProviderError> {
    let list: Vec<Ecosystem> = if ecosystems.is_empty() {
        vec![
            Ecosystem::Npm,
            Ecosystem::PyPI,
            Ecosystem::NuGet,
            Ecosystem::CratesIo,
        ]
    } else {
        ecosystems.to_vec()
    };
    let mut written = Vec::new();
    for eco in list {
        let ecosystem_slug = eco.osv_name().replace('.', "_");
        let cache_root = cache.root().to_path_buf();
        let lock_slug = ecosystem_slug.clone();
        let (dir, sync_lock) =
            tokio::task::spawn_blocking(move || acquire_osv_sync_lock(&cache_root, &lock_slug))
                .await
                .map_err(|error| {
                    ProviderError::Cache(format!(
                        "OSV sync lock task for {} failed: {error}",
                        eco.osv_name()
                    ))
                })??;
        let dir = Arc::new(dir);
        let url = format!("{}/{}/all.zip", config.base_url, eco.osv_name());
        debug!(%url, "downloading OSV dump");
        let archive_name = OsString::from(format!("{ecosystem_slug}.zip"));
        let marker_name = OsString::from(format!("{ecosystem_slug}.synced-at"));
        let path = dir.display_path(&archive_name);
        // The `dir.revalidate()` and `validate_marker_target` probes deliberately stay inline:
        // they are a bounded set of metadata syscalls on an already-open directory handle, and
        // keeping them on the async side preserves the exact boundary-hook ordering the swap
        // safety tests inject failures into. The expensive operations — temporary-file
        // creation, the marker write and fsync, and the publication rename/fsync sequence —
        // run on the blocking pool.
        validate_marker_target(&dir, &marker_name)?;
        let temp_prefix = format!(".{ecosystem_slug}-");
        let archive_temp = {
            let temp_dir = dir.clone();
            let prefix = temp_prefix.clone();
            tokio::task::spawn_blocking(move || {
                CapabilityTempFile::new(&temp_dir, &prefix, ".zip.tmp")
            })
            .await
            .map_err(|error| {
                ProviderError::Cache(format!(
                    "OSV temporary-file task for {} failed: {error}",
                    eco.osv_name()
                ))
            })??
        };
        #[cfg(test)]
        config.reach_boundary(OsvSyncBoundary::AfterTemporaryCreation);
        dir.revalidate()?;
        if let Err(error) = http
            .download_osv_dump(&url, archive_temp.as_file(), config)
            .await
        {
            #[cfg(test)]
            config.reach_boundary(OsvSyncBoundary::BeforeHandledErrorCleanup);
            dir.revalidate()?;
            return Err(error);
        }

        #[cfg(test)]
        config.reach_boundary(OsvSyncBoundary::BeforeValidation);
        dir.revalidate()?;
        let validation_file = archive_temp
            .as_file()
            .try_clone()
            .map_err(|error| ProviderError::Cache(error.to_string()))?;
        let validation_config = config.clone();
        let validation = tokio::task::spawn_blocking(move || {
            validate_osv_dump_file(validation_file, eco, &validation_config)
        })
        .await
        .map_err(|error| {
            ProviderError::InvalidResponse(format!(
                "OSV dump validation task for {} failed: {error}",
                eco.osv_name()
            ))
        })?;
        if let Err(error) = validation {
            #[cfg(test)]
            config.reach_boundary(OsvSyncBoundary::BeforeHandledErrorCleanup);
            dir.revalidate()?;
            return Err(error);
        }

        dir.revalidate()?;
        let marker_temp = {
            let marker_dir = dir.clone();
            let prefix = temp_prefix.clone();
            tokio::task::spawn_blocking(move || {
                let mut marker_temp =
                    CapabilityTempFile::new(&marker_dir, &prefix, ".synced-at.tmp")?;
                marker_temp
                    .write_all(Utc::now().to_rfc3339().as_bytes())
                    .and_then(|_| marker_temp.as_file().sync_all())
                    .map_err(|error| ProviderError::Cache(error.to_string()))?;
                Ok::<_, ProviderError>(marker_temp)
            })
            .await
            .map_err(|error| {
                ProviderError::Cache(format!(
                    "OSV marker task for {} failed: {error}",
                    eco.osv_name()
                ))
            })??
        };
        #[cfg(test)]
        config.reach_boundary(OsvSyncBoundary::BeforeRollbackStaging);
        dir.revalidate()?;
        #[cfg(test)]
        if config.force_rollback_staging_error {
            return Err(ProviderError::Cache(
                "injected rollback staging failure".to_owned(),
            ));
        }
        let stage_directory = dir.clone();
        let stage_name = archive_name.clone();
        let stage_prefix = temp_prefix.clone();
        let previous_archive = tokio::task::spawn_blocking(move || {
            stage_previous_archive(&stage_directory, &stage_name, &stage_prefix)
        })
        .await
        .map_err(|error| {
            ProviderError::Cache(format!(
                "OSV rollback staging task for {} failed: {error}",
                eco.osv_name()
            ))
        })??;

        dir.revalidate()?;
        validate_marker_target(&dir, &marker_name)?;
        {
            let publish_dir = dir.clone();
            let publish_archive_name = archive_name.clone();
            let publish_marker_name = marker_name.clone();
            let publish_config = config.clone();
            tokio::task::spawn_blocking(move || {
                publish_osv_pair(
                    &publish_dir,
                    archive_temp,
                    marker_temp,
                    &publish_archive_name,
                    &publish_marker_name,
                    previous_archive,
                    &publish_config,
                )
            })
            .await
            .map_err(|error| {
                ProviderError::Cache(format!(
                    "OSV publication task for {} failed: {error}",
                    eco.osv_name()
                ))
            })??;
        }
        dir.revalidate()?;
        let _ = fs2::FileExt::unlock(&sync_lock);
        written.push(path);
    }
    Ok(written)
}
