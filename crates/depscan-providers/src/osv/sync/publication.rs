use super::*;

pub(crate) struct CapabilityPersistError {
    pub(crate) source: std::io::Error,
    pub(crate) temporary: CapabilityTempFile,
}

pub(crate) fn persist_capability_temp(
    temporary: CapabilityTempFile,
    target: &OsStr,
) -> Result<(), ProviderError> {
    match temporary.persist(target) {
        Ok(()) => Ok(()),
        Err(error) => {
            let source = error.source.to_string();
            drop(error.temporary);
            Err(ProviderError::Cache(source))
        }
    }
}

pub(crate) fn cleanup_abandoned_osv_temps(
    directory: &OfflineDirectory,
    ecosystem_slug: &str,
) -> Result<(), ProviderError> {
    let prefix = format!(".{ecosystem_slug}-");
    let entries = directory.directory.entries().map_err(|error| {
        cache_path_error(
            &directory.path,
            format_args!("cannot inspect offline namespace: {error}"),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            cache_path_error(
                &directory.path,
                format_args!("cannot inspect offline namespace: {error}"),
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&prefix)
            || !OSV_DUMP_TEMP_SUFFIXES
                .iter()
                .any(|suffix| name.ends_with(suffix))
        {
            continue;
        }
        let metadata = directory
            .directory
            .symlink_metadata(name)
            .map_err(|error| {
                cache_path_error(
                    &directory.path,
                    format_args!("cannot inspect abandoned temporary file {name:?}: {error}"),
                )
            })?;
        if metadata.is_dir() || (!metadata.is_file() && !metadata.is_symlink()) {
            return Err(cache_path_error(
                &directory.path,
                format_args!("refusing non-file abandoned temporary path {name:?}"),
            ));
        }
        directory.directory.remove_file(name).map_err(|error| {
            cache_path_error(
                &directory.path,
                format_args!("cannot remove abandoned temporary file {name:?}: {error}"),
            )
        })?;
    }
    Ok(())
}

pub(crate) fn acquire_osv_sync_lock(
    root: &Path,
    ecosystem_slug: &str,
) -> Result<(OfflineDirectory, File), ProviderError> {
    acquire_osv_sync_lock_with(root, ecosystem_slug, || {}, || {})
}

pub(crate) fn acquire_osv_sync_lock_with(
    root: &Path,
    ecosystem_slug: &str,
    before_lock_open: impl FnOnce(),
    before_cleanup: impl FnOnce(),
) -> Result<(OfflineDirectory, File), ProviderError> {
    let directory = OfflineDirectory::open(root)?;
    let lock_name = OsString::from(format!(".{ecosystem_slug}.sync.lock"));
    let lock_path = directory.display_path(&lock_name);
    if let Ok(metadata) = directory.directory.symlink_metadata(&lock_name)
        && (metadata.is_symlink() || !metadata.is_file())
    {
        return Err(cache_path_error(
            &lock_path,
            "sync lock is not a regular file",
        ));
    }
    before_lock_open();
    let mut options = CapOpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .follow(FollowSymlinks::No);
    let lock = directory
        .directory
        .open_with(&lock_name, &options)
        .map_err(|error| {
            cache_path_error(&lock_path, format_args!("cannot open sync lock: {error}"))
        })?
        .into_std();
    if !lock.metadata().is_ok_and(|value| value.is_file()) {
        return Err(cache_path_error(
            &lock_path,
            "sync lock is not a regular file",
        ));
    }
    lock.lock_exclusive().map_err(|error| {
        cache_path_error(
            &lock_path,
            format_args!("cannot acquire sync lock: {error}"),
        )
    })?;
    directory.revalidate()?;
    before_cleanup();
    cleanup_abandoned_osv_temps(&directory, ecosystem_slug)?;
    directory.revalidate()?;
    Ok((directory, lock))
}

pub(crate) fn validate_marker_target(
    directory: &OfflineDirectory,
    name: &OsStr,
) -> Result<(), ProviderError> {
    let path = directory.display_path(name);
    match directory.directory.symlink_metadata(name) {
        Ok(metadata) if metadata.is_symlink() || !metadata.is_file() => Err(ProviderError::Cache(
            format!("cannot replace non-file sync marker {}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ProviderError::Cache(error.to_string())),
    }
}

pub(crate) fn stage_previous_archive(
    directory: &OfflineDirectory,
    archive_name: &OsStr,
    temp_prefix: &str,
) -> Result<Option<CapabilityTempFile>, ProviderError> {
    let path = directory.display_path(archive_name);
    let Some(mut source) =
        open_capability_regular_file(&directory.directory, archive_name, &path, false)?
    else {
        return Ok(None);
    };
    let source_identity = std_file_identity(&source, &path)?;
    let mut link_error = None;
    for _ in 0..128 {
        let candidate = OsString::from(format!(
            "{temp_prefix}{:016x}.zip.rollback.tmp",
            rand::rng().random::<u64>()
        ));
        match directory
            .directory
            .hard_link(archive_name, &directory.directory, &candidate)
        {
            Ok(()) => {
                let backup = match CapabilityTempFile::from_link(directory, candidate.clone()) {
                    Ok(backup) => backup,
                    Err(error) => {
                        let _ = directory.directory.remove_file(candidate);
                        return Err(error);
                    }
                };
                if std_file_identity(backup.as_file(), &backup.logical_path())? == source_identity {
                    return Ok(Some(backup));
                }
                drop(backup);
                link_error = Some("archive changed while creating the hard link".to_owned());
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                link_error = Some(error.to_string());
                break;
            }
        }
    }
    let link_error =
        link_error.unwrap_or_else(|| "could not allocate a unique hard-link name".to_owned());
    let expected_bytes = source
        .metadata()
        .map_err(|error| ProviderError::Cache(error.to_string()))?
        .len();
    let source_permissions = source
        .metadata()
        .map_err(|error| ProviderError::Cache(error.to_string()))?
        .permissions();
    let mut backup = CapabilityTempFile::new(directory, temp_prefix, ".zip.rollback.tmp").map_err(
        |copy_error| {
            ProviderError::Cache(format!(
                "cannot stage {} for rollback (hard link: {link_error}; copy: {copy_error})",
                path.display()
            ))
        },
    )?;
    let copied_bytes = std::io::copy(&mut source, backup.as_file_mut())
        .and_then(|bytes| {
            backup.as_file().set_permissions(source_permissions)?;
            backup.as_file().sync_all().map(|()| bytes)
        })
        .map_err(|copy_error| {
            ProviderError::Cache(format!(
                "cannot stage {} for rollback (hard link: {link_error}; copy: {copy_error})",
                path.display()
            ))
        })?;
    if copied_bytes != expected_bytes {
        return Err(ProviderError::Cache(format!(
            "cannot stage {} for rollback: copied {copied_bytes} of {expected_bytes} bytes",
            path.display()
        )));
    }
    Ok(Some(backup))
}

pub(crate) fn restore_previous_archive(
    directory: &OfflineDirectory,
    previous: Option<CapabilityTempFile>,
    archive_name: &OsStr,
) -> Result<(), ProviderError> {
    let Some(previous) = previous else {
        return match directory.directory.remove_file(archive_name) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ProviderError::Cache(error.to_string())),
        };
    };
    match previous.persist(archive_name) {
        Ok(()) => Ok(()),
        Err(error) => {
            let restore_error = error.source;
            let recovery_path = error.temporary.retain();
            Err(ProviderError::Cache(format!(
                "{restore_error}; rollback copy retained at {}",
                recovery_path.display()
            )))
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct OsvPairNames<'a> {
    pub(crate) archive: &'a OsStr,
    pub(crate) marker: &'a OsStr,
}

pub(crate) fn publish_osv_pair_with<F>(
    directory: &OfflineDirectory,
    archive_temp: CapabilityTempFile,
    marker_temp: CapabilityTempFile,
    names: OsvPairNames<'_>,
    previous_archive: Option<CapabilityTempFile>,
    before_archive: impl FnOnce() -> Result<(), ProviderError>,
    publish_marker: F,
) -> Result<(), ProviderError>
where
    F: FnOnce(CapabilityTempFile, &OsStr) -> Result<(), ProviderError>,
{
    let archive_path = directory.display_path(names.archive);
    let marker_path = directory.display_path(names.marker);
    before_archive()?;
    if let Err(error) = archive_temp.persist(names.archive) {
        let publication_error = error.source.to_string();
        drop(error.temporary);
        return Err(ProviderError::Cache(format!(
            "replacing {}: {publication_error}",
            archive_path.display()
        )));
    }
    if let Err(error) = publish_marker(marker_temp, names.marker) {
        let publication_error = error.to_string();
        restore_previous_archive(directory, previous_archive, names.archive).map_err(|rollback_error| {
            ProviderError::Cache(format!(
                "replacing {} failed: {publication_error}; restoring {} also failed: {rollback_error}",
                marker_path.display(),
                archive_path.display()
            ))
        })?;
        return Err(ProviderError::Cache(format!(
            "replacing {} failed: {publication_error}; restored previous archive",
            marker_path.display()
        )));
    }
    drop(previous_archive);
    Ok(())
}

pub(crate) fn publish_osv_pair(
    directory: &OfflineDirectory,
    archive_temp: CapabilityTempFile,
    marker_temp: CapabilityTempFile,
    archive_name: &OsStr,
    marker_name: &OsStr,
    previous_archive: Option<CapabilityTempFile>,
    _config: &OsvSyncConfig,
) -> Result<(), ProviderError> {
    publish_osv_pair_with(
        directory,
        archive_temp,
        marker_temp,
        OsvPairNames {
            archive: archive_name,
            marker: marker_name,
        },
        previous_archive,
        || {
            #[cfg(test)]
            _config.reach_boundary(OsvSyncBoundary::BeforeArchivePublication);
            directory.revalidate()
        },
        |temporary, target| {
            #[cfg(test)]
            _config.reach_boundary(OsvSyncBoundary::BeforeMarkerPublication);
            directory.revalidate()?;
            persist_capability_temp(temporary, target)
        },
    )
}
