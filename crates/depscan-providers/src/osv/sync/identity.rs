use super::*;

pub(crate) fn capability_directory_identity(
    directory: &CapDir,
    path: &Path,
) -> Result<FileIdentity, ProviderError> {
    let file = directory
        .try_clone()
        .map_err(|error| cache_path_error(path, format_args!("cannot clone directory: {error}")))?
        .into_std_file();
    FileIdentity::from_owned_file(file)
        .map_err(|error| cache_path_error(path, format_args!("cannot identify directory: {error}")))
}

pub(crate) fn std_file_identity(file: &File, path: &Path) -> Result<FileIdentity, ProviderError> {
    let clone = file
        .try_clone()
        .map_err(|error| cache_path_error(path, format_args!("cannot clone file: {error}")))?;
    FileIdentity::from_owned_file(clone)
        .map_err(|error| cache_path_error(path, format_args!("cannot identify file: {error}")))
}

pub(crate) fn open_capability_regular_file(
    directory: &CapDir,
    name: &OsStr,
    display_path: &Path,
    write: bool,
) -> Result<Option<File>, ProviderError> {
    let metadata = match directory.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(cache_path_error(
                display_path,
                format_args!("cannot inspect file: {error}"),
            ));
        }
    };
    if metadata.is_symlink() || !metadata.is_file() {
        return Err(cache_path_error(
            display_path,
            "path is not a real regular file",
        ));
    }
    let mut options = CapOpenOptions::new();
    options.read(true).write(write).follow(FollowSymlinks::No);
    let file = directory.open_with(name, &options).map_err(|error| {
        cache_path_error(
            display_path,
            format_args!("cannot open regular file without following links: {error}"),
        )
    })?;
    if !file
        .metadata()
        .map_err(|error| {
            cache_path_error(
                display_path,
                format_args!("cannot inspect opened file: {error}"),
            )
        })?
        .is_file()
    {
        return Err(cache_path_error(
            display_path,
            "opened path is not a regular file",
        ));
    }
    Ok(Some(file.into_std()))
}

pub(crate) fn validate_capability_sentinel(
    root: &CapDir,
    root_path: &Path,
) -> Result<(), ProviderError> {
    validate_capability_sentinel_with(root, root_path, || {})
}

pub(crate) fn validate_capability_sentinel_with(
    root: &CapDir,
    root_path: &Path,
    before_reopen: impl FnOnce(),
) -> Result<(), ProviderError> {
    let sentinel_path = root_path.join(CACHE_SENTINEL_FILE);
    let mut file =
        open_capability_regular_file(root, OsStr::new(CACHE_SENTINEL_FILE), &sentinel_path, false)?
            .ok_or_else(|| {
                cache_path_error(
                    root_path,
                    format_args!("missing ownership sentinel {CACHE_SENTINEL_FILE}"),
                )
            })?;
    let metadata = file.metadata().map_err(|error| {
        cache_path_error(
            root_path,
            format_args!("cannot inspect ownership sentinel: {error}"),
        )
    })?;
    if metadata.len() > 1024 {
        return Err(cache_path_error(
            root_path,
            format_args!("ownership sentinel {CACHE_SENTINEL_FILE} is oversized"),
        ));
    }
    let identity = std_file_identity(&file, &sentinel_path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).map_err(|error| {
        cache_path_error(
            root_path,
            format_args!("cannot read ownership sentinel: {error}"),
        )
    })?;
    let sentinel: CacheSentinel = serde_json::from_slice(&bytes).map_err(|error| {
        cache_path_error(
            root_path,
            format_args!("invalid ownership sentinel: {error}"),
        )
    })?;
    if sentinel != expected_cache_sentinel() {
        return Err(cache_path_error(
            root_path,
            "ownership sentinel does not identify a supported depscan cache",
        ));
    }
    before_reopen();
    let current =
        open_capability_regular_file(root, OsStr::new(CACHE_SENTINEL_FILE), &sentinel_path, false)?
            .ok_or_else(|| {
                cache_path_error(root_path, "ownership sentinel changed while validating")
            })?;
    if std_file_identity(&current, &sentinel_path)? != identity {
        return Err(cache_path_error(
            root_path,
            "ownership sentinel changed while validating",
        ));
    }
    Ok(())
}

pub(crate) fn validate_root_capability_attachment(
    root: &CapDir,
    root_path: &Path,
    expected_identity: &FileIdentity,
) -> Result<(), ProviderError> {
    let metadata = fs::symlink_metadata(root_path).map_err(|error| {
        cache_path_error(
            root_path,
            format_args!("cannot inspect cache root during revalidation: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(cache_path_error(
            root_path,
            "cache root changed while synchronizing",
        ));
    }
    let current_root =
        CapDir::open_ambient_dir(root_path, ambient_authority()).map_err(|error| {
            cache_path_error(
                root_path,
                format_args!("cannot reopen cache root during revalidation: {error}"),
            )
        })?;
    if &capability_directory_identity(&current_root, root_path)? != expected_identity {
        return Err(cache_path_error(
            root_path,
            "cache root changed while synchronizing",
        ));
    }
    validate_capability_sentinel(root, root_path)
}
