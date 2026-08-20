use super::*;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CacheSentinel {
    pub(crate) schema_version: u32,
    pub(crate) owner: String,
}

pub(crate) fn expected_cache_sentinel() -> CacheSentinel {
    CacheSentinel {
        schema_version: CACHE_SENTINEL_SCHEMA_VERSION,
        owner: CACHE_SENTINEL_OWNER.to_owned(),
    }
}

pub(crate) fn cache_path_error(root: &Path, message: impl std::fmt::Display) -> ProviderError {
    ProviderError::Cache(format!("refusing cache path {}: {message}", root.display()))
}

pub(crate) fn validate_cache_scope_with(
    root: &Path,
    current_directory: &Path,
    home_directory: Option<&Path>,
) -> Result<(), ProviderError> {
    if !root.is_absolute() {
        return Err(cache_path_error(root, "resolved path is not absolute"));
    }
    if root.parent().is_none() {
        return Err(cache_path_error(
            root,
            "filesystem roots are not cache directories",
        ));
    }
    if current_directory.starts_with(root) {
        return Err(cache_path_error(
            root,
            "path is the current workspace or one of its ancestors",
        ));
    }
    if home_directory.is_some_and(|home| home.starts_with(root)) {
        return Err(cache_path_error(
            root,
            "path is the home directory or one of its ancestors",
        ));
    }
    if [".git", ".hg", ".svn"]
        .iter()
        .any(|marker| root.join(marker).exists())
    {
        return Err(cache_path_error(
            root,
            "path is a version-control workspace",
        ));
    }
    Ok(())
}

pub(crate) fn validate_cache_scope(root: &Path) -> Result<(), ProviderError> {
    let current_directory = std::env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(|error| cache_path_error(root, format_args!("cannot resolve cwd: {error}")))?;
    let home_directory = BaseDirs::new().and_then(|dirs| {
        fs::canonicalize(dirs.home_dir())
            .ok()
            .or_else(|| Some(dirs.home_dir().to_path_buf()))
    });
    validate_cache_scope_with(root, &current_directory, home_directory.as_deref())
}

pub(crate) fn validate_cache_sentinel(root: &Path) -> Result<(), ProviderError> {
    let sentinel_path = root.join(CACHE_SENTINEL_FILE);
    let metadata = fs::symlink_metadata(&sentinel_path).map_err(|error| {
        cache_path_error(
            root,
            format_args!("missing ownership sentinel {CACHE_SENTINEL_FILE}: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(cache_path_error(
            root,
            format_args!("ownership sentinel {CACHE_SENTINEL_FILE} is not a regular file"),
        ));
    }
    if metadata.len() > 1024 {
        return Err(cache_path_error(
            root,
            format_args!("ownership sentinel {CACHE_SENTINEL_FILE} is oversized"),
        ));
    }
    let bytes = fs::read(&sentinel_path).map_err(|error| {
        cache_path_error(
            root,
            format_args!("cannot read ownership sentinel: {error}"),
        )
    })?;
    let sentinel = serde_json::from_slice::<CacheSentinel>(&bytes).map_err(|error| {
        cache_path_error(root, format_args!("invalid ownership sentinel: {error}"))
    })?;
    if sentinel != expected_cache_sentinel() {
        return Err(cache_path_error(
            root,
            "ownership sentinel has an unsupported owner or schema version",
        ));
    }
    Ok(())
}

pub(crate) fn write_cache_sentinel(root: &Path) -> Result<(), ProviderError> {
    let sentinel_path = root.join(CACHE_SENTINEL_FILE);
    let bytes = serde_json::to_vec(&expected_cache_sentinel())
        .map_err(|error| ProviderError::Cache(error.to_string()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&sentinel_path)
        .map_err(|error| cache_path_error(root, format_args!("cannot create sentinel: {error}")))?;
    std::io::Write::write_all(&mut file, &bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| cache_path_error(root, format_args!("cannot persist sentinel: {error}")))
}

pub(crate) fn legacy_cache_layout_is_owned(root: &Path) -> Result<bool, ProviderError> {
    let mut entries = fs::read_dir(root).map_err(|error| {
        cache_path_error(root, format_args!("cannot inspect legacy cache: {error}"))
    })?;
    let mut found_entry = false;
    for entry in &mut entries {
        let entry = entry.map_err(|error| {
            cache_path_error(root, format_args!("cannot inspect legacy cache: {error}"))
        })?;
        found_entry = true;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Ok(false);
        };
        if !CACHE_CONTENT_DIRECTORIES.contains(&name) {
            return Ok(false);
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            cache_path_error(root, format_args!("cannot inspect legacy cache: {error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Ok(false);
        }
    }
    Ok(found_entry)
}

pub(crate) fn initialize_cache_root(
    requested: &Path,
    allow_legacy_migration: bool,
) -> Result<PathBuf, ProviderError> {
    if requested.as_os_str().is_empty() {
        return Err(ProviderError::Cache(
            "refusing an empty cache directory path".to_owned(),
        ));
    }
    let absolute = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| ProviderError::Cache(error.to_string()))?
            .join(requested)
    };
    match fs::symlink_metadata(&absolute) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(cache_path_error(&absolute, "directory is a symbolic link"));
            }
            if !metadata.is_dir() {
                return Err(cache_path_error(&absolute, "path is not a directory"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(&absolute).map_err(|error| {
                cache_path_error(&absolute, format_args!("cannot create directory: {error}"))
            })?;
        }
        Err(error) => {
            return Err(cache_path_error(
                &absolute,
                format_args!("cannot inspect directory: {error}"),
            ));
        }
    }
    let metadata = fs::symlink_metadata(&absolute).map_err(|error| {
        cache_path_error(&absolute, format_args!("cannot inspect directory: {error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(cache_path_error(
            &absolute,
            "created path is not a real directory",
        ));
    }
    let root = fs::canonicalize(&absolute).map_err(|error| {
        cache_path_error(&absolute, format_args!("cannot resolve directory: {error}"))
    })?;
    validate_cache_scope(&root)?;

    let sentinel_path = root.join(CACHE_SENTINEL_FILE);
    match fs::symlink_metadata(&sentinel_path) {
        Ok(_) => validate_cache_sentinel(&root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut entries = fs::read_dir(&root).map_err(|error| {
                cache_path_error(&root, format_args!("cannot inspect directory: {error}"))
            })?;
            let has_entries = entries
                .next()
                .transpose()
                .map_err(|error| {
                    cache_path_error(&root, format_args!("cannot inspect directory: {error}"))
                })?
                .is_some();
            if has_entries && !(allow_legacy_migration && legacy_cache_layout_is_owned(&root)?) {
                return Err(cache_path_error(
                    &root,
                    "directory is non-empty and has no depscan ownership sentinel",
                ));
            }
            write_cache_sentinel(&root)?;
            validate_cache_sentinel(&root)?;
        }
        Err(error) => {
            return Err(cache_path_error(
                &root,
                format_args!("cannot inspect ownership sentinel: {error}"),
            ));
        }
    }
    Ok(root)
}

pub(crate) fn validate_owned_cache_root(root: &Path) -> Result<(), ProviderError> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        cache_path_error(root, format_args!("cannot inspect directory: {error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(cache_path_error(
            root,
            "directory was replaced or is not real",
        ));
    }
    let canonical = fs::canonicalize(root).map_err(|error| {
        cache_path_error(root, format_args!("cannot resolve directory: {error}"))
    })?;
    if canonical != root {
        return Err(cache_path_error(
            root,
            format_args!("directory now resolves to {}", canonical.display()),
        ));
    }
    validate_cache_scope(root)?;
    validate_cache_sentinel(root)
}
