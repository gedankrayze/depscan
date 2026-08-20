use super::*;

fn open_parent_ambient(path: &Path) -> Result<(Dir, PathBuf, OsString), SecureFsError> {
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| SecureFsError::NotRegularFile {
            path: path.to_path_buf(),
        })?
        .to_os_string();
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let dir = Dir::open_ambient_dir(&parent, ambient_authority())
        .map_err(|error| io_error("opening parent directory", &parent, error))?;
    Ok((dir, parent, name))
}

pub(super) fn open_regular_nofollow(
    dir: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<File, SecureFsError> {
    match dir.symlink_metadata(name) {
        Ok(metadata) if metadata.is_symlink() => {
            return Err(SecureFsError::SymbolicLink {
                path: display_path.to_path_buf(),
            });
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(SecureFsError::NotRegularFile {
                path: display_path.to_path_buf(),
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(SecureFsError::Missing {
                path: display_path.to_path_buf(),
            });
        }
        Err(error) => {
            return Err(io_error("inspecting", display_path, error));
        }
    }

    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = dir.open_with(name, &options).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            SecureFsError::Changed {
                path: display_path.to_path_buf(),
            }
        } else {
            io_error("opening", display_path, error)
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspecting opened file", display_path, error))?;
    if !metadata.is_file() {
        return Err(SecureFsError::NotRegularFile {
            path: display_path.to_path_buf(),
        });
    }
    Ok(file)
}

pub(crate) fn read_config_nofollow(
    path: &Path,
    missing_is_empty: bool,
) -> Result<Option<String>, SecureFsError> {
    read_config_nofollow_impl(path, missing_is_empty, || {})
}

pub(super) fn read_config_nofollow_impl<F>(
    path: &Path,
    missing_is_empty: bool,
    before_read: F,
) -> Result<Option<String>, SecureFsError>
where
    F: FnOnce(),
{
    let (parent, parent_path, name) = open_parent_ambient(path)?;
    let parent_identity = directory_identity(&parent, &parent_path)?;
    let mut file = match open_regular_nofollow(&parent, &name, path) {
        Ok(file) => file,
        Err(SecureFsError::Missing { .. }) if missing_is_empty => return Ok(None),
        Err(error) => return Err(error),
    };
    let identity = file_identity(&file, path)?;

    before_read();

    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| io_error("reading config", path, error))?;

    let current_parent =
        Dir::open_ambient_dir(&parent_path, ambient_authority()).map_err(|_| {
            SecureFsError::Changed {
                path: parent_path.clone(),
            }
        })?;
    if directory_identity(&current_parent, &parent_path)? != parent_identity {
        return Err(SecureFsError::Changed { path: parent_path });
    }
    let current = open_regular_nofollow(&current_parent, &name, path).map_err(|error| {
        if matches!(error, SecureFsError::Missing { .. }) {
            SecureFsError::Changed {
                path: path.to_path_buf(),
            }
        } else {
            error
        }
    })?;
    if file_identity(&current, path)? != identity {
        return Err(SecureFsError::Changed {
            path: path.to_path_buf(),
        });
    }
    Ok(Some(text))
}
