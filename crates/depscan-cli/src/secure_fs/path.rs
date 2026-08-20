use super::*;

pub(super) fn confined_relative_path(
    root: &Path,
    configured: &Path,
) -> Result<PathBuf, SecureFsError> {
    let candidate = if configured.is_absolute() {
        let root_absolute = lexical_absolute(root)?;
        let configured_absolute =
            normalize_lexical(configured).ok_or_else(|| SecureFsError::OutsideRoot {
                root: root.to_path_buf(),
                output: configured.to_path_buf(),
            })?;
        configured_absolute
            .strip_prefix(&root_absolute)
            .map(Path::to_path_buf)
            .map_err(|_| SecureFsError::OutsideRoot {
                root: root.to_path_buf(),
                output: configured.to_path_buf(),
            })?
    } else {
        configured.to_path_buf()
    };
    normalize_relative(&candidate).ok_or_else(|| SecureFsError::OutsideRoot {
        root: root.to_path_buf(),
        output: configured.to_path_buf(),
    })
}

fn lexical_absolute(path: &Path) -> Result<PathBuf, SecureFsError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| io_error("resolving current directory for", path, error))?
            .join(path)
    };
    normalize_lexical(&absolute).ok_or_else(|| SecureFsError::OutsideRoot {
        root: path.to_path_buf(),
        output: path.to_path_buf(),
    })
}

fn normalize_lexical(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    let mut normal_components = 0usize;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if normal_components == 0 || !normalized.pop() {
                    return None;
                }
                normal_components -= 1;
            }
            Component::Normal(name) => {
                normalized.push(name);
                normal_components += 1;
            }
        }
    }
    Some(normalized)
}

fn normalize_relative(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::Normal(name) => normalized.push(name),
            Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    if normalized.as_os_str().is_empty() {
        None
    } else {
        Some(normalized)
    }
}
