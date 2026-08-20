use super::*;

#[derive(Debug)]
enum TargetState {
    Missing,
    Existing {
        identity: FileIdentity,
        permissions: Permissions,
    },
}

impl TargetState {
    fn matches(&self, current: &Self) -> bool {
        match (self, current) {
            (Self::Missing, Self::Missing) => true,
            (
                Self::Existing {
                    identity: expected, ..
                },
                Self::Existing {
                    identity: actual, ..
                },
            ) => expected == actual,
            _ => false,
        }
    }

    fn permissions(&self) -> Option<&Permissions> {
        match self {
            Self::Missing => None,
            Self::Existing { permissions, .. } => Some(permissions),
        }
    }
}

pub(crate) struct ConfinedOutput {
    root: ScanRoot,
    parent: Dir,
    parent_relative: PathBuf,
    parent_identity: FileIdentity,
    name: OsString,
    target_state: TargetState,
    display_path: PathBuf,
}

impl fmt::Debug for ConfinedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfinedOutput")
            .field("parent_relative", &self.parent_relative)
            .field("name", &self.name)
            .field("display_path", &self.display_path)
            .finish_non_exhaustive()
    }
}

impl ConfinedOutput {
    pub(crate) fn prepare(
        root: ScanRoot,
        configured_path: &Path,
        display_path: &Path,
    ) -> Result<Self, SecureFsError> {
        root.revalidate()?;
        let relative = confined_relative_path(root.path(), configured_path)?;
        let name = relative
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| SecureFsError::NotRegularFile {
                path: display_path.to_path_buf(),
            })?
            .to_os_string();
        let parent_relative = relative
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let parent = open_relative_directory_nofollow(&root.dir, &parent_relative, display_path)?;
        let parent_identity = directory_identity(&parent, display_path)?;
        let target_state = target_state(&parent, &name, display_path)?;
        Ok(Self {
            root,
            parent,
            parent_relative,
            parent_identity,
            name,
            target_state,
            display_path: display_path.to_path_buf(),
        })
    }

    pub(crate) fn write(&self, contents: &[u8]) -> Result<(), SecureFsError> {
        self.write_impl(contents, || {})
    }

    pub(super) fn write_impl<F>(
        &self,
        contents: &[u8],
        before_publish: F,
    ) -> Result<(), SecureFsError>
    where
        F: FnOnce(),
    {
        let mut temporary = TempFile::new(&self.parent).map_err(|error| {
            io_error(
                "creating temporary output beside",
                &self.display_path,
                error,
            )
        })?;
        temporary.write_all(contents).map_err(|error| {
            io_error("writing temporary output beside", &self.display_path, error)
        })?;
        temporary.flush().map_err(|error| {
            io_error(
                "flushing temporary output beside",
                &self.display_path,
                error,
            )
        })?;
        if let Some(permissions) = self.target_state.permissions() {
            temporary
                .as_file()
                .set_permissions(permissions.clone())
                .map_err(|error| {
                    io_error(
                        "preserving existing output permissions for",
                        &self.display_path,
                        error,
                    )
                })?;
        }
        temporary.as_file().sync_all().map_err(|error| {
            io_error("syncing temporary output beside", &self.display_path, error)
        })?;

        before_publish();
        self.revalidate()?;
        temporary
            .replace(&self.name)
            .map_err(|error| io_error("publishing", &self.display_path, error))?;
        Ok(())
    }

    fn revalidate(&self) -> Result<(), SecureFsError> {
        self.root.revalidate()?;
        let current_parent = open_relative_directory_nofollow(
            &self.root.dir,
            &self.parent_relative,
            &self.display_path,
        )
        .map_err(|_| SecureFsError::Changed {
            path: self.display_path.clone(),
        })?;
        if directory_identity(&current_parent, &self.display_path)? != self.parent_identity {
            return Err(SecureFsError::Changed {
                path: self.display_path.clone(),
            });
        }
        let current_state = target_state(&self.parent, &self.name, &self.display_path)?;
        if !self.target_state.matches(&current_state) {
            return Err(SecureFsError::Changed {
                path: self.display_path.clone(),
            });
        }
        Ok(())
    }
}

fn target_state(
    parent: &Dir,
    name: &OsStr,
    display_path: &Path,
) -> Result<TargetState, SecureFsError> {
    match parent.symlink_metadata(name) {
        Ok(metadata) if metadata.is_symlink() => Err(SecureFsError::SymbolicLink {
            path: display_path.to_path_buf(),
        }),
        Ok(metadata) if !metadata.is_file() => Err(SecureFsError::NotRegularFile {
            path: display_path.to_path_buf(),
        }),
        Ok(_) => {
            let file = open_regular_nofollow(parent, name, display_path)?;
            let metadata = file
                .metadata()
                .map_err(|error| io_error("inspecting opened file", display_path, error))?;
            Ok(TargetState::Existing {
                identity: file_identity(&file, display_path)?,
                permissions: metadata.permissions(),
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(TargetState::Missing),
        Err(error) => Err(io_error("inspecting", display_path, error)),
    }
}

fn open_relative_directory_nofollow(
    root: &Dir,
    relative: &Path,
    display_path: &Path,
) -> Result<Dir, SecureFsError> {
    let mut current = root
        .try_clone()
        .map_err(|error| io_error("cloning scan-root handle for", display_path, error))?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::CurDir) {
                continue;
            }
            return Err(SecureFsError::OutsideRoot {
                root: PathBuf::from("."),
                output: display_path.to_path_buf(),
            });
        };
        current = current.open_dir_nofollow(name).map_err(|error| {
            io_error(
                "opening configured output directory for",
                display_path,
                error,
            )
        })?;
    }
    Ok(current)
}
