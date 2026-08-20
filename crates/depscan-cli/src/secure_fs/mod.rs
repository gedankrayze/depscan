use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, File, OpenOptions, Permissions},
};
use cap_tempfile::TempFile;
use depscan_core::FileIdentity;
use std::{
    ffi::{OsStr, OsString},
    fmt,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

mod config;
mod output;
mod path;

use config::open_regular_nofollow;
pub(crate) use config::read_config_nofollow;
#[cfg(test)]
use config::read_config_nofollow_impl;
pub(crate) use output::ConfinedOutput;
use path::*;

#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error)]
pub(crate) enum SecureFsError {
    #[error("{path} does not exist")]
    Missing { path: PathBuf },
    #[error("{path} is a symbolic link; symbolic links are not allowed")]
    SymbolicLink { path: PathBuf },
    #[error("{path} is not a regular file")]
    NotRegularFile { path: PathBuf },
    #[error("{path} changed while it was being used; refusing the operation")]
    Changed { path: PathBuf },
    #[error(
        "{output} escapes scan root {root}; use --output or an explicitly selected trusted config to write elsewhere"
    )]
    OutsideRoot { root: PathBuf, output: PathBuf },
    #[error("{action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn io_error(action: &'static str, path: impl Into<PathBuf>, source: io::Error) -> SecureFsError {
    SecureFsError::Io {
        action,
        path: path.into(),
        source,
    }
}

fn directory_identity(dir: &Dir, path: &Path) -> Result<FileIdentity, SecureFsError> {
    let file = dir
        .try_clone()
        .map_err(|error| io_error("cloning directory handle for", path, error))?
        .into_std_file();
    FileIdentity::from_owned_file(file)
        .map_err(|error| io_error("identifying directory", path, error))
}

fn file_identity(file: &File, path: &Path) -> Result<FileIdentity, SecureFsError> {
    let file = file
        .try_clone()
        .map_err(|error| io_error("cloning file handle for", path, error))?
        .into_std();
    FileIdentity::from_owned_file(file).map_err(|error| io_error("identifying file", path, error))
}

pub(crate) struct ScanRoot {
    dir: Dir,
    path: PathBuf,
    identity: FileIdentity,
}

impl fmt::Debug for ScanRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScanRoot")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl ScanRoot {
    pub(crate) fn open(path: &Path) -> Result<Self, SecureFsError> {
        let dir = Dir::open_ambient_dir(path, ambient_authority())
            .map_err(|error| io_error("opening scan root", path, error))?;
        let identity = directory_identity(&dir, path)?;
        Ok(Self {
            dir,
            path: path.to_path_buf(),
            identity,
        })
    }

    pub(crate) fn read_optional_config(
        &self,
        name: &OsStr,
        display_path: &Path,
    ) -> Result<Option<String>, SecureFsError> {
        self.read_optional_config_impl(name, display_path, || {})
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn read_optional_config_impl<F>(
        &self,
        name: &OsStr,
        display_path: &Path,
        before_read: F,
    ) -> Result<Option<String>, SecureFsError>
    where
        F: FnOnce(),
    {
        let mut file = match open_regular_nofollow(&self.dir, name, display_path) {
            Ok(file) => file,
            Err(SecureFsError::Missing { .. }) => return Ok(None),
            Err(error) => return Err(error),
        };
        let identity = file_identity(&file, display_path)?;
        before_read();
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|error| io_error("reading config", display_path, error))?;
        self.revalidate()?;
        let current = open_regular_nofollow(&self.dir, name, display_path).map_err(|error| {
            if matches!(error, SecureFsError::Missing { .. }) {
                SecureFsError::Changed {
                    path: display_path.to_path_buf(),
                }
            } else {
                error
            }
        })?;
        if file_identity(&current, display_path)? != identity {
            return Err(SecureFsError::Changed {
                path: display_path.to_path_buf(),
            });
        }
        Ok(Some(text))
    }

    pub(super) fn revalidate(&self) -> Result<(), SecureFsError> {
        let current = Dir::open_ambient_dir(&self.path, ambient_authority()).map_err(|_| {
            SecureFsError::Changed {
                path: self.path.clone(),
            }
        })?;
        if directory_identity(&current, &self.path)? != self.identity {
            return Err(SecureFsError::Changed {
                path: self.path.clone(),
            });
        }
        Ok(())
    }
}
