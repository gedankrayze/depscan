use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, File, OpenOptions, Permissions},
};
use cap_tempfile::TempFile;
use same_file::Handle;
use std::{
    ffi::{OsStr, OsString},
    fmt,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

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

fn directory_identity(dir: &Dir, path: &Path) -> Result<Handle, SecureFsError> {
    let file = dir
        .try_clone()
        .map_err(|error| io_error("cloning directory handle for", path, error))?
        .into_std_file();
    Handle::from_file(file).map_err(|error| io_error("identifying directory", path, error))
}

fn file_identity(file: &File, path: &Path) -> Result<Handle, SecureFsError> {
    let file = file
        .try_clone()
        .map_err(|error| io_error("cloning file handle for", path, error))?
        .into_std();
    Handle::from_file(file).map_err(|error| io_error("identifying file", path, error))
}

pub(crate) struct ScanRoot {
    dir: Dir,
    path: PathBuf,
    identity: Handle,
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

    fn revalidate(&self) -> Result<(), SecureFsError> {
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

fn open_regular_nofollow(
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

fn read_config_nofollow_impl<F>(
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

#[derive(Debug)]
enum TargetState {
    Missing,
    Existing {
        identity: Handle,
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
    parent_identity: Handle,
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

    fn write_impl<F>(&self, contents: &[u8], before_publish: F) -> Result<(), SecureFsError>
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

fn confined_relative_path(root: &Path, configured: &Path) -> Result<PathBuf, SecureFsError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::{Arc, Barrier},
        thread,
    };
    use tempfile::tempdir;

    fn prepare_output(root: &Path, configured: &Path, display: &Path) -> ConfinedOutput {
        ConfinedOutput::prepare(
            ScanRoot::open(root).expect("open scan root"),
            configured,
            display,
        )
        .expect("prepare output")
    }

    #[cfg(windows)]
    fn assert_windows_handle_blocks_rename(error: &io::Error) {
        assert!(
            error.raw_os_error().is_some(),
            "Windows must report an OS error while the directory capability is held: {error}"
        );
    }

    #[test]
    fn config_swap_after_open_is_detected_without_reading_replacement() {
        let directory = tempdir().expect("tempdir");
        let config = directory.path().join("depscan.toml");
        let replacement = directory.path().join("replacement.toml");
        fs::write(&config, "fail-on = 'never'\n").expect("write config");
        fs::write(&replacement, "allow-tools = true\n").expect("write replacement");
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = barrier.clone();
        let config_for_worker = config.clone();
        let replacement_for_worker = replacement.clone();
        let worker = thread::spawn(move || {
            worker_barrier.wait();
            fs::rename(replacement_for_worker, config_for_worker).expect("replace config");
        });

        let error = read_config_nofollow_impl(&config, false, || {
            barrier.wait();
            worker.join().expect("join swap worker");
        })
        .expect_err("swapped config must fail");
        assert!(matches!(error, SecureFsError::Changed { .. }));
    }

    #[cfg(not(windows))]
    #[test]
    fn config_parent_swap_is_detected_without_following_the_replacement() {
        let directory = tempdir().expect("tempdir");
        let project = directory.path().join("project");
        let configs = project.join("configs");
        let moved_configs = project.join("configs-original");
        fs::create_dir_all(&configs).expect("create config parent");
        let config = configs.join("policy.toml");
        fs::write(&config, "fail-on = 'never'\n").expect("write config");

        let error = read_config_nofollow_impl(&config, false, || {
            fs::rename(&configs, &moved_configs).expect("move validated parent");
            fs::create_dir(&configs).expect("replace config parent");
            fs::write(configs.join("policy.toml"), "allow-tools = true\n")
                .expect("write replacement config");
        });
        assert!(matches!(error, Err(SecureFsError::Changed { .. })));
    }

    #[cfg(windows)]
    #[test]
    fn config_parent_handle_prevents_a_windows_parent_swap() {
        let directory = tempdir().expect("tempdir");
        let configs = directory.path().join("configs");
        let moved_configs = directory.path().join("configs-original");
        fs::create_dir(&configs).expect("create config parent");
        let config = configs.join("policy.toml");
        fs::write(&config, "fail-on = 'never'\n").expect("write config");
        let text = read_config_nofollow_impl(&config, false, || {
            let error = fs::rename(&configs, &moved_configs)
                .expect_err("held Windows directory handle must prevent rename");
            assert_windows_handle_blocks_rename(&error);
        })
        .expect("read validated config")
        .expect("config exists");
        assert_eq!(text, "fail-on = 'never'\n");
    }

    #[cfg(not(windows))]
    #[test]
    fn implicit_config_and_output_share_one_scan_root_capability() {
        let directory = tempdir().expect("tempdir");
        let root = directory.path().join("project");
        let moved_root = directory.path().join("project-original");
        fs::create_dir_all(root.join("reports")).expect("create original project");
        fs::write(root.join("depscan.toml"), "output = 'reports/audit.json'\n")
            .expect("write implicit config");
        let scan_root = ScanRoot::open(&root).expect("open scan root");
        let config = scan_root
            .read_optional_config(OsStr::new("depscan.toml"), &root.join("depscan.toml"))
            .expect("read implicit config")
            .expect("implicit config exists");
        assert!(config.contains("reports/audit.json"));

        fs::rename(&root, &moved_root).expect("move original scan root");
        fs::create_dir_all(root.join("reports")).expect("create replacement project");
        let error = ConfinedOutput::prepare(
            scan_root,
            Path::new("reports/audit.json"),
            &root.join("reports/audit.json"),
        )
        .expect_err("a replacement scan root must not receive configured output");
        assert!(matches!(error, SecureFsError::Changed { .. }));
        assert!(!root.join("reports/audit.json").exists());
        assert!(!moved_root.join("reports/audit.json").exists());
    }

    #[cfg(windows)]
    #[test]
    fn scan_root_handle_prevents_config_to_output_handoff_swap_on_windows() {
        let directory = tempdir().expect("tempdir");
        let root = directory.path().join("project");
        let moved_root = directory.path().join("project-original");
        fs::create_dir_all(root.join("reports")).expect("create project");
        fs::write(root.join("depscan.toml"), "output = 'reports/audit.json'\n")
            .expect("write implicit config");
        let scan_root = ScanRoot::open(&root).expect("open scan root");
        scan_root
            .read_optional_config(OsStr::new("depscan.toml"), &root.join("depscan.toml"))
            .expect("read implicit config")
            .expect("implicit config exists");

        let error = fs::rename(&root, &moved_root)
            .expect_err("held Windows scan-root handle must prevent rename");
        assert_windows_handle_blocks_rename(&error);
        let capability = ConfinedOutput::prepare(
            scan_root,
            Path::new("reports/audit.json"),
            &root.join("reports/audit.json"),
        )
        .expect("prepare output through unchanged root");
        capability.write(b"safe report").expect("publish report");
        assert_eq!(
            fs::read_to_string(root.join("reports/audit.json")).expect("read report"),
            "safe report"
        );
        assert!(!moved_root.exists());
    }

    #[cfg(not(windows))]
    #[test]
    fn output_parent_swap_cannot_redirect_publication_or_cleanup() {
        let directory = tempdir().expect("tempdir");
        let root = directory.path().join("project");
        let reports = root.join("reports");
        let moved_reports = root.join("reports-original");
        fs::create_dir_all(&reports).expect("create reports");
        let output = reports.join("audit.json");
        let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);

        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = barrier.clone();
        let reports_for_worker = reports.clone();
        let moved_for_worker = moved_reports.clone();
        let worker = thread::spawn(move || {
            worker_barrier.wait();
            fs::rename(reports_for_worker, moved_for_worker).expect("move validated parent");
        });

        let error = capability
            .write_impl(b"safe report", || {
                barrier.wait();
                worker.join().expect("join parent-swap worker");
                fs::create_dir(&reports).expect("replace validated parent");
            })
            .expect_err("parent swap must fail");
        assert!(matches!(error, SecureFsError::Changed { .. }));
        assert!(!reports.join("audit.json").exists());
        assert!(!moved_reports.join("audit.json").exists());
        assert_eq!(
            fs::read_dir(&moved_reports)
                .expect("read moved parent")
                .count(),
            0,
            "temporary output must be cleaned through the held directory handle"
        );
    }

    #[cfg(windows)]
    #[test]
    fn output_parent_handle_prevents_a_windows_parent_swap() {
        let directory = tempdir().expect("tempdir");
        let root = directory.path().join("project");
        let reports = root.join("reports");
        let moved_reports = root.join("reports-original");
        fs::create_dir_all(&reports).expect("create reports");
        let output = reports.join("audit.json");
        let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);
        capability
            .write_impl(b"safe report", || {
                let error = fs::rename(&reports, &moved_reports)
                    .expect_err("held Windows directory handle must prevent rename");
                assert_windows_handle_blocks_rename(&error);
            })
            .expect("publish through the unchanged parent");
        assert_eq!(
            fs::read_to_string(output).expect("read output"),
            "safe report"
        );
        assert!(!moved_reports.exists());
    }

    #[cfg(not(windows))]
    #[test]
    fn output_target_swap_is_detected_and_external_symlink_target_is_untouched() {
        let directory = tempdir().expect("tempdir");
        let root = directory.path().join("project");
        let reports = root.join("reports");
        fs::create_dir_all(&reports).expect("create reports");
        let output = reports.join("audit.json");
        let external = directory.path().join("external.json");
        fs::write(&external, "preserve").expect("write external target");
        let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);

        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = barrier.clone();
        let external_for_worker = external.clone();
        let output_for_worker = output.clone();
        let worker = thread::spawn(move || {
            worker_barrier.wait();
            create_file_symlink(&external_for_worker, &output_for_worker)
                .expect("create swapped symlink");
        });

        let error = capability
            .write_impl(b"safe report", || {
                barrier.wait();
                worker.join().expect("join symlink-swap worker");
            })
            .expect_err("target swap must fail");
        assert!(matches!(error, SecureFsError::SymbolicLink { .. }));
        assert_eq!(
            fs::read_to_string(external).expect("read external"),
            "preserve"
        );
    }

    #[cfg(windows)]
    #[test]
    fn output_target_symlink_swap_is_rejected_when_windows_can_create_it() {
        let directory = tempdir().expect("tempdir");
        let root = directory.path().join("project");
        let reports = root.join("reports");
        fs::create_dir_all(&reports).expect("create reports");
        let output = reports.join("audit.json");
        let external = directory.path().join("external.json");
        fs::write(&external, "preserve").expect("write external target");
        let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);

        if let Err(error) = create_file_symlink(&external, &output) {
            assert_eq!(
                error.kind(),
                io::ErrorKind::PermissionDenied,
                "unexpected Windows symlink creation error: {error}"
            );
            assert!(!output.exists());
            assert_eq!(
                fs::read_to_string(external).expect("read external"),
                "preserve"
            );
            eprintln!("Windows runner lacks symlink privilege; the OS prevented the swap fixture");
            return;
        }

        let error = capability
            .write(b"safe report")
            .expect_err("target symlink swap must fail");
        assert!(matches!(error, SecureFsError::SymbolicLink { .. }));
        assert_eq!(
            fs::read_to_string(external).expect("read external"),
            "preserve"
        );
    }

    #[test]
    fn output_regular_file_swap_is_detected_before_atomic_replacement() {
        let directory = tempdir().expect("tempdir");
        let root = directory.path().join("project");
        let reports = root.join("reports");
        fs::create_dir_all(&reports).expect("create reports");
        let output = reports.join("audit.json");
        let replacement = reports.join("replacement.json");
        fs::write(&output, "original").expect("write original output");
        fs::write(&replacement, "concurrent replacement").expect("write replacement output");
        let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);

        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = barrier.clone();
        let replacement_for_worker = replacement.clone();
        let output_for_worker = output.clone();
        let worker = thread::spawn(move || {
            worker_barrier.wait();
            fs::rename(replacement_for_worker, output_for_worker)
                .expect("replace output concurrently");
        });

        let error = capability
            .write_impl(b"new report", || {
                barrier.wait();
                worker.join().expect("join file-swap worker");
            })
            .expect_err("regular-file swap must fail");
        assert!(matches!(error, SecureFsError::Changed { .. }));
        assert_eq!(
            fs::read_to_string(output).expect("read concurrent output"),
            "concurrent replacement"
        );
    }

    #[test]
    fn preexisting_output_parent_symlink_is_rejected() {
        let directory = tempdir().expect("tempdir");
        let root = directory.path().join("project");
        let outside = directory.path().join("outside");
        fs::create_dir(&root).expect("create root");
        fs::create_dir(&outside).expect("create outside");
        if let Err(error) = create_directory_symlink(&outside, &root.join("reports")) {
            if error.kind() == io::ErrorKind::PermissionDenied {
                assert!(!outside.join("audit.json").exists());
                eprintln!(
                    "Windows runner lacks symlink privilege; the OS prevented the parent-symlink fixture"
                );
                return;
            }
            panic!("create output-parent symlink: {error}");
        }
        let output = root.join("reports/audit.json");
        assert!(
            ConfinedOutput::prepare(
                ScanRoot::open(&root).expect("open scan root"),
                Path::new("reports/audit.json"),
                &output,
            )
            .is_err()
        );
        assert!(!outside.join("audit.json").exists());
    }

    #[test]
    fn output_is_atomically_replaced_through_the_validated_parent_handle() {
        let directory = tempdir().expect("tempdir");
        let root = directory.path().join("project");
        let reports = root.join("reports");
        fs::create_dir_all(&reports).expect("create reports");
        let output = reports.join("audit.json");
        fs::write(&output, "old").expect("write old output");
        let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);
        capability.write(b"new report").expect("replace output");
        assert_eq!(
            fs::read_to_string(output).expect("read output"),
            "new report"
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replacement_preserves_existing_unix_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempdir().expect("tempdir");
        let root = directory.path().join("project");
        let reports = root.join("reports");
        fs::create_dir_all(&reports).expect("create reports");
        let output = reports.join("audit.json");
        fs::write(&output, "old").expect("write old output");
        fs::set_permissions(&output, fs::Permissions::from_mode(0o600))
            .expect("restrict output mode");

        let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);
        capability.write(b"new report").expect("replace output");

        assert_eq!(
            fs::metadata(output).expect("output metadata").mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn missing_output_is_atomically_created_through_the_validated_parent_handle() {
        let directory = tempdir().expect("tempdir");
        let root = directory.path().join("project");
        let reports = root.join("reports");
        fs::create_dir_all(&reports).expect("create reports");
        let output = reports.join("audit.json");
        let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);
        capability.write(b"new report").expect("publish output");
        assert_eq!(
            fs::read_to_string(output).expect("read output"),
            "new report"
        );
    }

    #[cfg(unix)]
    fn create_directory_symlink(target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_directory_symlink(target: &Path, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    #[cfg(unix)]
    fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }
}
