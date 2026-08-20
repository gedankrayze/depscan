use super::*;

pub(crate) struct OfflineDirectory {
    pub(crate) root: CapDir,
    pub(crate) root_path: PathBuf,
    pub(crate) root_identity: FileIdentity,
    pub(crate) directory: CapDir,
    pub(crate) path: PathBuf,
    pub(crate) identity: FileIdentity,
}

impl OfflineDirectory {
    pub(crate) fn open(root_path: &Path) -> Result<Self, ProviderError> {
        Self::open_with(root_path, || {})
    }

    pub(crate) fn open_with(
        root_path: &Path,
        after_root_open: impl FnOnce(),
    ) -> Result<Self, ProviderError> {
        validate_owned_cache_root(root_path)?;
        let root = CapDir::open_ambient_dir(root_path, ambient_authority()).map_err(|error| {
            cache_path_error(
                root_path,
                format_args!("cannot open cache capability: {error}"),
            )
        })?;
        let root_identity = capability_directory_identity(&root, root_path)?;
        after_root_open();
        validate_root_capability_attachment(&root, root_path, &root_identity)?;
        let path = root_path.join("offline");
        let directory = match root.open_dir_nofollow("offline") {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match root.create_dir("offline") {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(cache_path_error(
                            &path,
                            format_args!("cannot create offline namespace: {error}"),
                        ));
                    }
                }
                root.open_dir_nofollow("offline").map_err(|error| {
                    cache_path_error(
                        &path,
                        format_args!(
                            "cannot open offline namespace without following links: {error}"
                        ),
                    )
                })?
            }
            Err(error) => {
                return Err(cache_path_error(
                    &path,
                    format_args!("cannot open offline namespace without following links: {error}"),
                ));
            }
        };
        let identity = capability_directory_identity(&directory, &path)?;
        let instance = Self {
            root,
            root_path: root_path.to_path_buf(),
            root_identity,
            directory,
            path,
            identity,
        };
        instance.revalidate()?;
        Ok(instance)
    }

    pub(crate) fn revalidate(&self) -> Result<(), ProviderError> {
        validate_root_capability_attachment(&self.root, &self.root_path, &self.root_identity)?;
        let current = self.root.open_dir_nofollow("offline").map_err(|error| {
            cache_path_error(
                &self.path,
                format_args!("offline namespace changed while synchronizing: {error}"),
            )
        })?;
        if capability_directory_identity(&current, &self.path)? != self.identity {
            return Err(cache_path_error(
                &self.path,
                "offline namespace changed while synchronizing",
            ));
        }
        Ok(())
    }

    pub(crate) fn display_path(&self, name: &OsStr) -> PathBuf {
        self.path.join(name)
    }

    pub(crate) fn open_dump(&self, ecosystem: Ecosystem) -> Result<OfflineDumpRead, ProviderError> {
        self.revalidate().map_err(offline_capability_error)?;
        let ecosystem_slug = ecosystem.osv_name().replace('.', "_");
        let archive_name = OsString::from(format!("{ecosystem_slug}.zip"));
        let marker_name = OsString::from(format!("{ecosystem_slug}.synced-at"));
        let archive_path = self.display_path(&archive_name);
        let marker_path = self.display_path(&marker_name);
        let archive =
            open_capability_regular_file(&self.directory, &archive_name, &archive_path, false)
                .map_err(offline_capability_error)?
                .ok_or_else(|| {
                    ProviderError::Offline(format!(
                        "missing OSV dump {}; run `depscan sync --ecosystem {}`",
                        archive_path.display(),
                        ecosystem.display_name()
                    ))
                })?;
        let marker =
            open_capability_regular_file(&self.directory, &marker_name, &marker_path, false)
                .map_err(offline_capability_error)?
                .ok_or_else(|| {
                    ProviderError::Offline(format!(
                        "missing OSV dump timestamp {}; run `depscan sync --ecosystem {}`",
                        marker_path.display(),
                        ecosystem.display_name()
                    ))
                })?;
        let archive_identity =
            std_file_identity(&archive, &archive_path).map_err(offline_capability_error)?;
        let marker_identity =
            std_file_identity(&marker, &marker_path).map_err(offline_capability_error)?;
        let dump = OfflineDumpRead {
            archive,
            marker,
            archive_name,
            marker_name,
            archive_path,
            marker_path,
            archive_identity,
            marker_identity,
        };
        self.revalidate_dump(&dump)?;
        Ok(dump)
    }

    pub(crate) fn revalidate_dump(&self, dump: &OfflineDumpRead) -> Result<(), ProviderError> {
        self.revalidate().map_err(offline_capability_error)?;
        self.revalidate_dump_file(
            &dump.archive_name,
            &dump.archive_path,
            &dump.archive_identity,
        )?;
        self.revalidate_dump_file(&dump.marker_name, &dump.marker_path, &dump.marker_identity)
    }

    pub(crate) fn revalidate_dump_file(
        &self,
        name: &OsStr,
        path: &Path,
        expected_identity: &FileIdentity,
    ) -> Result<(), ProviderError> {
        let current = open_capability_regular_file(&self.directory, name, path, false)
            .map_err(offline_capability_error)?
            .ok_or_else(|| {
                ProviderError::Offline(format!(
                    "OSV dump file {} changed while it was being read; refusing offline scan",
                    path.display()
                ))
            })?;
        let current_identity =
            std_file_identity(&current, path).map_err(offline_capability_error)?;
        if &current_identity != expected_identity {
            return Err(ProviderError::Offline(format!(
                "OSV dump file {} changed while it was being read; refusing offline scan",
                path.display()
            )));
        }
        Ok(())
    }
}

pub(crate) struct CapabilityTempFile {
    pub(crate) directory: CapDir,
    pub(crate) directory_path: PathBuf,
    pub(crate) file: Option<File>,
    pub(crate) name: Option<OsString>,
    pub(crate) cleanup: bool,
}

impl CapabilityTempFile {
    pub(crate) fn new(
        directory: &OfflineDirectory,
        prefix: &str,
        suffix: &str,
    ) -> Result<Self, ProviderError> {
        for _ in 0..128 {
            let name = OsString::from(format!(
                "{prefix}{:016x}{suffix}",
                rand::rng().random::<u64>()
            ));
            let mut options = CapOpenOptions::new();
            options
                .read(true)
                .write(true)
                .create_new(true)
                .follow(FollowSymlinks::No);
            match directory.directory.open_with(&name, &options) {
                Ok(file) => {
                    return Ok(Self {
                        directory: directory.directory.try_clone().map_err(|error| {
                            cache_path_error(
                                &directory.path,
                                format_args!("cannot clone offline capability: {error}"),
                            )
                        })?,
                        directory_path: directory.path.clone(),
                        file: Some(file.into_std()),
                        name: Some(name),
                        cleanup: true,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(cache_path_error(
                        &directory.path,
                        format_args!("cannot create temporary file: {error}"),
                    ));
                }
            }
        }
        Err(cache_path_error(
            &directory.path,
            "cannot allocate a unique temporary file name",
        ))
    }

    pub(crate) fn from_link(
        directory: &OfflineDirectory,
        name: OsString,
    ) -> Result<Self, ProviderError> {
        let display = directory.display_path(&name);
        let file = open_capability_regular_file(&directory.directory, &name, &display, false)?
            .ok_or_else(|| cache_path_error(&display, "staged rollback link disappeared"))?;
        Ok(Self {
            directory: directory.directory.try_clone().map_err(|error| {
                cache_path_error(
                    &directory.path,
                    format_args!("cannot clone offline capability: {error}"),
                )
            })?,
            directory_path: directory.path.clone(),
            file: Some(file),
            name: Some(name),
            cleanup: true,
        })
    }

    pub(crate) fn as_file(&self) -> &File {
        self.file
            .as_ref()
            .expect("temporary file handle is present before publication")
    }

    pub(crate) fn as_file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .expect("temporary file handle is present before publication")
    }

    pub(crate) fn logical_path(&self) -> PathBuf {
        self.directory_path.join(
            self.name
                .as_deref()
                .expect("temporary file name is present before publication"),
        )
    }

    pub(crate) fn persist(mut self, target: &OsStr) -> Result<(), CapabilityPersistError> {
        drop(self.file.take());
        let name = self
            .name
            .take()
            .expect("temporary file name is present before publication");
        match self.directory.rename(&name, &self.directory, target) {
            Ok(()) => {
                self.cleanup = false;
                Ok(())
            }
            Err(source) => {
                self.name = Some(name);
                Err(CapabilityPersistError {
                    source,
                    temporary: self,
                })
            }
        }
    }

    pub(crate) fn retain(mut self) -> PathBuf {
        self.cleanup = false;
        self.logical_path()
    }
}

impl Write for CapabilityTempFile {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.as_file_mut().write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.as_file_mut().flush()
    }
}

impl Drop for CapabilityTempFile {
    fn drop(&mut self) {
        drop(self.file.take());
        if self.cleanup
            && let Some(name) = self.name.take()
        {
            let _ = self.directory.remove_file(name);
        }
    }
}
