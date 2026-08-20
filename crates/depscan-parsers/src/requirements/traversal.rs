use super::*;

impl RequirementsParser<'_> {
    pub(super) fn resolve_directory(
        &mut self,
        relative: &Path,
        base: &Arc<DirectoryCapability>,
    ) -> Result<Arc<DirectoryCapability>, ParseError> {
        let target = relative
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name.to_os_string()),
                Component::CurDir => None,
                Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                    unreachable!("requirements directory paths are normalized before resolution")
                }
            })
            .collect::<Vec<_>>();
        let mut ancestry = Vec::new();
        let mut cursor = Some(base.clone());
        while let Some(capability) = cursor {
            cursor = capability.parent.clone();
            ancestry.push(capability);
        }
        ancestry.reverse();
        let base_components = base
            .relative
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name.to_os_string()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let common = target
            .iter()
            .zip(&base_components)
            .take_while(|(left, right)| left == right)
            .count();
        let mut current = ancestry[common].clone();
        for name in &target[common..] {
            let relative = current.relative.join(name);
            let display = self.root.canonical.join(&relative);
            let directory = match current.directory.open_dir(name) {
                Ok(directory) => directory,
                Err(component_error) => {
                    let full_relative = PathBuf::from_iter(&target);
                    let full_display = self.root.canonical.join(&full_relative);
                    let directory = self
                        .root
                        .directory
                        .directory
                        .open_dir(&full_relative)
                        .map_err(|error| {
                            self.rejected(
                                &full_display,
                                format!(
                                    "cannot open requirements include directory within scan root: {error}; component resolution failed: {component_error}"
                                ),
                            )
                        })?;
                    let identity = directory_identity(&directory, &full_display)?;
                    let capability = Arc::new(DirectoryCapability {
                        directory,
                        identity,
                        relative: full_relative.clone(),
                        parent: Some(self.root.directory.clone()),
                        name: Some(full_relative.clone()),
                    });
                    (self.hook)(ReadBoundary::DirectoryOpened, &full_relative, &full_display)?;
                    return Ok(capability);
                }
            };
            let metadata = directory.dir_metadata().map_err(|error| {
                self.rejected(
                    &display,
                    format!("cannot inspect requirements include directory: {error}"),
                )
            })?;
            if !metadata.is_dir() {
                return Err(
                    self.rejected(&display, "requirements include parent is not a directory")
                );
            }
            let identity = directory_identity(&directory, &display)?;
            current = Arc::new(DirectoryCapability {
                directory,
                identity,
                relative: relative.clone(),
                parent: Some(current),
                name: Some(PathBuf::from(name)),
            });
            (self.hook)(ReadBoundary::DirectoryOpened, &relative, &display)?;
        }
        Ok(current)
    }

    pub(super) fn revalidate_file(&self, opened: &OpenRequirementsFile) -> Result<(), ParseError> {
        let logical_parent = self.revalidate_directory(&opened.logical_parent, &opened.display)?;
        let canonical_parent = self.revalidate_directory(&opened.parent, &opened.display)?;
        self.revalidate_name(
            &logical_parent,
            &opened.logical_name,
            &opened.identity,
            &opened.display,
        )?;
        self.revalidate_name(
            &canonical_parent,
            &opened.name,
            &opened.identity,
            &opened.display,
        )
    }

    pub(super) fn revalidate_directory(
        &self,
        expected: &Arc<DirectoryCapability>,
        display: &Path,
    ) -> Result<Dir, ParseError> {
        let root =
            Dir::open_ambient_dir(&self.root.canonical, ambient_authority()).map_err(|_| {
                self.current_error(display, "requirements scan root changed while reading")
            })?;
        if directory_identity(&root, &self.root.canonical)? != self.root.directory.identity {
            return Err(self.current_error(display, "requirements scan root changed while reading"));
        }
        let mut ancestry = Vec::new();
        let mut cursor = Some(expected.clone());
        while let Some(capability) = cursor {
            cursor = capability.parent.clone();
            ancestry.push(capability);
        }
        ancestry.reverse();
        let mut current = root;
        for capability in ancestry.iter().skip(1) {
            let name = capability
                .name
                .as_deref()
                .expect("non-root directory capability has a name");
            current = current.open_dir(name).map_err(|_| {
                self.current_error(display, "requirements include path changed while reading")
            })?;
            if directory_identity(&current, display)? != capability.identity {
                return Err(
                    self.current_error(display, "requirements include path changed while reading")
                );
            }
        }
        Ok(current)
    }

    pub(super) fn revalidate_name(
        &self,
        parent: &Dir,
        name: &OsStr,
        expected: &FileIdentity,
        display: &Path,
    ) -> Result<(), ParseError> {
        let file = self
            .open_regular_nofollow(parent, name, display)
            .map_err(|_| self.current_error(display, "requirements file changed while reading"))?;
        if &file_identity(&file, display)? != expected {
            return Err(self.current_error(display, "requirements file changed while reading"));
        }
        Ok(())
    }
}
