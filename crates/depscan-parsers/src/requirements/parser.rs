use super::*;

pub(super) fn parse_with_limits(
    path: &Path,
    limits: RequirementsLimits,
) -> Result<Vec<Package>, ParseError> {
    let mut hook = |boundary, relative: &Path, display: &Path| {
        process_test_barrier(boundary, relative, display)
    };
    parse_with_limits_and_hook(path, limits, &mut hook)
}

pub(super) fn parse_with_limits_and_hook(
    path: &Path,
    limits: RequirementsLimits,
    hook: &mut dyn FnMut(ReadBoundary, &Path, &Path) -> Result<(), ParseError>,
) -> Result<Vec<Package>, ParseError> {
    let requested_root = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let root_directory =
        Dir::open_ambient_dir(requested_root, ambient_authority()).map_err(|error| {
            invalid(
                requested_root,
                format!("cannot open requirements scan root: {error}"),
            )
        })?;
    let metadata = root_directory.dir_metadata().map_err(|error| {
        invalid(
            requested_root,
            format!("cannot inspect requirements scan root: {error}"),
        )
    })?;
    if !metadata.is_dir() {
        return Err(invalid(
            requested_root,
            "requirements scan root is not a directory",
        ));
    }
    let root_identity = directory_identity(&root_directory, requested_root)?;
    let canonical = fs::canonicalize(requested_root).map_err(|error| {
        invalid(
            requested_root,
            format!("cannot canonicalize requirements scan root: {error}"),
        )
    })?;
    let canonical_directory =
        Dir::open_ambient_dir(&canonical, ambient_authority()).map_err(|error| {
            invalid(
                requested_root,
                format!("cannot validate canonical requirements scan root: {error}"),
            )
        })?;
    if directory_identity(&canonical_directory, &canonical)? != root_identity {
        return Err(invalid(
            requested_root,
            "requirements scan root changed while its capability was acquired",
        ));
    }
    let requested_absolute = lexical_absolute(requested_root).map_err(|message| {
        invalid(
            requested_root,
            format!("cannot resolve requirements scan root: {message}"),
        )
    })?;
    let root = RequirementsRoot {
        directory: Arc::new(DirectoryCapability {
            directory: root_directory,
            identity: root_identity,
            relative: PathBuf::new(),
            parent: None,
            name: None,
        }),
        canonical,
        requested_absolute,
    };
    hook(ReadBoundary::RootOpened, Path::new("."), &root.canonical)?;
    let root_capability = root.directory.clone();

    let root_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid(path, "requirements source is not a regular file"))?;

    let mut parser = RequirementsParser {
        root,
        limits,
        active: Vec::new(),
        files_read: 0,
        bytes_read: 0,
        registry_origin_ambiguous: false,
        range_resolution_ambiguous: false,
        constraints: BTreeMap::new(),
        hook,
    };
    let mut packages = parser.parse_file(
        Path::new(root_name),
        FileRole::Requirement,
        &root_capability,
    )?;
    apply_constraints(path, &mut packages, &parser.constraints)?;
    if parser.registry_origin_ambiguous {
        for package in &mut packages {
            package.enrichable = false;
        }
    } else if parser.range_resolution_ambiguous {
        for package in &mut packages {
            if package.resolved_from_range {
                package.enrichable = false;
            }
        }
    }
    Ok(dedup(packages))
}

pub(super) struct RequirementsParser<'hook> {
    pub(super) root: RequirementsRoot,
    pub(super) limits: RequirementsLimits,
    pub(super) active: Vec<ActiveFile>,
    pub(super) files_read: usize,
    pub(super) bytes_read: u64,
    pub(super) registry_origin_ambiguous: bool,
    pub(super) range_resolution_ambiguous: bool,
    pub(super) constraints: BTreeMap<String, Vec<ConstraintSpec>>,
    pub(super) hook: &'hook mut dyn FnMut(ReadBoundary, &Path, &Path) -> Result<(), ParseError>,
}

pub(super) fn apply_constraints(
    root: &Path,
    packages: &mut [Package],
    constraints: &BTreeMap<String, Vec<ConstraintSpec>>,
) -> Result<(), ParseError> {
    for package in packages {
        let Some(additional) = constraints.get(&package.name) else {
            continue;
        };
        if let Some(declared) = package.manifest_constraint.take() {
            let raw = std::iter::once(declared.raw())
                .chain(additional.iter().map(|constraint| constraint.raw.as_str()))
                .filter(|constraint| *constraint != "*")
                .collect::<Vec<_>>()
                .join(", ");
            let normalized = std::iter::once(declared.normalized())
                .chain(
                    additional
                        .iter()
                        .map(|constraint| constraint.normalized.as_str()),
                )
                .collect::<Vec<_>>()
                .join(",");
            let normalized = normalized
                .parse::<VersionSpecifiers>()
                .map_err(|error| {
                    invalid(
                        root,
                        format!(
                            "combined constraint for {:?} is invalid: {error}",
                            package.display_name
                        ),
                    )
                })?
                .to_string();
            package.set_normalized_manifest_constraint(
                if raw.is_empty() { "*" } else { &raw },
                normalized,
            );
        } else if !package.resolved_from_range {
            let normalized = additional
                .iter()
                .map(|constraint| constraint.normalized.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let specifiers = normalized.parse::<VersionSpecifiers>().map_err(|error| {
                invalid(
                    root,
                    format!(
                        "constraint for {:?} is invalid: {error}",
                        package.display_name
                    ),
                )
            })?;
            let version = package.version.parse::<Pep440Version>().map_err(|error| {
                invalid(
                    root,
                    format!(
                        "pinned version for {:?} is invalid: {error}",
                        package.display_name
                    ),
                )
            })?;
            if !specifiers.contains(&version) {
                return Err(invalid(
                    root,
                    format!(
                        "pinned requirement {:?}=={} conflicts with its constraints",
                        package.display_name, package.version
                    ),
                ));
            }
        }
    }
    Ok(())
}

impl RequirementsParser<'_> {
    pub(super) fn parse_file(
        &mut self,
        relative: &Path,
        role: FileRole,
        base: &Arc<DirectoryCapability>,
    ) -> Result<Vec<Package>, ParseError> {
        let display = self.root.canonical.join(relative);
        let depth = self.active.len();
        if depth > self.limits.include_depth {
            return Err(self.rejected(
                &display,
                format!(
                    "requirements include depth {depth} exceeds the maximum of {}",
                    self.limits.include_depth
                ),
            ));
        }
        if self.files_read >= self.limits.files {
            return Err(self.rejected(
                &display,
                format!(
                    "requirements file count exceeds the maximum of {}",
                    self.limits.files
                ),
            ));
        }

        let mut opened = self.open_file(relative, base)?;
        if self
            .active
            .iter()
            .any(|active| active.identity == opened.identity)
        {
            return Err(self.rejected(&opened.display, "requirements include cycle detected"));
        }
        self.active.push(ActiveFile {
            display: opened.display.clone(),
            identity: file_identity(&opened.file, &opened.display)?,
        });
        let result = self.read_and_parse(&mut opened, role);
        self.active.pop();
        result
    }

    pub(super) fn open_file(
        &mut self,
        relative: &Path,
        base: &Arc<DirectoryCapability>,
    ) -> Result<OpenRequirementsFile, ParseError> {
        let relative = normalize_relative(relative).ok_or_else(|| {
            self.rejected(
                &self.root.canonical.join(relative),
                format!(
                    "requirements include resolves outside scan root {}",
                    self.root.canonical.display()
                ),
            )
        })?;
        let logical_name = relative
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| self.rejected(&relative, "requirements include is not a regular file"))?
            .to_os_string();
        let logical_parent_relative = relative.parent().unwrap_or_else(|| Path::new(""));
        let logical_parent = self.resolve_directory(logical_parent_relative, base)?;
        let logical_display = self.root.canonical.join(&relative);
        let first_file =
            self.open_regular_nofollow(&logical_parent.directory, &logical_name, &logical_display)?;
        let first_identity = file_identity(&first_file, &logical_display)?;

        let canonical_relative = self
            .root
            .directory
            .directory
            .canonicalize(&relative)
            .map_err(|error| {
                self.rejected(
                    &logical_display,
                    format!(
                        "requirements include path changed while resolving within scan root: {error}"
                    ),
                )
            })?;
        let canonical_relative = normalize_relative(&canonical_relative).ok_or_else(|| {
            self.rejected(
                &logical_display,
                format!(
                    "requirements include resolves outside scan root {}",
                    self.root.canonical.display()
                ),
            )
        })?;
        let name = canonical_relative
            .file_name()
            .filter(|name| !name.is_empty())
            .expect("a normalized requirements path has a final component")
            .to_os_string();
        let canonical_parent_relative =
            canonical_relative.parent().unwrap_or_else(|| Path::new(""));
        let parent = self.resolve_directory(canonical_parent_relative, base)?;
        let display = self.root.canonical.join(&canonical_relative);
        let canonical_file = self.open_regular_nofollow(&parent.directory, &name, &display)?;
        if file_identity(&canonical_file, &display)? != first_identity {
            return Err(self.rejected(
                &logical_display,
                "requirements file changed while its capability was acquired",
            ));
        }
        let identity = file_identity(&first_file, &display)?;
        (self.hook)(ReadBoundary::FileOpened, &canonical_relative, &display)?;
        Ok(OpenRequirementsFile {
            file: first_file,
            identity,
            parent,
            logical_parent,
            relative: canonical_relative,
            display,
            name,
            logical_name,
        })
    }

    pub(super) fn open_regular_nofollow(
        &self,
        parent: &Dir,
        name: &OsStr,
        display: &Path,
    ) -> Result<File, ParseError> {
        let metadata = parent.symlink_metadata(name).map_err(|error| {
            self.rejected(
                display,
                format!("cannot inspect requirements file: {error}"),
            )
        })?;
        if metadata.is_symlink() {
            return Err(self.rejected(
                display,
                "requirements file is a symbolic link; symbolic includes are not allowed",
            ));
        }
        if !metadata.is_file() {
            return Err(self.rejected(display, "requirements include is not a regular file"));
        }
        let mut options = OpenOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let file = parent.open_with(name, &options).map_err(|error| {
            self.rejected(
                display,
                format!("cannot open requirements file without following links: {error}"),
            )
        })?;
        let metadata = file.metadata().map_err(|error| {
            self.rejected(
                display,
                format!("cannot inspect open requirements file: {error}"),
            )
        })?;
        if !metadata.is_file() {
            return Err(self.rejected(display, "requirements include is not a regular file"));
        }
        Ok(file)
    }
}
