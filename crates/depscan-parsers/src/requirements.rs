use super::{dedup, invalid};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, File, OpenOptions},
};
use depscan_core::{Ecosystem, Package, ParseError, normalize_name};
use pep440_rs::{Version as Pep440Version, VersionSpecifiers};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

mod process_barrier;
mod syntax;

use process_barrier::process_test_barrier;
use syntax::{ConstraintSpec, GlobalOption, IncludeKind, ParsedLine};

const MAX_INCLUDE_DEPTH: usize = 32;
const MAX_REQUIREMENTS_FILES: usize = 256;
const MAX_REQUIREMENTS_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Copy)]
struct RequirementsLimits {
    include_depth: usize,
    files: usize,
    bytes: u64,
}

impl Default for RequirementsLimits {
    fn default() -> Self {
        Self {
            include_depth: MAX_INCLUDE_DEPTH,
            files: MAX_REQUIREMENTS_FILES,
            bytes: MAX_REQUIREMENTS_BYTES,
        }
    }
}

pub(crate) fn parse(path: &Path) -> Result<Vec<Package>, ParseError> {
    parse_with_limits(path, RequirementsLimits::default())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileRole {
    Requirement,
    Constraint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadBoundary {
    RootOpened,
    DirectoryOpened,
    FileOpened,
    BeforeRead,
    AfterRead,
}

impl ReadBoundary {
    #[cfg(debug_assertions)]
    fn label(self) -> &'static str {
        match self {
            Self::RootOpened => "root-opened",
            Self::DirectoryOpened => "directory-opened",
            Self::FileOpened => "file-opened",
            Self::BeforeRead => "before-read",
            Self::AfterRead => "after-read",
        }
    }
}

struct RequirementsRoot {
    directory: Arc<DirectoryCapability>,
    canonical: PathBuf,
    requested_absolute: PathBuf,
}

struct DirectoryCapability {
    directory: Dir,
    identity: FileIdentity,
    relative: PathBuf,
    parent: Option<Arc<Self>>,
    name: Option<PathBuf>,
}

struct OpenRequirementsFile {
    file: File,
    identity: FileIdentity,
    parent: Arc<DirectoryCapability>,
    logical_parent: Arc<DirectoryCapability>,
    relative: PathBuf,
    display: PathBuf,
    name: OsString,
    logical_name: OsString,
}

struct ActiveFile {
    display: PathBuf,
    identity: FileIdentity,
}

#[derive(Debug)]
struct FileIdentity {
    key: IdentityKey,
    _handle: std::fs::File,
}

impl PartialEq for FileIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for FileIdentity {}

#[derive(Debug, PartialEq, Eq)]
enum IdentityKey {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },
    #[cfg(windows)]
    Windows {
        volume_serial_number: u64,
        file_id: [u8; 16],
    },
}

#[cfg(unix)]
fn platform_file_identity(file: &std::fs::File) -> std::io::Result<IdentityKey> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    Ok(IdentityKey::Unix {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn platform_file_identity(file: &std::fs::File) -> std::io::Result<IdentityKey> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx},
    };

    let mut information = FILE_ID_INFO::default();
    // SAFETY: `file` owns a valid handle for this call, `information` provides a correctly sized
    // initialized writable FILE_ID_INFO buffer, and the return value is checked before its fields
    // are trusted.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileIdInfo,
            (&raw mut information).cast(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>())
                .expect("FILE_ID_INFO size fits a Windows DWORD"),
        )
    };
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(IdentityKey::Windows {
        volume_serial_number: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    })
}

fn directory_identity(directory: &Dir, path: &Path) -> Result<FileIdentity, ParseError> {
    let file = directory
        .try_clone()
        .map_err(|error| {
            invalid(
                path,
                format!("cannot clone requirements directory: {error}"),
            )
        })?
        .into_std_file();
    let key = platform_file_identity(&file).map_err(|error| {
        invalid(
            path,
            format!("cannot identify requirements directory: {error}"),
        )
    })?;
    Ok(FileIdentity { key, _handle: file })
}

fn file_identity(file: &File, path: &Path) -> Result<FileIdentity, ParseError> {
    let file = file
        .try_clone()
        .map_err(|error| invalid(path, format!("cannot clone requirements file: {error}")))?
        .into_std();
    let key = platform_file_identity(&file)
        .map_err(|error| invalid(path, format!("cannot identify requirements file: {error}")))?;
    Ok(FileIdentity { key, _handle: file })
}

fn lexical_absolute(path: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| error.to_string())?
            .join(path)
    };
    normalize_lexical(&absolute).ok_or_else(|| "path escapes its filesystem root".to_owned())
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
    (!normalized.as_os_str().is_empty()).then_some(normalized)
}

#[cfg(not(windows))]
fn strip_root_prefix(path: &Path, root: &Path) -> Option<PathBuf> {
    path.strip_prefix(root).ok().map(Path::to_path_buf)
}

#[cfg(windows)]
fn strip_root_prefix(path: &Path, root: &Path) -> Option<PathBuf> {
    let path_components = path.components().collect::<Vec<_>>();
    let root_components = root.components().collect::<Vec<_>>();
    if root_components.len() > path_components.len()
        || !root_components
            .iter()
            .zip(&path_components)
            .all(|(expected, actual)| {
                expected
                    .as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&actual.as_os_str().to_string_lossy())
            })
    {
        return None;
    }
    let mut relative = PathBuf::new();
    for component in &path_components[root_components.len()..] {
        relative.push(component.as_os_str());
    }
    Some(relative)
}

fn parse_with_limits(path: &Path, limits: RequirementsLimits) -> Result<Vec<Package>, ParseError> {
    let mut hook = |boundary, relative: &Path, display: &Path| {
        process_test_barrier(boundary, relative, display)
    };
    parse_with_limits_and_hook(path, limits, &mut hook)
}

fn parse_with_limits_and_hook(
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

struct RequirementsParser<'hook> {
    root: RequirementsRoot,
    limits: RequirementsLimits,
    active: Vec<ActiveFile>,
    files_read: usize,
    bytes_read: u64,
    registry_origin_ambiguous: bool,
    range_resolution_ambiguous: bool,
    constraints: BTreeMap<String, Vec<ConstraintSpec>>,
    hook: &'hook mut dyn FnMut(ReadBoundary, &Path, &Path) -> Result<(), ParseError>,
}

fn apply_constraints(
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
    fn parse_file(
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

    fn open_file(
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

    fn open_regular_nofollow(
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

    fn resolve_directory(
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

    fn read_and_parse(
        &mut self,
        opened: &mut OpenRequirementsFile,
        role: FileRole,
    ) -> Result<Vec<Package>, ParseError> {
        let metadata = opened.file.metadata().map_err(|error| {
            self.current_error(
                &opened.display,
                format!("cannot inspect open requirements file: {error}"),
            )
        })?;
        let remaining = self.limits.bytes.saturating_sub(self.bytes_read);
        if metadata.len() > remaining {
            return Err(self.current_error(
                &opened.display,
                format!(
                    "requirements input exceeds the maximum total of {} bytes",
                    self.limits.bytes
                ),
            ));
        }

        (self.hook)(ReadBoundary::BeforeRead, &opened.relative, &opened.display)?;
        let mut bytes = Vec::new();
        (&mut opened.file)
            .take(remaining.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| {
                self.current_error(
                    &opened.display,
                    format!("cannot read requirements file: {error}"),
                )
            })?;
        (self.hook)(ReadBoundary::AfterRead, &opened.relative, &opened.display)?;
        self.revalidate_file(opened)?;

        let byte_count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if byte_count > remaining {
            return Err(self.current_error(
                &opened.display,
                format!(
                    "requirements input exceeds the maximum total of {} bytes",
                    self.limits.bytes
                ),
            ));
        }
        self.files_read += 1;
        self.bytes_read += byte_count;

        let text = String::from_utf8(bytes).map_err(|error| {
            self.current_error(
                &opened.display,
                format!("requirements file is not valid UTF-8: {error}"),
            )
        })?;
        self.parse_text(
            &opened.display,
            &opened.relative,
            &opened.parent,
            &text,
            role,
        )
    }

    fn revalidate_file(&self, opened: &OpenRequirementsFile) -> Result<(), ParseError> {
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

    fn revalidate_directory(
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

    fn revalidate_name(
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

    fn parse_text(
        &mut self,
        canonical: &Path,
        relative: &Path,
        parent: &Arc<DirectoryCapability>,
        text: &str,
        role: FileRole,
    ) -> Result<Vec<Package>, ParseError> {
        let mut packages = Vec::new();
        let logical_lines = syntax::logical_lines(text).map_err(|error| {
            self.current_error(
                canonical,
                format!("invalid requirements syntax: {}", error.message()),
            )
        })?;
        let base = canonical
            .parent()
            .unwrap_or(&self.root.canonical)
            .to_path_buf();
        for logical in logical_lines {
            let parsed = syntax::parse_line(&logical.text, &base).map_err(|error| {
                self.current_error(
                    canonical,
                    format!(
                        "invalid requirements syntax at line {}: {}",
                        logical.number,
                        error.message()
                    ),
                )
            })?;
            match parsed {
                ParsedLine::Empty | ParsedLine::Global(GlobalOption::Ignored) => {}
                ParsedLine::Global(GlobalOption::AmbiguousRegistry) => {
                    self.registry_origin_ambiguous = true;
                }
                ParsedLine::Global(GlobalOption::AmbiguousRangeResolution) => {
                    self.range_resolution_ambiguous = true;
                    tracing::warn!(
                        source_file = %canonical.display(),
                        line = logical.number,
                        "requirements option changes release selection; range freshness is disabled"
                    );
                }
                ParsedLine::Include { kind, target } => {
                    if target.contains("://") {
                        return Err(self.current_error(
                            canonical,
                            format!(
                                "remote requirements include at line {} is not supported; includes must remain inside the scan root",
                                logical.number
                            ),
                        ));
                    }
                    let include_path = Path::new(&target);
                    let requested_display = if include_path.is_absolute() {
                        include_path.to_path_buf()
                    } else {
                        base.join(include_path)
                    };
                    let requested =
                        self.include_relative(relative, include_path)
                            .ok_or_else(|| {
                                self.rejected(
                                    &requested_display,
                                    format!(
                                        "requirements include resolves outside scan root {}",
                                        self.root.canonical.display()
                                    ),
                                )
                            })?;
                    let include_role = match kind {
                        IncludeKind::Requirement => role,
                        IncludeKind::Constraint => FileRole::Constraint,
                    };
                    packages.extend(self.parse_file(&requested, include_role, parent)?);
                }
                ParsedLine::Package(spec) => {
                    if spec.has_marker {
                        tracing::warn!(
                            source_file = %canonical.display(),
                            line = logical.number,
                            "requirements environment marker is assumed true"
                        );
                    }
                    if role == FileRole::Constraint {
                        if !spec.constraint_compatible {
                            return Err(self.current_error(
                                canonical,
                                format!(
                                    "invalid constraint at line {}: constraints must be named, non-editable requirements without extras or direct URLs",
                                    logical.number
                                ),
                            ));
                        }
                        let constraint = spec.registry_constraint.ok_or_else(|| {
                            self.current_error(
                                canonical,
                                format!(
                                    "invalid constraint at line {}: constraint has no registry version expression",
                                    logical.number
                                ),
                            )
                        })?;
                        self.constraints
                            .entry(normalize_name(Ecosystem::PyPI, &spec.display_name))
                            .or_default()
                            .push(constraint);
                        continue;
                    }
                    let mut package = Package::new(
                        Ecosystem::PyPI,
                        spec.display_name,
                        spec.version,
                        canonical.to_path_buf(),
                    );
                    package.direct = true;
                    package.dev_known = false;
                    package.enrichable = spec.enrichable;
                    package.resolved_from_range = spec.resolved_from_range;
                    if spec.resolved_from_range
                        && let Some(constraint) = spec.registry_constraint
                    {
                        package.set_normalized_manifest_constraint(
                            constraint.raw,
                            constraint.normalized,
                        );
                    }
                    packages.push(package);
                }
            }
        }
        Ok(packages)
    }

    fn include_relative(&self, including: &Path, requested: &Path) -> Option<PathBuf> {
        if requested.is_absolute() {
            let requested = normalize_lexical(requested)?;
            return strip_root_prefix(&requested, &self.root.canonical)
                .or_else(|| strip_root_prefix(&requested, &self.root.requested_absolute))
                .and_then(|relative| normalize_relative(&relative));
        }
        let base = including.parent().unwrap_or_else(|| Path::new(""));
        normalize_relative(&base.join(requested))
    }

    fn rejected(&self, requested: &Path, message: impl AsRef<str>) -> ParseError {
        invalid(
            requested,
            format!(
                "{}; requirements include chain: {}",
                message.as_ref(),
                self.include_chain(Some(requested))
            ),
        )
    }

    fn current_error(&self, path: &Path, message: impl AsRef<str>) -> ParseError {
        invalid(
            path,
            format!(
                "{}; requirements include chain: {}",
                message.as_ref(),
                self.include_chain(None)
            ),
        )
    }

    fn include_chain(&self, next: Option<&Path>) -> String {
        self.active
            .iter()
            .map(|active| active.display.display().to_string())
            .chain(next.into_iter().map(|path| path.display().to_string()))
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}
#[cfg(test)]
mod tests;
