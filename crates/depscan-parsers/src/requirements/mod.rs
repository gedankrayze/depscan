use super::{dedup, invalid};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, File, OpenOptions},
};
use depscan_core::{Ecosystem, FileIdentity, Package, ParseError, normalize_name};
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
    FileIdentity::from_owned_file(file).map_err(|error| {
        invalid(
            path,
            format!("cannot identify requirements directory: {error}"),
        )
    })
}

fn file_identity(file: &File, path: &Path) -> Result<FileIdentity, ParseError> {
    let file = file
        .try_clone()
        .map_err(|error| invalid(path, format!("cannot clone requirements file: {error}")))?
        .into_std();
    FileIdentity::from_owned_file(file)
        .map_err(|error| invalid(path, format!("cannot identify requirements file: {error}")))
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

mod diagnostics;
mod parser;
mod reading;
mod traversal;

use parser::*;

#[cfg(test)]
mod tests;
