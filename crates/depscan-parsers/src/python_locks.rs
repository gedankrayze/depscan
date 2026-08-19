use depscan_core::{Ecosystem, Package, ParseError, normalize_name};
use pep440_rs::Version as Pep440Version;
use std::{fs, path::Path};
use toml::{Table, Value as Toml};

use super::{dedup, invalid, io_error};

mod poetry;
mod uv;

pub(super) use poetry::parse_poetry_lock;
pub(super) use uv::parse_uv_lock;

const UV_LOCK_VERSION: i64 = 1;
const PYPI_INDEX: &str = "https://pypi.org/simple";

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum PythonSource {
    Registry(String),
    Git(String),
    Url(String),
    Path(String),
    Directory(String),
    Editable(String),
    Virtual(String),
}

impl PythonSource {
    fn enrichable(&self) -> bool {
        matches!(self, Self::Registry(url) if is_pypi_index(url))
    }

    fn is_project_root(&self) -> bool {
        matches!(
            self,
            Self::Directory(path) | Self::Editable(path) | Self::Virtual(path)
                if path == "."
        )
    }

    fn allows_missing_version(&self) -> bool {
        matches!(
            self,
            Self::Directory(_) | Self::Editable(_) | Self::Virtual(_)
        )
    }
}

fn read_toml(path: &Path) -> Result<Toml, ParseError> {
    let text = fs::read_to_string(path).map_err(|error| io_error(path, error))?;
    toml::from_str(&text).map_err(|error| invalid(path, error))
}

fn required_string<'a>(
    table: &'a Table,
    key: &str,
    path: &Path,
    context: &str,
) -> Result<&'a str, ParseError> {
    table
        .get(key)
        .and_then(Toml::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            invalid(
                path,
                format!("{context} is missing a non-empty string {key}"),
            )
        })
}

fn required_integer(
    table: &Table,
    key: &str,
    path: &Path,
    context: &str,
) -> Result<i64, ParseError> {
    table
        .get(key)
        .and_then(Toml::as_integer)
        .ok_or_else(|| invalid(path, format!("{context} is missing an integer {key}")))
}

fn required_bool(table: &Table, key: &str, path: &Path, context: &str) -> Result<bool, ParseError> {
    table
        .get(key)
        .and_then(Toml::as_bool)
        .ok_or_else(|| invalid(path, format!("{context} is missing a boolean {key}")))
}

fn required_array<'a>(
    table: &'a Table,
    key: &str,
    path: &Path,
    context: &str,
) -> Result<&'a Vec<Toml>, ParseError> {
    table
        .get(key)
        .and_then(Toml::as_array)
        .ok_or_else(|| invalid(path, format!("{context} is missing an array {key}")))
}

fn optional_version(
    value: Option<&Toml>,
    path: &Path,
    context: &str,
) -> Result<Option<String>, ParseError> {
    value
        .map(|value| {
            let version = value
                .as_str()
                .filter(|version| !version.is_empty())
                .ok_or_else(|| {
                    invalid(
                        path,
                        format!("{context} version must be a non-empty string"),
                    )
                })?;
            validate_version(version, path, context)?;
            Ok(version.to_owned())
        })
        .transpose()
}

fn validate_version(version: &str, path: &Path, context: &str) -> Result<(), ParseError> {
    version
        .parse::<Pep440Version>()
        .map(|_| ())
        .map_err(|error| {
            invalid(
                path,
                format!("{context} version {version:?} is not valid PEP 440: {error}"),
            )
        })
}

fn normalized_name(name: &str, path: &Path, context: &str) -> Result<String, ParseError> {
    let first = name.chars().next();
    let last = name.chars().last();
    if !first.is_some_and(|character| character.is_ascii_alphanumeric())
        || !last.is_some_and(|character| character.is_ascii_alphanumeric())
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(invalid(
            path,
            format!("{context} contains invalid Python package name {name:?}"),
        ));
    }
    Ok(normalize_name(Ecosystem::PyPI, name))
}

fn is_pypi_index(url: &str) -> bool {
    url.trim_end_matches('/').eq_ignore_ascii_case(PYPI_INDEX)
}
