use depscan_core::ParseError;
use std::{collections::BTreeSet, path::Path};
use toml::{Table, Value as Toml};

use crate::invalid;

#[derive(Debug)]
pub(super) struct PoetrySourcePolicy {
    configured: BTreeSet<String>,
    unqualified_pypi: bool,
}

impl PoetrySourcePolicy {
    pub(super) fn parse(value: Option<&Toml>, path: &Path) -> Result<Self, ParseError> {
        let Some(value) = value else {
            return Ok(Self {
                configured: BTreeSet::new(),
                unqualified_pypi: true,
            });
        };
        let sources = value
            .as_array()
            .ok_or_else(|| invalid(path, "tool.poetry.source must be an array of tables"))?;
        let mut configured = BTreeSet::new();
        let mut unqualified_pypi = true;
        for (index, source) in sources.iter().enumerate() {
            let context = format!("tool.poetry.source entry {index}");
            let source = source
                .as_table()
                .ok_or_else(|| invalid(path, format!("{context} must be a table")))?;
            for key in source.keys() {
                if !matches!(key.as_str(), "name" | "url" | "priority") {
                    return Err(invalid(
                        path,
                        format!("{context} contains unsupported field {key:?}"),
                    ));
                }
            }
            let name = required_string(source, "name", path, &context)?;
            if !configured.insert(name.to_owned()) {
                return Err(invalid(
                    path,
                    format!("{context} duplicates Poetry source {name:?}"),
                ));
            }
            let priority =
                optional_string(source, "priority", path, &context)?.unwrap_or("primary");
            if !matches!(priority, "primary" | "supplemental" | "explicit") {
                return Err(invalid(
                    path,
                    format!("{context}.priority has unsupported value {priority:?}"),
                ));
            }
            let url = optional_string(source, "url", path, &context)?;
            if name.eq_ignore_ascii_case("pypi") {
                if url.is_some() {
                    return Err(invalid(
                        path,
                        format!("{context} must omit url for Poetry's built-in PyPI source"),
                    ));
                }
            } else {
                if url.is_none() {
                    return Err(invalid(
                        path,
                        format!("{context} must define a non-empty url"),
                    ));
                }
                if priority != "explicit" {
                    unqualified_pypi = false;
                }
            }
        }
        Ok(Self {
            configured,
            unqualified_pypi,
        })
    }

    pub(super) fn unqualified_pypi(&self) -> bool {
        self.unqualified_pypi
    }

    fn validate_named(&self, name: &str, path: &Path, context: &str) -> Result<(), ParseError> {
        if name.eq_ignore_ascii_case("pypi") || self.configured.contains(name) {
            Ok(())
        } else {
            Err(invalid(
                path,
                format!("{context} references unconfigured Poetry source {name:?}"),
            ))
        }
    }
}

#[derive(Debug)]
pub(super) enum PoetrySource {
    Registry,
    NamedRegistry(String),
    Git {
        location: String,
        reference: Option<String>,
        subdirectory: Option<String>,
    },
    Path {
        location: String,
        develop: bool,
    },
    Url(String),
}

impl PoetrySource {
    pub(super) fn parse(
        table: &Table,
        policy: &PoetrySourcePolicy,
        path: &Path,
        context: &str,
    ) -> Result<Self, ParseError> {
        let git = optional_string(table, "git", path, context)?;
        let local_path = optional_string(table, "path", path, context)?;
        let url = optional_string(table, "url", path, context)?;
        let named = optional_string(table, "source", path, context)?;
        let source_count = [
            git.is_some(),
            local_path.is_some(),
            url.is_some(),
            named.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if source_count > 1 {
            return Err(invalid(
                path,
                format!("{context} declares conflicting dependency sources"),
            ));
        }

        let mut selectors = Vec::new();
        for field in ["branch", "rev", "tag"] {
            if let Some(value) = optional_string(table, field, path, context)? {
                selectors.push((field, value));
            }
        }
        if selectors.len() > 1 {
            return Err(invalid(
                path,
                format!("{context} may define only one of branch, rev, or tag"),
            ));
        }
        let reference = selectors
            .into_iter()
            .next()
            .map(|(_, value)| value.to_owned());
        let subdirectory =
            optional_string(table, "subdirectory", path, context)?.map(str::to_owned);
        if (reference.is_some() || subdirectory.is_some()) && git.is_none() {
            return Err(invalid(
                path,
                format!("{context} branch/rev/tag/subdirectory fields require a git source"),
            ));
        }
        let develop = table
            .get("develop")
            .and_then(Toml::as_bool)
            .unwrap_or(false);
        if table.contains_key("develop") && local_path.is_none() {
            return Err(invalid(
                path,
                format!("{context}.develop requires a path source"),
            ));
        }

        Ok(if let Some(location) = git {
            Self::Git {
                location: location.to_owned(),
                reference,
                subdirectory,
            }
        } else if let Some(location) = local_path {
            Self::Path {
                location: location.to_owned(),
                develop,
            }
        } else if let Some(location) = url {
            Self::Url(location.to_owned())
        } else if let Some(name) = named {
            policy.validate_named(name, path, context)?;
            Self::NamedRegistry(name.to_owned())
        } else {
            Self::Registry
        })
    }

    pub(super) fn enrichable(&self, policy: &PoetrySourcePolicy) -> bool {
        matches!(self, Self::Registry) && policy.unqualified_pypi()
            || matches!(self, Self::NamedRegistry(name) if name.eq_ignore_ascii_case("pypi"))
    }

    pub(super) fn is_direct_origin(&self) -> bool {
        matches!(self, Self::Git { .. } | Self::Path { .. } | Self::Url(_))
    }

    pub(super) fn display(&self) -> Option<String> {
        match self {
            Self::Git {
                location,
                reference,
                subdirectory,
            } => {
                let mut display = format!("git+{location}");
                if let Some(reference) = reference {
                    display.push('@');
                    display.push_str(reference);
                }
                if let Some(subdirectory) = subdirectory {
                    display.push(if display.contains('#') { '&' } else { '#' });
                    display.push_str("subdirectory=");
                    display.push_str(subdirectory);
                }
                Some(display)
            }
            Self::Path { location, develop } => Some(if *develop {
                format!("path:{location}#develop=true")
            } else {
                format!("path:{location}")
            }),
            Self::Url(location) => Some(location.clone()),
            Self::Registry | Self::NamedRegistry(_) => None,
        }
    }
}

fn required_string<'a>(
    table: &'a Table,
    field: &str,
    path: &Path,
    context: &str,
) -> Result<&'a str, ParseError> {
    optional_string(table, field, path, context)?.ok_or_else(|| {
        invalid(
            path,
            format!("{context}.{field} must be a non-empty string"),
        )
    })
}

pub(super) fn optional_string<'a>(
    table: &'a Table,
    field: &str,
    path: &Path,
    context: &str,
) -> Result<Option<&'a str>, ParseError> {
    table
        .get(field)
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    invalid(
                        path,
                        format!("{context}.{field} must be a non-empty string"),
                    )
                })
        })
        .transpose()
}
