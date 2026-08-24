use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};

const DEFAULT_NPM_REGISTRY: &str = "https://registry.npmjs.org";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BunLockVersion {
    V0,
    V1,
    V2,
    V3,
}

impl BunLockVersion {
    pub(crate) fn parse(path: &Path, value: &Json) -> Result<Self, ParseError> {
        let version = value
            .get("lockfileVersion")
            .and_then(Json::as_f64)
            .ok_or_else(|| invalid(path, "Bun lockfile is missing an integer lockfileVersion"))?;
        if version < 0.0 || version.fract() != 0.0 {
            return Err(invalid(
                path,
                "Bun lockfile is missing an integer lockfileVersion",
            ));
        }
        match version {
            0.0 => Ok(Self::V0),
            1.0 => Ok(Self::V1),
            2.0 => Ok(Self::V2),
            3.0 => Ok(Self::V3),
            _ => Err(invalid(
                path,
                format!(
                    "unsupported Bun lockfileVersion {version}; supported versions are 0, 1, 2, and 3"
                ),
            )),
        }
    }

    pub(crate) const fn number(self) -> u8 {
        match self {
            Self::V0 => 0,
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
        }
    }
}

pub(crate) fn validate_bun_config_version(path: &Path, value: &Json) -> Result<(), ParseError> {
    let Some(config_version) = value.get("configVersion") else {
        return Ok(());
    };
    let Some(config_version) = config_version.as_f64() else {
        return Err(invalid(
            path,
            "Bun configVersion must be a non-negative integer",
        ));
    };
    if config_version < 0.0 || config_version.fract() != 0.0 {
        return Err(invalid(
            path,
            "Bun configVersion must be a non-negative integer",
        ));
    }
    Ok(())
}

pub(crate) fn bun_registry_integrity_is_valid(registry: &str, integrity: &str) -> bool {
    registry.is_empty()
        || url_is_under_default_npm_registry(registry)
        || has_supported_integrity(integrity)
}

fn url_is_under_default_npm_registry(url: &str) -> bool {
    let registry = DEFAULT_NPM_REGISTRY.trim_end_matches('/');
    url == registry
        || url
            .strip_prefix(registry)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn has_supported_integrity(integrity: &str) -> bool {
    integrity.split_ascii_whitespace().any(|entry| {
        let entry = entry.split_once('?').map_or(entry, |(value, _)| value);
        let Some((algorithm, digest)) = entry.split_once('-') else {
            return false;
        };
        let maximum_length = match algorithm {
            "sha1" => 20,
            "sha256" => 32,
            "sha384" => 48,
            "sha512" => 64,
            _ => return false,
        };
        STANDARD_NO_PAD
            .decode(digest.trim_end_matches('='))
            .is_ok_and(|decoded| decoded.len() <= maximum_length)
    })
}

pub(crate) fn is_safe_bun_git_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 256
        && !tag.starts_with('-')
        && !matches!(tag, "." | "..")
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
