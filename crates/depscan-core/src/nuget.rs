use std::{cmp::Ordering, str::FromStr};

use thiserror::Error;

const SYSTEM_VERSION_COMPONENT_MAX: u32 = i32::MAX as u32;

/// A NuGet version parsed according to NuGet's SemVer 2 and legacy four-part rules.
///
/// Release components are normalized to four integers. Build metadata is validated but omitted
/// from the value because NuGet's default version precedence and identity ignore it.
#[derive(Debug, Clone)]
pub struct NuGetVersion {
    release: [u32; 4],
    prerelease: Vec<PrereleaseIdentifier>,
}

#[derive(Debug, Clone)]
enum PrereleaseIdentifier {
    Numeric(String),
    AlphaNumeric(String),
}

/// A NuGet version could not be parsed without inventing version components.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid NuGet version {version:?}: {reason}")]
pub struct NuGetVersionError {
    version: String,
    reason: String,
}

impl NuGetVersionError {
    fn new(version: &str, reason: impl Into<String>) -> Self {
        Self {
            version: version.to_owned(),
            reason: reason.into(),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl NuGetVersion {
    pub fn parse(value: &str) -> Result<Self, NuGetVersionError> {
        value.parse()
    }

    pub fn is_prerelease(&self) -> bool {
        !self.prerelease.is_empty()
    }

    pub fn release_segments(&self) -> &[u32; 4] {
        &self.release
    }

    /// Return NuGet's normalized identity form: three release components, an optional non-zero
    /// revision and prerelease labels, with build metadata omitted.
    pub fn to_normalized_string(&self) -> String {
        let mut normalized = format!(
            "{}.{}.{}",
            self.release[0], self.release[1], self.release[2]
        );
        if self.release[3] != 0 {
            normalized.push('.');
            normalized.push_str(&self.release[3].to_string());
        }
        if !self.prerelease.is_empty() {
            normalized.push('-');
            for (index, identifier) in self.prerelease.iter().enumerate() {
                if index != 0 {
                    normalized.push('.');
                }
                normalized.push_str(identifier.as_str());
            }
        }
        normalized
    }
}

impl FromStr for NuGetVersion {
    type Err = NuGetVersionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let candidate = value.trim();
        if candidate.is_empty() {
            return Err(NuGetVersionError::new(value, "version is empty"));
        }

        let mut build_sections = candidate.split('+');
        let core = build_sections
            .next()
            .expect("split always yields one section");
        if let Some(metadata) = build_sections.next() {
            if build_sections.next().is_some() {
                return Err(NuGetVersionError::new(
                    value,
                    "version contains more than one build metadata separator",
                ));
            }
            validate_identifiers(value, metadata, IdentifierKind::BuildMetadata)?;
        }

        let (release, prerelease) = core
            .split_once('-')
            .map_or((core, None), |(release, prerelease)| {
                (release, Some(prerelease))
            });
        let prerelease = prerelease
            .map(|prerelease| parse_prerelease(value, prerelease))
            .transpose()?
            .unwrap_or_default();

        let components = release.split('.').collect::<Vec<_>>();
        if components.is_empty() || components.len() > 4 {
            return Err(NuGetVersionError::new(
                value,
                "release must contain between one and four numeric components",
            ));
        }

        let mut normalized = [0; 4];
        for (index, component) in components.into_iter().enumerate() {
            normalized[index] = parse_release_component(value, component.trim())?;
        }

        Ok(Self {
            release: normalized,
            prerelease,
        })
    }
}

fn parse_release_component(value: &str, component: &str) -> Result<u32, NuGetVersionError> {
    if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(NuGetVersionError::new(
            value,
            "release components must be non-empty decimal integers",
        ));
    }

    let mut parsed = 0_u32;
    for digit in component.bytes().map(|byte| u32::from(byte - b'0')) {
        parsed = parsed
            .checked_mul(10)
            .and_then(|parsed| parsed.checked_add(digit))
            .filter(|parsed| *parsed <= SYSTEM_VERSION_COMPONENT_MAX)
            .ok_or_else(|| {
                NuGetVersionError::new(
                    value,
                    format!("release components must not exceed {SYSTEM_VERSION_COMPONENT_MAX}"),
                )
            })?;
    }
    Ok(parsed)
}

#[derive(Debug, Clone, Copy)]
enum IdentifierKind {
    Prerelease,
    BuildMetadata,
}

impl IdentifierKind {
    fn label(self) -> &'static str {
        match self {
            Self::Prerelease => "prerelease",
            Self::BuildMetadata => "build metadata",
        }
    }
}

fn validate_identifiers(
    version: &str,
    value: &str,
    kind: IdentifierKind,
) -> Result<(), NuGetVersionError> {
    for identifier in value.split('.') {
        if identifier.is_empty()
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(NuGetVersionError::new(
                version,
                format!(
                    "{} identifiers must be non-empty ASCII alphanumeric or hyphen strings",
                    kind.label()
                ),
            ));
        }
        if matches!(kind, IdentifierKind::Prerelease)
            && identifier.len() > 1
            && identifier.bytes().all(|byte| byte.is_ascii_digit())
            && identifier.starts_with('0')
        {
            return Err(NuGetVersionError::new(
                version,
                "numeric prerelease identifiers must not contain leading zeroes",
            ));
        }
    }
    Ok(())
}

fn parse_prerelease(
    version: &str,
    prerelease: &str,
) -> Result<Vec<PrereleaseIdentifier>, NuGetVersionError> {
    validate_identifiers(version, prerelease, IdentifierKind::Prerelease)?;
    Ok(prerelease
        .split('.')
        .map(|identifier| {
            if identifier.bytes().all(|byte| byte.is_ascii_digit()) {
                PrereleaseIdentifier::Numeric(identifier.to_owned())
            } else {
                PrereleaseIdentifier::AlphaNumeric(identifier.to_owned())
            }
        })
        .collect())
}

impl PrereleaseIdentifier {
    fn as_str(&self) -> &str {
        match self {
            Self::Numeric(value) | Self::AlphaNumeric(value) => value,
        }
    }
}

fn compare_ascii_case_insensitive(left: &str, right: &str) -> Ordering {
    left.bytes()
        .map(|byte| byte.to_ascii_lowercase())
        .cmp(right.bytes().map(|byte| byte.to_ascii_lowercase()))
}

impl Ord for PrereleaseIdentifier {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Numeric(left), Self::Numeric(right)) => {
                left.len().cmp(&right.len()).then_with(|| left.cmp(right))
            }
            (Self::Numeric(_), Self::AlphaNumeric(_)) => Ordering::Less,
            (Self::AlphaNumeric(_), Self::Numeric(_)) => Ordering::Greater,
            (Self::AlphaNumeric(left), Self::AlphaNumeric(right)) => {
                compare_ascii_case_insensitive(left, right)
            }
        }
    }
}

impl PartialOrd for PrereleaseIdentifier {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PrereleaseIdentifier {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for PrereleaseIdentifier {}

impl Ord for NuGetVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.release.cmp(&other.release).then_with(|| {
            match (self.prerelease.is_empty(), other.prerelease.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.prerelease.cmp(&other.prerelease),
            }
        })
    }
}

impl PartialOrd for NuGetVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for NuGetVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for NuGetVersion {}

#[cfg(test)]
#[path = "nuget/tests.rs"]
mod tests;
