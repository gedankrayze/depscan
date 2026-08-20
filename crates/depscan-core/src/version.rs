use crate::{Ecosystem, NuGetVersion, Staleness};
use pep440_rs::Version as Pep440Version;
use semver::Version;
use std::cmp::Ordering;

pub fn compare_versions(ecosystem: Ecosystem, a: &str, b: &str) -> Ordering {
    match ecosystem {
        Ecosystem::Npm | Ecosystem::CratesIo => Version::parse(a).ok().cmp(&Version::parse(b).ok()),
        Ecosystem::NuGet => compare_nuget(a, b),
        Ecosystem::PyPI => compare_pep440(a, b),
    }
}

fn compare_nuget(a: &str, b: &str) -> Ordering {
    match (NuGetVersion::parse(a), NuGetVersion::parse(b)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        // A malformed registry version must never displace a valid NuGet version.
        (Ok(_), Err(_)) => Ordering::Greater,
        (Err(_), Ok(_)) => Ordering::Less,
        (Err(_), Err(_)) => a
            .trim()
            .to_ascii_lowercase()
            .cmp(&b.trim().to_ascii_lowercase())
            .then_with(|| a.cmp(b)),
    }
}

fn parse_pep440(version: &str) -> Option<Pep440Version> {
    version.trim().parse().ok()
}

fn compare_pep440(a: &str, b: &str) -> Ordering {
    match (parse_pep440(a), parse_pep440(b)) {
        (Some(a), Some(b)) => a.cmp(&b),
        // A malformed registry version must never displace a valid PEP 440 version.
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => a
            .trim()
            .to_ascii_lowercase()
            .cmp(&b.trim().to_ascii_lowercase())
            .then_with(|| a.cmp(b)),
    }
}

/// Returns whether a PyPI version is a valid PEP 440 pre-release or development release.
/// Invalid versions return `false`.
pub fn pypi_version_is_prerelease(version: &str) -> bool {
    parse_pep440(version).is_some_and(|version| version.any_prerelease())
}

/// Returns whether a PyPI version is valid PEP 440 and stable.
/// Invalid versions return `false` so they cannot be selected as registry candidates.
pub fn pypi_version_is_stable(version: &str) -> bool {
    parse_pep440(version).is_some_and(|version| version.is_stable())
}

pub fn classify_staleness(ecosystem: Ecosystem, installed: &str, latest: &str) -> Staleness {
    if ecosystem == Ecosystem::NuGet {
        return match (NuGetVersion::parse(installed), NuGetVersion::parse(latest)) {
            (Ok(installed), Ok(latest)) if installed >= latest => Staleness::Current,
            (Ok(installed), Ok(latest)) => {
                classify_release_segments(installed.release_segments(), latest.release_segments())
            }
            _ => Staleness::Unknown,
        };
    }

    if compare_versions(ecosystem, installed, latest) != Ordering::Less {
        return Staleness::Current;
    }
    match ecosystem {
        Ecosystem::Npm | Ecosystem::CratesIo => {
            match (Version::parse(installed), Version::parse(latest)) {
                (Ok(a), Ok(b)) if a.major != b.major => Staleness::Major,
                (Ok(a), Ok(b)) if a.minor != b.minor => Staleness::Minor,
                (Ok(_), Ok(_)) => Staleness::Patch,
                _ => Staleness::Unknown,
            }
        }
        Ecosystem::NuGet => unreachable!("NuGet staleness is handled using parsed versions"),
        Ecosystem::PyPI => match (parse_pep440(installed), parse_pep440(latest)) {
            (Some(a), Some(b)) if a.epoch() != b.epoch() => Staleness::Major,
            (Some(a), Some(b)) => classify_release_segments(a.release(), b.release()),
            _ => Staleness::Unknown,
        },
    }
}

fn classify_release_segments<T: PartialEq>(installed: &[T], latest: &[T]) -> Staleness {
    if installed.first() != latest.first() {
        Staleness::Major
    } else if installed.get(1) != latest.get(1) {
        Staleness::Minor
    } else {
        Staleness::Patch
    }
}
