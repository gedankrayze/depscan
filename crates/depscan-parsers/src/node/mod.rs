use super::*;

pub struct NodeParser;
impl EcosystemParser for NodeParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }
    fn detect(&self, root: &Path) -> Vec<DetectedSource> {
        for (file, kind) in [
            ("bun.lock", SourceKind::BunLock),
            ("bun.lockb", SourceKind::BunLockBinary),
            ("package-lock.json", SourceKind::PackageLock),
            ("pnpm-lock.yaml", SourceKind::PnpmLock),
            ("yarn.lock", SourceKind::YarnLock),
        ] {
            if let Some(s) = source(root, file, kind) {
                return vec![s];
            }
        }
        source(root, "package.json", SourceKind::PackageJson)
            .into_iter()
            .collect()
    }
    fn parse(&self, source: &DetectedSource) -> Result<Vec<Package>, ParseError> {
        match source.kind {
            SourceKind::PackageLock => parse_package_lock(&source.path),
            SourceKind::PnpmLock => parse_pnpm_lock(&source.path),
            SourceKind::YarnLock => parse_yarn_lock(&source.path),
            SourceKind::BunLock => parse_bun_lock(&source.path),
            SourceKind::PackageJson => parse_package_json_project(&source.path),
            SourceKind::BunLockBinary => Err(invalid(
                &source.path,
                "bun.lockb is binary; rerun with --allow-tools and Bun on PATH, or commit bun.lock",
            )),
            _ => Err(invalid(&source.path, "unexpected source kind")),
        }
    }
}

mod bun;
mod manifest;
mod metadata;
mod npm;
mod pnpm;
mod yarn;

pub(crate) use bun::*;
pub(crate) use manifest::*;
pub(crate) use metadata::*;
pub(crate) use npm::*;
pub(crate) use pnpm::*;
pub(crate) use yarn::*;
