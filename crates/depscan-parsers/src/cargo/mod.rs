use super::*;

pub struct CargoParser;
impl EcosystemParser for CargoParser {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::CratesIo
    }
    fn detect(&self, root: &Path) -> Vec<DetectedSource> {
        source(root, "Cargo.lock", SourceKind::CargoLock)
            .or_else(|| source(root, "Cargo.toml", SourceKind::CargoToml))
            .into_iter()
            .collect()
    }
    fn parse(&self, source: &DetectedSource) -> Result<Vec<Package>, ParseError> {
        match source.kind {
            SourceKind::CargoLock => parse_cargo_lock(&source.path),
            SourceKind::CargoToml => parse_cargo_toml(&source.path),
            _ => Err(invalid(&source.path, "unexpected source kind")),
        }
    }
}

const CARGO_CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[derive(Clone, Debug)]
pub(crate) enum CargoDependencySource {
    CratesIo,
    RegistryName,
    RegistryIndex(String),
    Git {
        url: String,
        selector: Option<(String, String)>,
    },
    Path,
}

#[derive(Clone, Debug)]
pub(crate) struct CargoDependencySpec {
    package_name: String,
    version: Option<String>,
    enrichable: bool,
    local_path: Option<PathBuf>,
    source: CargoDependencySource,
}

#[derive(Debug)]
pub(crate) struct CargoDeclaration {
    dependency: CargoDependencySpec,
    declaring_manifest: PathBuf,
    declaring_package: CargoProjectPackageId,
    dev: bool,
}

#[derive(Debug)]
pub(crate) struct CargoManifest {
    path: PathBuf,
    value: Toml,
    package: CargoProjectPackageId,
}

mod dependency;
mod lock_graph;
mod lock_model;
mod lock_source;
mod workspace;
mod workspace_discovery;

pub(crate) use dependency::*;
pub(crate) use lock_graph::*;
pub(crate) use lock_model::*;
pub(crate) use lock_source::*;
pub(crate) use workspace::*;
pub(crate) use workspace_discovery::*;
