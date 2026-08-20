use depscan_core::{DetectedSource, EcosystemParser, Package, SourceKind};
use depscan_parsers::CargoParser;
use serde_json::{Value as Json, json};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

pub(super) fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cargo")
        .join(name)
}

pub(super) fn parse(path: PathBuf, kind: SourceKind) -> Result<Vec<Package>, String> {
    CargoParser
        .parse(&DetectedSource { path, kind })
        .map_err(|error| error.to_string())
}

pub(super) fn parse_inline_cargo(manifest: &str, lock: &str) -> Result<Vec<Package>, String> {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("Cargo.toml"), manifest).unwrap();
    fs::write(directory.path().join("Cargo.lock"), lock).unwrap();
    parse(directory.path().join("Cargo.lock"), SourceKind::CargoLock)
}

fn portable_relative_path(path: &Path) -> String {
    path.components()
        .map(|component| match component {
            Component::Normal(name) => name.to_str().expect("UTF-8 Cargo fixture component"),
            _ => panic!("Cargo fixture provenance was not a normalized relative path: {path:?}"),
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub(super) fn normalized(packages: &[Package], root: &Path) -> Json {
    let canonical_root = fs::canonicalize(root).expect("canonical Cargo fixture root");
    Json::Array(
        packages
            .iter()
            .map(|package| {
                let canonical_source =
                    fs::canonicalize(&package.source_file).expect("canonical Cargo package source");
                let source = canonical_source
                    .strip_prefix(&canonical_root)
                    .expect("Cargo source is inside canonical fixture root");
                json!({
                    "name": package.name,
                    "display_name": package.display_name,
                    "version": package.version,
                    "direct": package.direct,
                    "direct_known": package.direct_known,
                    "dev": package.dev,
                    "dev_known": package.dev_known,
                    "enrichable": package.enrichable,
                    "resolved_from_range": package.resolved_from_range,
                    "source": portable_relative_path(source),
                })
            })
            .collect(),
    )
}
