use super::*;

pub(crate) fn npm_fixture_packages(fixture: &str) -> Vec<Package> {
    let lock = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture)
        .join("package-lock.json");
    let packages = parse_package_lock(&lock).unwrap();
    assert!(packages.iter().all(|package| package.source_file == lock));
    packages
}

pub(crate) fn normalized_npm_packages(packages: &[Package]) -> Json {
    Json::Array(
        packages
            .iter()
            .map(|package| {
                json!({
                    "name": package.name,
                    "version": package.version,
                    "direct": package.direct,
                    "dev": package.dev,
                    "source": package
                        .source_file
                        .file_name()
                        .and_then(|name| name.to_str()),
                })
            })
            .collect(),
    )
}

pub(crate) fn parse_npm_value(value: &Json) -> Result<Vec<Package>, ParseError> {
    let directory = tempfile::tempdir().unwrap();
    let lock = directory.path().join("package-lock.json");
    fs::write(&lock, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    parse_package_lock(&lock)
}

pub(crate) fn assert_npm_lock_edge_directness(packages: &[Package]) {
    let package = |name: &str, version: &str| {
        packages
            .iter()
            .find(|package| package.name == name && package.version == version)
            .unwrap_or_else(|| panic!("missing npm package {name}@{version}"))
    };

    for (name, version) in [
        ("duplicate", "2.0.0"),
        ("hoisted", "1.0.0"),
        ("parent", "1.0.0"),
        ("root-actual", "1.0.0"),
        ("root-direct", "2.0.0"),
        ("shared", "1.0.0"),
        ("workspace-actual", "1.0.0"),
    ] {
        let package = package(name, version);
        assert!(package.direct, "{name}@{version} was not direct");
        assert!(
            package.direct_known,
            "{name}@{version} directness was not proven"
        );
    }

    let nested_duplicate = package("duplicate", "1.0.0");
    assert!(!nested_duplicate.direct);
    assert!(nested_duplicate.direct_known);

    for name in ["unreferenced", "unreferenced-parent", "unreferenced-child"] {
        let unreferenced = package(name, "9.0.0");
        assert!(!unreferenced.direct);
        assert!(
            !unreferenced.direct_known,
            "disconnected {name} was spuriously classified as known transitive"
        );
    }
    assert_eq!(
        packages
            .iter()
            .filter(|package| package.name == "shared" && package.version == "1.0.0")
            .count(),
        1,
        "dedup must retain one existentially direct shared coordinate"
    );
}
