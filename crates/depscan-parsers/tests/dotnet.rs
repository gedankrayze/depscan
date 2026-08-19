use depscan_core::{DetectedSource, EcosystemParser, Package, SourceKind};
use depscan_parsers::NugetParser;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dotnet/multi-project")
}

fn relative(path: &Path) -> String {
    path.strip_prefix(fixture_root())
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/")
}

fn parsed_fixture() -> BTreeMap<String, Vec<Package>> {
    NugetParser
        .detect(&fixture_root())
        .into_iter()
        .map(|source| {
            let name = relative(&source.path);
            let packages = NugetParser.parse(&source).unwrap();
            assert!(
                packages
                    .iter()
                    .all(|package| package.source_file == source.path),
                "all package provenance must point at the parsed project or lockfile: {name}"
            );
            (name, packages)
        })
        .collect()
}

fn package<'a>(packages: &'a [Package], name: &str, version: &str) -> &'a Package {
    packages
        .iter()
        .find(|package| package.name == name && package.version == version)
        .unwrap_or_else(|| panic!("missing {name}@{version} in {packages:#?}"))
}

#[test]
fn detects_every_project_lock_and_legacy_manifest() {
    let sources = NugetParser.detect(&fixture_root());
    let detected: Vec<_> = sources
        .iter()
        .map(|source| (relative(&source.path), source.kind.clone()))
        .collect();

    assert_eq!(
        detected,
        vec![
            ("legacy/Legacy.csproj".into(), SourceKind::ProjectFile),
            ("legacy/packages.config".into(), SourceKind::PackagesConfig),
            ("packages.lock.json".into(), SourceKind::PackagesLock),
            ("src/csharp/CSharp.csproj".into(), SourceKind::ProjectFile),
            (
                "src/deep/one/two/three/four/five/Deep.csproj".into(),
                SourceKind::ProjectFile
            ),
            ("src/fsharp/FSharp.fsproj".into(), SourceKind::ProjectFile),
            (
                "src/locked/packages.lock.json".into(),
                SourceKind::PackagesLock
            ),
            (
                "src/unlocked/Unlocked.csproj".into(),
                SourceKind::ProjectFile
            ),
            (
                "src/visual-basic/VisualBasic.vbproj".into(),
                SourceKind::ProjectFile
            ),
        ]
    );
    assert!(
        !detected
            .iter()
            .any(|(path, _)| path == "src/locked/Locked.csproj"),
        "the adjacent resolved lock must supersede only its project manifest"
    );
}

#[test]
fn merges_nearest_central_versions_and_project_overrides() {
    let parsed = parsed_fixture();

    let csharp = &parsed["src/csharp/CSharp.csproj"];
    assert_eq!(csharp.len(), 6);
    assert_eq!(
        package(csharp, "central.shared", "1.2.3").display_name,
        "Central.Shared"
    );
    assert!(!package(csharp, "central.shared", "1.2.3").resolved_from_range);
    assert_eq!(
        package(csharp, "central.nested", "2.3.4").display_name,
        "Central.Nested"
    );
    assert!(package(csharp, "central.range", "[3.0.0,4.0.0)").resolved_from_range);
    assert_eq!(
        package(csharp, "override.me", "4.5.6").display_name,
        "Override.Me"
    );
    assert!(package(csharp, "inline.attribute", "5.6.7").direct);
    assert!(package(csharp, "inline.nested", "6.7.8").direct);

    let fsharp = &parsed["src/fsharp/FSharp.fsproj"];
    assert_eq!(fsharp.len(), 3);
    assert!(package(fsharp, "central.shared", "1.2.3").direct);
    assert!(package(fsharp, "override.me", "7.8.9").direct);
    assert!(package(fsharp, "updated.central", "0.2.0").direct);

    let visual_basic = &parsed["src/visual-basic/VisualBasic.vbproj"];
    assert_eq!(visual_basic.len(), 3);
    assert!(package(visual_basic, "central.shared", "10.0.0").direct);
    assert!(package(visual_basic, "child.nested", "11.0.0").direct);
    assert!(package(visual_basic, "floating.central", "12.*").resolved_from_range);
    assert!(
        visual_basic
            .iter()
            .all(|package| package.version != "1.2.3"),
        "only the closest Directory.Packages.props may apply automatically"
    );

    let deep = &parsed["src/deep/one/two/three/four/five/Deep.csproj"];
    assert_eq!(deep.len(), 2);
    assert!(package(deep, "central.shared", "1.2.3").direct);
    assert!(package(deep, "deep.only", "13.0.0").direct);

    assert!(
        parsed
            .values()
            .flatten()
            .all(|package| package.name != "unused.central"),
        "unused central declarations are not dependencies"
    );
}

#[test]
fn lockfiles_cover_all_frameworks_and_keep_resolved_metadata() {
    let parsed = parsed_fixture();

    let root_lock = &parsed["packages.lock.json"];
    assert_eq!(root_lock.len(), 1);
    let root_package = package(root_lock, "root.locked", "16.0.1");
    assert!(root_package.direct);
    assert!(!root_package.resolved_from_range);

    let project_lock = &parsed["src/locked/packages.lock.json"];
    assert_eq!(project_lock.len(), 4);
    assert!(package(project_lock, "locked.direct", "1.0.1").direct);
    assert!(!package(project_lock, "locked.transitive", "2.0.0").direct);
    assert!(package(project_lock, "locked.centralpinned", "3.0.0").direct);
    assert!(!package(project_lock, "locked.fourpart", "4.0.0.5").direct);
    assert!(
        project_lock
            .iter()
            .all(|package| package.name != "workspace.project")
    );
    assert!(
        parsed
            .values()
            .flatten()
            .all(|package| package.name != "manifest.should.not.appear"),
        "the locked project manifest must not be scanned beside its resolved lock"
    );

    let sibling = &parsed["src/unlocked/Unlocked.csproj"];
    assert_eq!(sibling.len(), 2);
    assert!(package(sibling, "central.shared", "1.2.3").direct);
    assert!(package(sibling, "sibling.only", "8.0.0").direct);
}

#[test]
fn preserves_legacy_development_dependency_metadata() {
    let parsed = parsed_fixture();
    assert!(parsed["legacy/Legacy.csproj"].is_empty());

    let legacy = &parsed["legacy/packages.config"];
    assert_eq!(legacy.len(), 2);
    assert!(!package(legacy, "legacy.runtime", "14.0.0").dev);
    assert!(package(legacy, "legacy.tool", "15.0.0").dev);
    assert!(legacy.iter().all(|package| package.direct));
}

#[test]
fn rejects_unresolved_references_and_malformed_lock_entries() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("Unresolved.csproj");
    fs::write(
        &project,
        r#"<Project><ItemGroup><PackageReference Include="Missing.Version" /></ItemGroup></Project>"#,
    )
    .unwrap();
    let project_error = NugetParser
        .parse(&DetectedSource {
            path: project,
            kind: SourceKind::ProjectFile,
        })
        .unwrap_err()
        .to_string();
    assert!(project_error.contains("has no inline, override, or central version"));

    let lock = directory.path().join("packages.lock.json");
    fs::write(
        &lock,
        r#"{"version":1,"dependencies":{"net8.0":{"Broken.Package":{"type":"Direct"}}}}"#,
    )
    .unwrap();
    let lock_error = NugetParser
        .parse(&DetectedSource {
            path: lock,
            kind: SourceKind::PackagesLock,
        })
        .unwrap_err()
        .to_string();
    assert!(lock_error.contains("missing resolved version"));

    let malformed_directory = directory.path().join("malformed");
    fs::create_dir(&malformed_directory).unwrap();
    let malformed_project = malformed_directory.join("Malformed.csproj");
    fs::write(
        &malformed_project,
        r#"<Project><ItemGroup><PackageReference Include="Broken"><Version>1.0.0</PackageReference></ItemGroup></Project>"#,
    )
    .unwrap();
    let xml_error = NugetParser
        .parse(&DetectedSource {
            path: malformed_project,
            kind: SourceKind::ProjectFile,
        })
        .unwrap_err()
        .to_string();
    assert!(xml_error.contains("failed to parse"));

    let central = directory.path().join("Directory.Packages.props");
    fs::write(
        &central,
        r#"<Project><ItemGroup><PackageVersion Include="Missing.Central.Version" /></ItemGroup></Project>"#,
    )
    .unwrap();
    let central_error = NugetParser
        .parse(&DetectedSource {
            path: central,
            kind: SourceKind::DirectoryPackagesProps,
        })
        .unwrap_err()
        .to_string();
    assert!(central_error.contains("missing its package version"));
}
