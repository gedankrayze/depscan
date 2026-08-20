use super::*;

#[test]
fn parses_nuget_lock_with_normalized_identity_and_preserved_case() {
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("packages.lock.json");
    fs::write(
        &lock,
        r#"{
            "version": 1,
            "dependencies": {
                "net8.0": {
                    "Newtonsoft.Json": {
                        "type": "Direct",
                        "resolved": "12.0.1"
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let result = parse_packages_lock(&lock).unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, "newtonsoft.json");
    assert_eq!(result[0].display_name, "Newtonsoft.Json");
    assert_eq!(result[0].key(), "NuGet:newtonsoft.json:12.0.1");
    assert!(result[0].direct);
}

#[test]
fn parses_nuget_project_with_normalized_identity_and_preserved_case() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("sample.csproj");
    fs::write(
        &project,
        r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>"#,
    )
    .unwrap();

    let result = parse_nuget_project(&project).unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, "newtonsoft.json");
    assert_eq!(result[0].display_name, "Newtonsoft.Json");
}

#[test]
fn rejects_duplicate_nuget_attributes_after_large_attribute_set() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("duplicate-attributes.csproj");
    let mut attributes = String::from(r#"Include="First.Package" Version="1.2.3""#);
    // quick-xml 0.41 switches duplicate detection to its linear-time hash path
    // after 32 attributes. Keep the duplicate beyond that boundary so this
    // exercises depscan's real `attributes()` call through the patched path.
    for index in 0..40 {
        attributes.push_str(&format!(r#" data-{index}="value""#));
    }
    attributes.push_str(r#" Include="Second.Package""#);
    fs::write(
        &project,
        format!("<Project><ItemGroup><PackageReference {attributes} /></ItemGroup></Project>"),
    )
    .unwrap();

    let error = parse_nuget_project(&project).unwrap_err();

    assert!(error.to_string().contains("duplicated attribute"));
}

#[test]
fn plain_nuget_reader_accepts_more_than_namespace_resolver_limit() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("namespace-declarations.csproj");
    let mut namespaces = String::new();
    // RUSTSEC-2026-0195 affects NsReader's namespace resolver. depscan uses
    // plain Reader, so even an element above NsReader's 256-declaration cap
    // is handled as ordinary attributes without a resolver-side allocation.
    for index in 0..300 {
        namespaces.push_str(&format!(r#" xmlns:p{index}="urn:test:{index}""#));
    }
    fs::write(
        &project,
        format!(
            "<Project{namespaces}><ItemGroup><PackageReference Include=\"Safe.Package\" Version=\"4.5.6\" /></ItemGroup></Project>"
        ),
    )
    .unwrap();

    let result = parse_nuget_project(&project).unwrap();

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].display_name, "Safe.Package");
    assert_eq!(result[0].version, "4.5.6");
}

#[test]
fn deduplicates_nuget_identifiers_case_insensitively() {
    let packages = vec![
        Package::new(
            Ecosystem::NuGet,
            "Newtonsoft.Json",
            "12.0.1",
            PathBuf::from("one.csproj"),
        ),
        Package::new(
            Ecosystem::NuGet,
            "NEWTONSOFT.JSON",
            "12.0.1",
            PathBuf::from("two.csproj"),
        ),
    ];

    let result = dedup(packages);

    assert_eq!(result.len(), 1);
    assert_eq!(result[0].key(), "NuGet:newtonsoft.json:12.0.1");
}
