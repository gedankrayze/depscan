use super::*;
use depscan_core::{Ecosystem, Package};
use std::path::PathBuf;

fn document() -> ScanDocument {
    ScanDocument::new(vec![ScanResult {
        package: Package::new(
            Ecosystem::Npm,
            "example",
            "1.0.0",
            PathBuf::from("package-lock.json"),
        ),
        vulns: vec![Vulnerability {
            id: "TEST-1".to_owned(),
            aliases: vec![],
            summary: "fixture".to_owned(),
            severity: None,
            cvss_score: None,
            fixed_in: vec![],
            references: vec![],
            withdrawn: false,
        }],
        latest: None,
        errors: vec![],
        suppressed: vec![],
    }])
}

#[test]
fn sarif_omits_missing_help_and_chooses_a_valid_absolute_reference() {
    let mut document = document();
    let report = render_sarif(&document);
    assert!(
        report
            .pointer("/runs/0/tool/driver/rules/0/helpUri")
            .is_none()
    );
    document.results[0].vulns[0].references = vec![
        "not a URI".to_owned(),
        "https://example.test/advisory".to_owned(),
    ];
    let report = render_sarif(&document);
    assert_eq!(
        report.pointer("/runs/0/tool/driver/rules/0/helpUri"),
        Some(&json!("https://example.test/advisory"))
    );
}

#[test]
fn sarif_artifact_locations_escape_native_paths() {
    for (path, expected) in [
        ("project #1/é%.lock", "project%20%231/%C3%A9%25.lock"),
        ("dir:name.lock", "dir%3Aname.lock"),
        (
            "/tmp/space dir/Cargo.lock",
            "file:///tmp/space%20dir/Cargo.lock",
        ),
        (
            r"C:\project dir\Cargo.lock",
            "file:///C:/project%20dir/Cargo.lock",
        ),
    ] {
        let mut document = document();
        document.results[0].package.source_file = path.into();
        let report = render_sarif(&document);
        assert_eq!(
            report.pointer("/runs/0/results/0/locations/0/physicalLocation/artifactLocation/uri"),
            Some(&json!(expected))
        );
    }
    if !cfg!(windows) {
        assert_eq!(
            artifact_uri(Path::new(r"unix\name.lock")),
            "unix%5Cname.lock"
        );
    }
}
