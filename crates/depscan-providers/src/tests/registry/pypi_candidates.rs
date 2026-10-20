use super::*;

#[test]
fn pypi_empty_releases_are_neither_latest_nor_matching_candidates() {
    let mut package = Package::new(Ecosystem::PyPI, "example", ">=1", "requirements.txt".into());
    package.set_manifest_constraint(">=1");
    let data = json!({"releases": {
        "1.0": [{"yanked": false}], "9.0": [], "8.0": [{"yanked": true}]
    }});
    let latest = pypi_version_result(&package, &data).unwrap();
    assert_eq!(latest.latest_stable, "1.0");
    assert_eq!(latest.latest_matching.as_deref(), Some("1.0"));
    assert!(pypi_version_result(&package, &json!({"releases":{"9.0":[]}})).is_err());
}

#[test]
fn pypi_malformed_file_lists_fail_visibly() {
    let package = Package::new(Ecosystem::PyPI, "example", "1.0", "requirements.txt".into());
    for files in [json!(null), json!({}), json!(false), json!([null])] {
        let data = json!({"releases":{"1.0":[{"yanked":false}], "9.0":files}});
        assert!(
            pypi_version_result(&package, &data).is_err(),
            "accepted {data}"
        );
    }
}
