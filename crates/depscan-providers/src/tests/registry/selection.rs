use super::*;

#[test]
fn selects_latest_pypi_release_regardless_of_response_order() {
    let data = json!({
        "2.34.2": [{"yanked": false}],
        "2.9.2": [{"yanked": false}],
        "2.32.5": [{"yanked": false}]
    });

    assert_eq!(
        select_pypi_release(data.as_object().unwrap(), "2.32.5"),
        Some("2.34.2".to_owned())
    );
}

#[test]
fn excludes_fully_yanked_but_keeps_partially_yanked_pypi_releases() {
    let data = json!({
        "2.34.2": [{"yanked": true}, {"yanked": true}],
        "2.33.1": [{"yanked": true}, {"yanked": false}],
        "2.33.0": [{"yanked": false}]
    });

    assert_eq!(
        select_pypi_release(data.as_object().unwrap(), "2.32.5"),
        Some("2.33.1".to_owned())
    );
    assert!(pypi_release_is_yanked(&data["2.34.2"]));
    assert!(!pypi_release_is_yanked(&data["2.33.1"]));
    assert!(!pypi_release_is_yanked(&data["2.33.0"]));
}

#[test]
fn follows_installed_pypi_prerelease_policy() {
    let data = json!({
        "3.0rc1": [{"yanked": false}],
        "2.34.2": [{"yanked": false}],
        "not a version": [{"yanked": false}]
    });
    let releases = data.as_object().unwrap();

    assert_eq!(
        select_pypi_release(releases, "2.32.5"),
        Some("2.34.2".to_owned())
    );
    assert_eq!(
        select_pypi_release(releases, "3.0b1"),
        Some("3.0rc1".to_owned())
    );
}

#[test]
fn selects_latest_valid_stable_nuget_release() {
    let versions = [
        "1.9.0",
        "2.0.0-rc.10",
        "not-a-version",
        "1.10.0",
        "2.0.0+build-sha",
        "2147483648.0.0",
    ];

    assert_eq!(
        select_nuget_release(versions),
        Some("2.0.0+build-sha".to_owned())
    );
    assert_eq!(
        select_nuget_release(["1.0.0-rc.2", "1.0.0-rc.10", "bad"]),
        None
    );
}
