use super::*;

#[test]
fn selects_latest_matching_versions_with_native_ecosystem_semantics() {
    let cases = [
        (
            Ecosystem::Npm,
            "^1.2.0",
            vec!["1.2.0", "1.9.9", "2.0.0-beta.1", "2.0.0"],
            Some("1.9.9"),
        ),
        (
            Ecosystem::Npm,
            "1.2.3 - 1.4.x || 3.x",
            vec!["1.4.9", "2.9.0", "3.2.0", "4.0.0"],
            Some("3.2.0"),
        ),
        (
            Ecosystem::CratesIo,
            "^0.2.3",
            vec!["0.2.3", "0.2.9", "0.3.0-alpha.1", "0.3.0"],
            Some("0.2.9"),
        ),
        (
            Ecosystem::PyPI,
            ">=1.0,<2.0,!=1.9",
            vec!["1.8", "1.9", "1.10rc1", "1.10", "2.0"],
            Some("1.10"),
        ),
        (
            Ecosystem::NuGet,
            "[1.0,2.0)",
            vec!["1.9.0", "1.9.0.5", "2.0.0-beta.1", "2.0.0"],
            Some("1.9.0.5"),
        ),
        (
            Ecosystem::NuGet,
            "1.2.*",
            vec!["1.2.8", "1.2.9-beta.1", "1.3.0", "2.0.0"],
            Some("1.2.8"),
        ),
        (
            Ecosystem::NuGet,
            "1.2",
            vec!["1.1.9", "1.2.0", "2.0.0-beta.1", "2.0.0"],
            Some("2.0.0"),
        ),
    ];

    for (ecosystem, constraint, versions, expected) in cases {
        assert_eq!(
            latest_matching_version(ecosystem, constraint, versions).unwrap(),
            expected.map(str::to_owned),
            "unexpected match for {ecosystem:?} {constraint:?}"
        );
    }
}

#[test]
fn handles_prereleases_according_to_each_constraint_language() {
    assert_eq!(
        latest_matching_version(
            Ecosystem::Npm,
            ">=1.2.3-rc.1 <1.2.3",
            ["1.2.3-beta.1", "1.2.3-rc.2", "1.2.4-rc.1"]
        )
        .unwrap(),
        Some("1.2.3-rc.2".to_owned())
    );
    assert_eq!(
        latest_matching_version(
            Ecosystem::CratesIo,
            ">=1.2.3-alpha.1, <1.2.3",
            ["1.2.3-alpha.2", "1.2.3-beta.1", "1.2.4-alpha.1"]
        )
        .unwrap(),
        Some("1.2.3-beta.1".to_owned())
    );
    assert_eq!(
        latest_matching_version(Ecosystem::PyPI, ">=2.0,<3", ["2.1a1", "2.2rc1"]).unwrap(),
        Some("2.2rc1".to_owned()),
        "PEP 440 permits prereleases when no final/post release matches"
    );
    assert_eq!(
        latest_matching_version(
            Ecosystem::NuGet,
            "1.2.0-rc.*",
            ["1.2.0-rc.1", "1.2.0-rc.2", "1.2.0", "1.2.0.5", "1.2.1"]
        )
        .unwrap(),
        Some("1.2.0".to_owned())
    );
}

#[test]
fn invalid_or_unsupported_constraints_fail_instead_of_matching_partially() {
    let cases = [
        (Ecosystem::Npm, "workspace:*"),
        (Ecosystem::Npm, ">=1.2.3 garbage"),
        (Ecosystem::CratesIo, "not a cargo requirement"),
        (Ecosystem::PyPI, "^1.2"),
        (Ecosystem::NuGet, "(1.0)"),
        (Ecosystem::NuGet, "$(CentralVersion)"),
    ];
    for (ecosystem, constraint) in cases {
        let error = latest_matching_version(ecosystem, constraint, ["1.2.3"])
            .expect_err("invalid constraint unexpectedly produced a match");
        assert!(error.to_string().contains(constraint));
    }
}
