use super::*;

fn version(value: &str) -> NuGetVersion {
    NuGetVersion::parse(value).unwrap()
}

#[test]
fn follows_nuget_precedence() {
    let cases = [
        ("1.0.0-rc.2", "1.0.0-rc.10", Ordering::Less),
        ("1.0.0-1", "1.0.0-alpha", Ordering::Less),
        ("1.0.0-alpha", "1.0.0-alpha.1", Ordering::Less),
        ("1.0.0-alpha.1", "1.0.0-alpha.beta", Ordering::Less),
        ("1.0.0-beta", "1.0.0-beta2", Ordering::Less),
        ("1.0.0-BETA", "1.0.0-beta", Ordering::Equal),
        (
            "1.0.0-beta.x.y.5.79",
            "1.0.0-beta.x.y.5.790",
            Ordering::Less,
        ),
        ("1.0.0-rc.10", "1.0.0", Ordering::Less),
        ("1.0.0+build.1", "1.0.0+build.2", Ordering::Equal),
        ("1.0.0.4", "1.0.0.5", Ordering::Less),
        ("1", "1.0.0.0", Ordering::Equal),
        ("1.00.01", "1.0.1.0", Ordering::Equal),
    ];

    for (left, right, expected) in cases {
        assert_eq!(
            version(left).cmp(&version(right)),
            expected,
            "unexpected ordering for {left:?} and {right:?}"
        );
    }
}

#[test]
fn normalizes_release_components_and_omits_metadata() {
    let cases = [
        ("1", "1.0.0"),
        ("1.00", "1.0.0"),
        ("1.01.1", "1.1.1"),
        ("1.00.0.0", "1.0.0"),
        ("1.0.01.5-RC.2+build.9", "1.0.1.5-RC.2"),
    ];

    for (input, expected) in cases {
        assert_eq!(version(input).to_normalized_string(), expected);
    }
}

#[test]
fn rejects_malformed_versions_instead_of_inventing_zero_components() {
    let invalid = [
        "",
        "not-a-version",
        "1..2",
        "1.2.3.4.5",
        "1.2.x",
        "1.2.3-",
        "1.2.3-alpha..1",
        "1.2.3-alpha.01",
        "1.2.3+",
        "1.2.3+meta..data",
        "1.2.3+meta+again",
        "1.2147483648",
        "-1.2.3",
    ];

    for input in invalid {
        assert!(
            NuGetVersion::parse(input).is_err(),
            "malformed version {input:?} parsed successfully"
        );
    }
}

#[test]
fn accepts_nuget_release_zeroes_and_large_numeric_prerelease_identifiers() {
    assert_eq!(version("01.002.0003"), version("1.2.3"));
    assert_eq!(
        version("1.0.0-9999999999999999999999999999")
            .cmp(&version("1.0.0-10000000000000000000000000000")),
        Ordering::Less
    );
    assert!(NuGetVersion::parse("1.0.0-alpha.0A").is_ok());
    assert!(NuGetVersion::parse("1.0.0+build.0001").is_ok());
}
