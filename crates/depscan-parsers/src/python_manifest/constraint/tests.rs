use super::*;
use depscan_core::{Ecosystem, latest_matching_version};

#[test]
fn poetry_constraints_select_the_documented_release_sets() {
    let cases = [
        ("^1.2.3", vec!["1.2.3", "1.9.9", "2.0.0"], "1.9.9"),
        ("^0.2.3", vec!["0.2.3", "0.2.9", "0.3.0"], "0.2.9"),
        ("^0.0.3", vec!["0.0.3", "0.0.4", "0.1.0"], "0.0.3"),
        ("^0.0", vec!["0.0.0", "0.0.9", "0.1.0"], "0.0.9"),
        ("^0", vec!["0.0.0", "0.9.9", "1.0.0"], "0.9.9"),
        ("~1.2.3", vec!["1.2.3", "1.2.9", "1.3.0"], "1.2.9"),
        ("~1.2", vec!["1.2.0", "1.2.9", "1.3.0"], "1.2.9"),
        ("~1", vec!["1.0.0", "1.9.9", "2.0.0"], "1.9.9"),
        ("1.*", vec!["1.0.0", "1.9.9", "2.0.0"], "1.9.9"),
        ("1.2.*", vec!["1.2.0", "1.2.9", "1.3.0"], "1.2.9"),
    ];
    for (raw, candidates, expected) in cases {
        let normalized = normalize_poetry_constraint(raw).unwrap();
        assert_eq!(
            latest_matching_version(Ecosystem::PyPI, &normalized, candidates).unwrap(),
            Some(expected.to_owned()),
            "unexpected release set for {raw:?} normalized as {normalized:?}"
        );
    }
}

#[test]
fn poetry_constraint_upper_bounds_are_exclusive() {
    for (raw, excluded) in [
        ("^1.2.3", "2.0.0"),
        ("^0.0.3", "0.0.4"),
        ("~1.2", "1.3.0"),
        ("1.2.*", "1.3.0"),
    ] {
        let normalized = normalize_poetry_constraint(raw).unwrap();
        assert_eq!(
            latest_matching_version(Ecosystem::PyPI, &normalized, [excluded]).unwrap(),
            None,
            "{excluded} must be outside {raw:?} normalized as {normalized:?}"
        );
    }
}

#[test]
fn rejects_unrepresentable_poetry_unions_and_malformed_wildcards() {
    for raw in ["^1 || ^2", "1.2*", "1..*"] {
        assert!(
            normalize_poetry_constraint(raw).is_err(),
            "accepted {raw:?}"
        );
    }
}
