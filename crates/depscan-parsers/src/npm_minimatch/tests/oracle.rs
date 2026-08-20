use super::*;
use std::collections::BTreeSet;

#[test]
fn matches_checked_in_npm11_differential_corpus() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/npm-minimatch/npm11-vectors.json"
    ))
    .expect("decode npm minimatch oracle corpus");
    assert_eq!(corpus["oracle"]["npm"], "11.0.0");
    assert_eq!(corpus["oracle"]["minimatch"], "9.0.5");
    assert_eq!(corpus["oracle"]["unicode"], "16.0");
    assert_eq!(unicode_general_category::UNICODE_VERSION, (16, 0, 0));
    let candidates = corpus["candidates"]
        .as_array()
        .expect("oracle candidate array");
    let cases = corpus["cases"].as_array().expect("oracle case array");
    let pairs = corpus["pairs"].as_array().expect("oracle pair array");
    assert_eq!(candidates.len() * cases.len() + pairs.len(), 1_794);

    for case in cases {
        let pattern = case["pattern"].as_str().expect("oracle pattern");
        let expected = case["matches"]
            .as_array()
            .expect("oracle match array")
            .iter()
            .map(|candidate| candidate.as_str().expect("oracle match candidate"))
            .collect::<BTreeSet<_>>();
        let matcher = NpmMinimatch::compile(pattern)
            .unwrap_or_else(|error| panic!("oracle pattern {pattern:?} failed: {error}"));
        for candidate in candidates {
            let candidate = candidate.as_str().expect("oracle candidate");
            let actual = matcher.is_match(candidate).unwrap_or_else(|error| {
                panic!("oracle match {pattern:?} against {candidate:?} failed: {error}")
            });
            assert_eq!(
                actual,
                expected.contains(candidate),
                "npm 11 mismatch for {pattern:?} against {candidate:?}"
            );
        }
    }

    for pair in pairs {
        let pattern = pair["pattern"].as_str().expect("pair pattern");
        let candidate = pair["candidate"].as_str().expect("pair candidate");
        let expected = pair["matches"].as_bool().expect("pair expectation");
        let actual = NpmMinimatch::compile(pattern)
            .unwrap_or_else(|error| panic!("oracle pair {pattern:?} failed: {error}"))
            .is_match(candidate)
            .unwrap_or_else(|error| {
                panic!("oracle pair {pattern:?} against {candidate:?} failed: {error}")
            });
        assert_eq!(
            actual, expected,
            "npm 11 pair mismatch for {pattern:?} against {candidate:?}"
        );
    }

    for rejection in corpus["rejects"].as_array().expect("oracle reject array") {
        let pattern = rejection["pattern"].as_str().expect("rejected pattern");
        let expected = rejection["contains"].as_str().expect("rejection text");
        rejection["npmThrows"]
            .as_bool()
            .expect("npm rejection classification");
        let error = NpmMinimatch::compile(pattern)
            .expect_err("oracle rejection must fail closed during compilation");
        assert!(
            error.contains(expected),
            "rejection {pattern:?} returned {error:?}"
        );
    }
}
