use super::*;

#[test]
fn treats_dollar_and_singleton_braces_as_literals() {
    assert!(matches("packages/$", "packages/$"));
    assert!(!matches("packages/$", "packages/x"));
    assert!(matches("packages/(core)", "packages/(core)"));
}

#[test]
fn recognizes_comments_only_at_the_start_of_the_whole_pattern() {
    let comment = NpmMinimatch::compile("# packages/*").unwrap();
    assert!(!comment.is_match("# packages/api").unwrap());
    assert!(matches("packages/#name", "packages/#name"));
}

#[test]
fn follows_minimatch_literal_fallbacks_and_rejects_unsafe_input() {
    assert!(NpmMinimatch::compile("").is_err());
    assert!(NpmMinimatch::compile("packages\\*").is_err());
    assert!(matches("packages/[abc", "packages/[abc"));
    assert!(matches("packages/{a,b", "packages/{a,b"));
    for pattern in [
        "packages/@(a|b",
        "packages/!(a|b",
        "packages/?(",
        "packages/*(",
    ] {
        let error = NpmMinimatch::compile(pattern).unwrap_err();
        assert!(error.contains("unmatched npm workspace extglob openers"));
    }
    assert!(matches("packages/a(b)", "packages/a(b)"));
    assert!(matches("packages/?x", "packages/ax"));
    assert!(matches("packages/*x", "packages/anythingx"));
    assert!(matches("packages/@x", "packages/@x"));
    assert!(matches("packages/+x", "packages/+x"));
    assert!(matches("packages/!x", "packages/!x"));
    assert!(matches("packages/a)", "packages/a)"));
    assert!(matches("packages/[]", "packages/[]"));
    assert!(matches("packages/[!]", "packages/[!]"));
    assert!(matches("packages/[]]", "packages/]"));
    assert!(!matches("packages/[z-a]", "packages/z"));
    assert!(!matches("packages/[!z-a]", "packages/z"));
    assert!(matches("packages/[z-aq]", "packages/q"));
    assert!(matches("packages//api", "packages/api"));

    let matcher = NpmMinimatch::compile("packages/*").unwrap();
    assert!(matcher.is_match("packages//api").is_err());
    assert!(matcher.is_match("packages/../api").is_err());
    assert!(matcher.is_match(&"x".repeat(4_097)).is_err());
}

#[test]
fn exposes_the_workspace_collection_limit_to_the_caller() {
    assert_eq!(MAX_WORKSPACE_PATTERNS, 256);
}

#[test]
fn preserves_resource_bounds_after_extglob_lowering() {
    let clone_heavy = format!("packages/{}", "!(a|b)".repeat(7));
    let compile_error = NpmMinimatch::compile(&clone_heavy).unwrap_err();
    assert!(compile_error.contains("4096-node syntax limit after extglob lowering"));

    let matcher = NpmMinimatch::compile("packages/+(*|*)").unwrap();
    let candidate = format!("packages/{}", "x".repeat(512));
    let match_error = matcher.is_match(&candidate).unwrap_err();
    assert!(match_error.contains("250000-operation limit"));
}
