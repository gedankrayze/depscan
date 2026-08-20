use super::{MAX_BRACE_EXPANSIONS, MAX_WORKSPACE_PATTERNS, NpmMinimatch};

mod boundaries;
mod extglobs;
mod oracle;
mod unicode;

fn matches(pattern: &str, candidate: &str) -> bool {
    NpmMinimatch::compile(pattern)
        .unwrap()
        .is_match(candidate)
        .unwrap()
}

#[test]
fn matches_wildcards_without_crossing_slashes() {
    assert!(matches("packages/*", "packages/api"));
    assert!(!matches("packages/*", "packages/api/client"));
    assert!(matches("packages/app?", "packages/apps"));
    assert!(!matches("packages/app?", "packages/app"));
    assert!(matches("packages/**/client", "packages/client"));
    assert!(matches(
        "packages/**/client",
        "packages/api/generated/client"
    ));
    assert!(!matches("packages/**/client", "other/client"));
    assert!(!matches("packages/**", "packages"));
    assert!(matches("packages/**", "packages/api"));
    assert!(matches("**/packages", "packages"));
}

#[test]
fn applies_dot_false_to_every_component() {
    assert!(!matches("*", ".root"));
    assert!(!matches("packages/*", "packages/.hidden"));
    assert!(!matches("**/client", ".cache/client"));
    assert!(matches("packages/.*", "packages/.hidden"));
    assert!(matches("packages/[.]hidden", "packages/.hidden"));
    assert!(!matches("packages/[.a]hidden", "packages/.hidden"));
    assert!(!matches("packages/[.-0]hidden", "packages/.hidden"));
    assert!(!matches("packages/[[:punct:]]hidden", "packages/.hidden"));
    assert!(!matches("packages/[^a]*", "packages/.hidden"));
}

#[test]
fn matches_character_classes_and_posix_classes() {
    assert!(matches("packages/[ab]", "packages/a"));
    assert!(matches("packages/[a-c]", "packages/b"));
    assert!(!matches("packages/[!a-c]", "packages/b"));
    assert!(matches("packages/[^a-c]", "packages/z"));
    assert!(matches("packages/[[:alpha:]]", "packages/q"));
    assert!(matches("packages/[[:alpha:]]", "packages/λ"));
    assert!(!matches("packages/[[:alpha:]]", "packages/7"));
    assert!(matches("packages/[[:punct:]]", "packages/!"));
    assert!(!matches("packages/[[:punct:]]", "packages/$"));
    assert!(matches("packages/[[:digit:]]", "packages/\u{0661}"));
    assert!(matches("packages/[[:word:]]", "packages/\u{2163}"));
    assert!(!matches("packages/[[:alnum:]]", "packages/\u{00bd}"));
    assert!(!matches("packages/[[:upper:]]", "packages/\u{2163}"));
    assert!(!matches("packages/[[:graph:]]", "packages/\u{200c}"));
    assert!(!matches("packages/[[:print:]]", "packages/a"));
    assert!(matches("packages/[[:print:]]", "packages/\u{200c}"));
    assert!(NpmMinimatch::compile("packages/[[:unknown:]]").is_err());
}

#[test]
fn expands_comma_nested_and_ranged_braces_with_bounds() {
    assert!(matches("packages/{api,web}", "packages/api"));
    assert!(matches("packages/{,a}", "packages/a"));
    assert!(!matches("packages/{,a}", "packages"));
    assert!(matches("packages/{api,{web,worker}}", "packages/worker"));
    assert!(matches("{packages/api,apps/web}", "packages/api"));
    assert!(matches("{packages/api,apps/web}", "apps/web"));
    assert!(matches("packages/v{1..3}", "packages/v2"));
    assert!(matches("packages/v{03..01}", "packages/v02"));
    assert!(matches("packages/{-01..01}", "packages/000"));
    assert!(matches("packages/{-01..01}", "packages/001"));
    assert!(!matches("packages/{-01..01}", "packages/00"));
    assert!(matches("packages/v{1..5..2}", "packages/v3"));
    assert!(!matches("packages/v{1..5..2}", "packages/v4"));
    assert!(matches("packages/{a..c}", "packages/b"));
    assert!(matches("packages/{A..C}", "packages/B"));
    assert!(matches("packages/{a..e..2}", "packages/c"));
    assert!(!matches("packages/{a..e..2}", "packages/b"));
    assert!(matches("packages/{e..a..2}", "packages/c"));
    assert!(matches("packages/{literal}", "packages/{literal}"));
    assert!(!matches("packages/{literal}", "packages/literal"));
    // npm brace expansion runs before class and extglob parsing. Braces
    // inside a would-be class expand, and commas inside brackets remain
    // brace delimiters rather than class contents.
    assert!(matches("packages/[{a,b}]", "packages/a"));
    assert!(matches("packages/[{a,b}]", "packages/b"));
    assert!(!matches("packages/[{a,b}]", "packages/{"));
    assert!(!matches("packages/[{a,b}]", "packages/,"));
    assert!(matches("packages/[{1..3}]", "packages/2"));
    assert!(!matches("packages/[{1..3}]", "packages/{"));
    assert!(matches("packages/{[,],x}", "packages/["));
    assert!(matches("packages/{[,],x}", "packages/]"));
    assert!(matches("packages/{[,],x}", "packages/x"));
    assert!(!matches("packages/{[,],x}", "packages/,"));
    assert!(matches("packages/${a,b}", "packages/${a,b}"));
    assert!(!matches("packages/${a,b}", "packages/$a"));
    assert!(!matches("packages/${a,b}", "packages/$b"));
    assert!(matches("packages/x${a,b}y", "packages/x${a,b}y"));
    assert!(matches("packages/${{a,b},c}", "packages/${{a,b},c}"));
    assert!(matches("packages/$x{a,b}", "packages/$xa"));
    assert!(matches("packages/$x{a,b}", "packages/$xb"));
    for pattern in [
        "packages/@(!(a)",
        "packages/a@(!(b)",
        "packages/@(?(a)",
        "packages/@({a,!(x,y)}|z)",
        "packages/**(b",
        "packages/**({b,#}",
    ] {
        let error = NpmMinimatch::compile(pattern).unwrap_err();
        assert!(error.contains("unmatched npm workspace extglob openers"));
    }
    assert!(matches("packages/{+1..+3}", "packages/{+1..+3}"));
    assert!(!matches("packages/{+1..+3}", "packages/1"));
    assert!(matches("packages/{1..3..+1}", "packages/{1..3..+1}"));
    assert!(!matches("packages/{1..3..+1}", "packages/2"));

    let over_limit = format!("packages/{{1..{}}}", MAX_BRACE_EXPANSIONS + 1);
    assert!(NpmMinimatch::compile(&over_limit).is_err());
    assert!(NpmMinimatch::compile("packages/{1..3..0}").is_err());
}
