use super::*;

#[test]
fn matches_all_extglob_operators() {
    assert!(matches("packages/@(api|web)", "packages/api"));
    assert!(!matches("packages/@(api|web)", "packages/worker"));

    assert!(matches("packages/item?(s|z)", "packages/item"));
    assert!(matches("packages/item?(s|z)", "packages/items"));
    assert!(!matches("packages/item?(s|z)", "packages/itemss"));

    assert!(matches("packages/+(ab|c)", "packages/abcab"));
    assert!(!matches("packages/+(ab|c)", "packages/x"));

    assert!(matches("packages/x*(ab|c)", "packages/x"));
    assert!(matches("packages/x*(ab|c)", "packages/xabc"));

    assert!(matches("packages/!(api|web)", "packages/worker"));
    assert!(!matches("packages/!(api|web)", "packages/api"));

    assert!(matches("packages/pre!(bad).js", "packages/pregood.js"));
    assert!(matches("packages/pre!(bad).js", "packages/pre.js"));
    assert!(!matches("packages/pre!(bad).js", "packages/prebad.js"));
    assert!(matches("packages/!(a)*", "packages/a"));
    assert!(!matches("packages/!(a)*", "packages/ac"));
    assert!(matches("packages/!(a)*", "packages/bc"));
    assert!(matches("packages/!(a)b", "packages/b"));
    assert!(!matches("packages/!(a)b", "packages/ab"));
    assert!(matches("packages/a!(b)c", "packages/ac"));
    assert!(!matches("packages/a!(b)c", "packages/abc"));
    assert!(matches("packages/a!(b)c", "packages/axc"));

    let cross_component = NpmMinimatch::compile("@(packages/a|packages/b)").unwrap_err();
    assert!(cross_component.contains("must not cross path separators"));

    assert!(!matches("packages/*@(a|b)", "packages/a"));
    assert!(matches("packages/*@(a|b)", "packages/aa"));
    assert!(!matches("packages/@(a|b)*", "packages/a"));
    assert!(matches("packages/@(a|b)*", "packages/ab"));
    assert!(matches("packages/**@(a|b)", "packages/a"));
    assert!(matches("packages/@(a|b)**", "packages/a"));
    assert!(matches("packages/@(a*|b)", "packages/a"));

    assert!(matches("packages/!(@(foo|bar)).js", "packages/foo.js"));
    assert!(!matches("packages/!(@(foo|bar)).js", "packages/.js"));
    assert!(!matches("packages/@(!(foo)|bar).js", "packages/foo.js"));
    assert!(matches("packages/@(!(foo)|bar).js", "packages/baz.js"));
    assert!(matches("packages/!(!(foo)).js", "packages/foo.js"));

    assert!(!matches("packages/!(a)@(*)", "packages/a"));
    assert!(!matches("packages/!(a)@(*)", "packages/ac"));
    assert!(matches("packages/!(a)@(*)", "packages/b"));
    assert!(!matches("packages/!(a)@(*|b)", "packages/a"));

    assert!(matches("packages/!(a)!(a|)b", "packages/aab"));
    assert!(matches("packages/!(a)!(b|)b", "packages/abb"));
    assert!(matches("packages/!(a)!(@(a)|)b", "packages/aab"));
}

#[test]
fn follows_npm_empty_extglob_and_dot_boundaries() {
    assert!(matches("packages/!()", "packages/a"));
    assert!(matches("packages/!(a|)", "packages/a"));
    assert!(!matches("packages/!(a|)", "packages/.a"));
    assert!(!matches("packages/!(|a)", "packages/a"));
    assert!(matches("packages/!(|a)", "packages/b"));
    assert!(matches("packages/@(a|)", "packages/a"));
    assert!(matches("packages/@()", "packages/@()"));
    assert!(!matches("packages/@()", "packages/a"));

    assert!(matches("packages/!(a)@()", "packages/b@"));
    assert!(matches("packages/!(a)@()", "packages/a@"));
    assert!(!matches("packages/!(a)@()", "packages/b@()"));
    for pattern in ["packages/!(a)?()", "packages/!(a)+()", "packages/!(a)*()"] {
        assert!(!matches(pattern, "packages/a"));
        assert!(matches(pattern, "packages/b"));
        assert!(matches(pattern, "packages/aa"));
        assert!(!matches(pattern, "packages/.y"));
    }
    assert!(matches("packages/@(@()|b)", "packages/@"));
    assert!(matches("packages/@(@()|b)", "packages/b"));
    assert!(!matches("packages/@(@()|b)", "packages/@()"));
    for pattern in ["packages/@(?())", "packages/@(+())", "packages/@(*())"] {
        assert!(NpmMinimatch::compile(pattern).is_err());
    }

    assert!(!matches("packages/@(.x|*)", "packages/.y"));
    assert!(matches("packages/@(.x|*)", "packages/.x"));
    assert!(matches("packages/?(a)@(*)", "packages/.y"));
    assert!(matches("packages/*(a)@(*)", "packages/.y"));
    assert!(matches("packages/@(a|)*", "packages/.y"));
    assert!(matches("packages/+(a|)*", "packages/.y"));
    assert!(!matches("packages/!(a)*", "packages/.y"));

    assert!(!matches("packages/!()!()", "packages/x."));
    assert!(!matches("packages/!()!()", "packages/x.."));
    assert!(matches("packages/!()!()", "packages/xy"));
    assert!(matches("packages/!()!()", "packages/x.y"));
    assert!(!matches("packages/!(a|)!()", "packages/x."));
    assert!(!matches("packages/!(a|)!(b|)", "packages/x."));
    assert!(!matches("packages/!(a|)!(@())", "packages/x."));
    assert!(!matches("packages/!()@(*)", "packages/a."));
    assert!(!matches("packages/!()+(*)", "packages/a."));
    assert!(matches("packages/+(*)", "packages/a."));
    assert!(!matches("packages/+(*)", "packages/.a"));

    assert!(matches("packages/*(?(*)|b)", "packages/.a"));
    assert!(matches("packages/*(*(*)|b)", "packages/.a"));
    assert!(matches("packages/*(*(?|*)|b)", "packages/.a"));

    for pattern in ["packages/+(@())", "packages/*(a|@())"] {
        let error = NpmMinimatch::compile(pattern).unwrap_err();
        assert!(error.contains("repeated extglobs containing nested empty @()"));
    }
}
