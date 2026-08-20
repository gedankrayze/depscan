use super::*;

#[test]
fn follows_component_local_utf16_and_unicode_regexp_modes() {
    assert!(matches("packages/😀", "packages/😀"));
    assert!(matches("packages/@(😀)", "packages/😀"));
    assert!(!matches("packages/?", "packages/😀"));
    assert!(matches("packages/??", "packages/😀"));
    assert!(!matches("packages/@(?)", "packages/😀"));
    assert!(!matches("packages/[𐀀]", "packages/𐀀"));
    assert!(!matches("packages/[!𐀀]", "packages/𐀀"));
    assert!(matches("packages/*[𐀀]", "packages/𐀀"));

    assert!(matches("packages/@(?|[[:alpha:]])", "packages/😀"));
    assert!(matches("packages/@([𐀀]|[[:digit:]])", "packages/𐀀"));
    assert!(!matches("packages/[[:alpha:]]/?", "packages/a/😀"));
    assert!(matches("packages/[[:alpha:]]/??", "packages/a/😀"));
    assert!(!matches("packages/{[😀],[[:alpha:]]}", "packages/😀"));
    assert!(matches("packages/!(?)", "packages/😀"));
    assert!(!matches("packages/!(?|[[:alpha:]])", "packages/😀"));

    for pattern in [
        "packages/[𐀀-𐀂]",
        "packages/[!a😀-a]?",
        "packages/@([a-😀]|[[:digit:]])",
        "packages/@([😀-\u{e000}]|[[:digit:]])",
    ] {
        let error = NpmMinimatch::compile(pattern).unwrap_err();
        assert!(error.contains("non-BMP characters with hyphens"), "{error}");
    }
    assert!(!matches("packages/[a-[:alpha:]]", "packages/a"));
    assert!(matches("packages/[!a[:graph:]]", "packages/b"));
    assert!(matches("packages/[.-.]x", "packages/.x"));
    assert!(matches("packages/[a[:graph:]][[:alpha:]]", "packages/.x"));
    assert!(matches("packages/[!a[:graph:]][[:alpha:]]", "packages/.x"));
}

#[test]
fn rejects_minimatch_invalid_unicode_escapes_and_empty_quantifiers() {
    for pattern in [
        "packages/@(-|[[:alpha:]])",
        "packages/@(,|[[:alpha:]])",
        "packages/@(#|[[:alpha:]])",
        "packages/@( |[[:alpha:]])",
        "packages/@([-]|[[:alpha:]])",
        "packages/@([---]|[[:alpha:]])",
    ] {
        let error = NpmMinimatch::compile(pattern).unwrap_err();
        assert!(error.contains("invalid under minimatch's Unicode regular-expression rules"));
    }

    assert!(matches("packages/@([a-]|[[:alpha:]])", "packages/-"));
    assert!(matches("packages/@(-|[[:ascii:]])", "packages/-"));
    assert!(matches("packages/[[:alpha:]]/-", "packages/a/-"));
    for line_terminator in ['\n', '\r', '\u{2028}', '\u{2029}'] {
        let pattern = format!("packages/@([{line_terminator}]|[[:alpha:]])");
        let candidate = format!("packages/{line_terminator}");
        assert!(NpmMinimatch::compile(&pattern).is_ok(), "{pattern:?}");
        assert!(matches(&pattern, &candidate), "{pattern:?}");

        let invalid_literal = format!("packages/@({line_terminator}|[[:alpha:]])");
        let error = NpmMinimatch::compile(&invalid_literal).unwrap_err();
        assert!(error.contains("invalid under minimatch's Unicode regular-expression rules"));
    }

    for broad_negative in ["!()", "!(a|)", "!(@(a))"] {
        for empty_operator in ['?', '+', '*'] {
            for pattern in [
                format!("packages/{broad_negative}{empty_operator}()"),
                format!("packages/@({broad_negative}{empty_operator}())"),
            ] {
                let error = NpmMinimatch::compile(&pattern).unwrap_err();
                assert!(
                    error.contains("invalid minimatch regular expression"),
                    "{pattern}: {error}"
                );
            }
        }
    }
    for pattern in ["packages/!(a)!()?()", "packages/@(!(a)!()?())"] {
        let error = NpmMinimatch::compile(pattern).unwrap_err();
        assert!(error.contains("invalid minimatch regular expression"));
    }

    for empty_operator in ['?', '+', '*'] {
        for pattern in [
            format!("packages/!(a){empty_operator}()"),
            format!("packages/@(!(a){empty_operator}())"),
            format!("packages/!()!(a){empty_operator}()"),
            format!("packages/@(!()!(a){empty_operator}())"),
        ] {
            assert!(NpmMinimatch::compile(&pattern).is_ok(), "{pattern}");
        }
    }
}
