use super::support::*;
use depscan_core::SourceKind;

#[test]
fn rejects_ambiguous_dangling_duplicate_and_malformed_cargo_lock_graphs() {
    let manifest = r#"[package]
name = "root"
version = "1.0.0"
"#;
    for (name, lock, expected) in [
        (
            "ambiguous",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
dependencies = ["dup"]
[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "dup"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            "omits a version",
        ),
        (
            "dangling",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
dependencies = ["missing"]
"#,
            "no matching locked package",
        ),
        (
            "self dependency",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
dependencies = ["root"]
"#,
            "cannot depend on itself",
        ),
        (
            "duplicate",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
[[package]]
name = "root"
version = "1.0.0"
"#,
            "repeats exact package identity",
        ),
        (
            "semantically duplicate source",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
source = "registry+https://EXAMPLE.com:443/index"
[[package]]
name = "root"
version = "1.0.0"
source = "registry+https://example.com/index"
"#,
            "repeats exact package identity",
        ),
        (
            "non-string edge",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
dependencies = [42]
"#,
            "must be a non-empty string",
        ),
        (
            "noncanonical dependency spacing",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
dependencies = ["dep  1.0.0"]
[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            "malformed dependency reference",
        ),
        (
            "dependencies and replace",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
dependencies = []
replace = "replacement 1.0.0"
[[package]]
name = "replacement"
version = "1.0.0"
"#,
            "cannot define both dependencies and replace",
        ),
        (
            "dangling replace",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
replace = "missing 1.0.0"
"#,
            "no matching locked package",
        ),
        (
            "replacement coordinate mismatch",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
replace = "other 2.0.0 (git+https://example.com/other#abcdef)"
[[package]]
name = "other"
version = "2.0.0"
source = "git+https://example.com/other#abcdef"
"#,
            "replacement must have the same package name and version",
        ),
        (
            "replacement cycle",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
replace = "root 1.0.0 (git+https://example.com/root#abcdef)"
[[package]]
name = "root"
version = "1.0.0"
source = "git+https://example.com/root#abcdef"
replace = "root 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"
"#,
            "replacement target cannot itself define replace",
        ),
        (
            "malformed git source",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
source = "git+not a URL"
"#,
            "invalid Git source URL",
        ),
        (
            "malformed registry source",
            r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
source = "registry+not a URL"
"#,
            "invalid registry source URL",
        ),
    ] {
        let error = parse_inline_cargo(manifest, lock).unwrap_err();
        assert!(
            error.contains(expected),
            "{name}: expected {expected:?}, got {error:?}"
        );
    }
}

#[test]
fn malformed_workspace_and_dependency_shapes_fail_cleanly() {
    for (fixture_name, expected) in [
        (
            "malformed-missing-inherited",
            "inherits from a missing [workspace.dependencies] entry",
        ),
        (
            "malformed-package-type",
            "field \"package\" must be a string",
        ),
        ("malformed-unmatched-member", "matched no packages"),
    ] {
        let root = fixture(fixture_name);
        let error = parse(root.join("Cargo.toml"), SourceKind::CargoToml).unwrap_err();
        assert!(
            error.contains(expected),
            "{fixture_name}: expected {expected:?}, got {error:?}"
        );
    }
}
