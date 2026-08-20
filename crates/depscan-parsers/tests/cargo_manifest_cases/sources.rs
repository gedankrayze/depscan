use super::support::*;

#[test]
fn normalizes_lock_sources_with_cargo_url_semantics() {
    let manifest = r#"[package]
name = "root"
version = "1.0.0"

[dependencies]
dep = { version = "1", registry = "private" }
"#;
    let packages = parse_inline_cargo(
        manifest,
        r#"version = 4

[[package]]
name = "root"
version = "1.0.0"
dependencies = ["dep 1.0.0 (registry+https://EXAMPLE.com:443/index)"]

[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://EXAMPLE.com:443/index"
"#,
    )
    .unwrap();
    let dep = packages
        .iter()
        .find(|package| package.name == "dep")
        .unwrap();
    assert!(dep.direct && dep.direct_known);
    assert!(!dep.dev_known, "named registry scope is not URL-proven");

    parse_inline_cargo(
        manifest,
        r#"version = 4
[[package]]
name = "sparse"
version = "1.0.0"
source = "sparse+https://EXAMPLE.com:443/index"
[[package]]
name = "sparse"
version = "1.0.0"
source = "sparse+https://example.com/index"
"#,
    )
    .expect("sparse URL parsing retains the full custom-scheme port identity");

    let local = parse_inline_cargo(
        r#"[package]
name = "root"
version = "1.0.0"

[dependencies]
local = { path = "../outside-local" }
"#,
        r#"version = 4
[[package]]
name = "root"
version = "1.0.0"
dependencies = ["local"]
[[package]]
name = "local"
version = "1.0.0"
source = "path+file:///tmp/local"
[[package]]
name = "local"
version = "1.0.0"
source = "registry+https://example.com/index"
"#,
    )
    .unwrap();
    let local = local
        .iter()
        .find(|package| package.name == "local")
        .unwrap();
    assert!(local.direct && local.direct_known);
    assert!(!local.dev_known, "path declaration scope is conservative");
}
