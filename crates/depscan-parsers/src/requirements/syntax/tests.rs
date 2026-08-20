use super::*;

#[test]
fn joins_continuations_before_removing_comments() {
    let input = ["alpha==1 \\", " --hash=sha256:aa # hash", "beta==2\\\\"].join("\n");
    let lines = logical_lines(&input).unwrap();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].number, 1);
    assert_eq!(lines[0].text, "alpha==1  --hash=sha256:aa # hash");
    assert_eq!(lines[1].text, "beta==2\\\\");
}

#[test]
fn parses_attached_and_separated_includes() {
    assert_eq!(
        parse_line("-rnested.txt", Path::new(".")),
        Ok(ParsedLine::Include {
            kind: IncludeKind::Requirement,
            target: "nested.txt".to_owned(),
        })
    );
    assert_eq!(
        parse_line("--requirement=nested.txt", Path::new(".")),
        Ok(ParsedLine::Include {
            kind: IncludeKind::Requirement,
            target: "nested.txt".to_owned(),
        })
    );
}

#[test]
fn parses_exact_range_extras_and_direct_sources() {
    let exact = parse_line(
        "Requests[security,Socks]==2.32.5 ; python_version >= '3.9' --hash=sha256:aa",
        Path::new("."),
    )
    .unwrap();
    let ParsedLine::Package(exact) = exact else {
        panic!("expected package");
    };
    assert_eq!(exact.display_name, "Requests");
    assert_eq!(exact.version, "2.32.5");
    assert!(!exact.resolved_from_range);
    assert!(exact.has_marker);

    let range = parse_line("urllib3>=2,<3", Path::new(".")).unwrap();
    let ParsedLine::Package(range) = range else {
        panic!("expected package");
    };
    assert!(range.resolved_from_range);
    assert_eq!(range.version, ">=2,<3");
    assert_eq!(
        range.registry_constraint,
        Some(ConstraintSpec {
            raw: ">=2,<3".to_owned(),
            normalized: ">=2, <3".to_owned(),
        })
    );

    let direct = parse_line(
        "urllib3 @ https://example.invalid/urllib3.zip",
        Path::new("."),
    )
    .unwrap();
    let ParsedLine::Package(direct) = direct else {
        panic!("expected package");
    };
    assert!(!direct.enrichable);
    assert!(direct.resolved_from_range);

    let windows_path = parse_line(r"C:\src\Win_Pkg-1.0-py3-none-any.whl", Path::new(".")).unwrap();
    let ParsedLine::Package(windows_path) = windows_path else {
        panic!("expected package");
    };
    assert_eq!(windows_path.display_name, "Win_Pkg");
    assert!(!windows_path.enrichable);
}

#[test]
fn rejects_unknown_options_and_malformed_hashes() {
    let unknown = parse_line("--proxy=https://secret.invalid", Path::new("."))
        .unwrap_err()
        .message()
        .to_owned();
    assert!(unknown.contains("--proxy"));
    assert!(!unknown.contains("secret.invalid"));

    let hash = parse_line("safe==1 --hash=sha256:not-hex", Path::new("."))
        .unwrap_err()
        .message()
        .to_owned();
    assert!(hash.contains("hexadecimal digest"));
}
