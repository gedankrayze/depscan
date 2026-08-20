use super::*;

#[test]
fn detects_canonical_alias_cycle_with_full_chain() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("requirements.txt");
    let nested = directory.path().join("nested/requirements.txt");
    write(&root, "-r nested/requirements.txt\n");
    write(&nested, "-r .././requirements.txt\n");

    let error = parse(&root).unwrap_err().to_string();

    assert!(error.contains("include cycle detected"));
    assert!(error.contains("requirements include chain"));
    assert_eq!(error.matches("requirements.txt").count(), 4);
}

#[test]
fn allows_repeated_include_when_it_is_not_active() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("requirements.txt");
    write(&root, "-r shared.txt\n-r shared.txt\n");
    write(&directory.path().join("shared.txt"), "shared==1\n");

    let packages = parse(&root).unwrap();

    assert_eq!(names(&packages), vec!["shared"]);
}

#[test]
fn rejects_missing_and_non_file_includes_with_chain() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("requirements.txt");
    write(&root, "-r missing.txt\n");

    let missing = parse(&root).unwrap_err().to_string();
    assert!(missing.contains("cannot inspect requirements file"));
    assert!(missing.contains("missing.txt"));
    assert!(missing.contains("requirements include chain"));

    fs::create_dir(directory.path().join("included-directory")).unwrap();
    write(&root, "-r included-directory\n");
    let directory_error = parse(&root).unwrap_err().to_string();
    assert!(directory_error.contains("not a regular file"));
    assert!(directory_error.contains("included-directory"));
}

#[test]
fn enforces_include_depth_limit() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("requirements.txt");
    write(&root, "-r one.txt\n");
    write(&directory.path().join("one.txt"), "-r two.txt\n");
    write(&directory.path().join("two.txt"), "-r three.txt\n");
    write(&directory.path().join("three.txt"), "leaf==1\n");

    let error = parse_with_limits(
        &root,
        RequirementsLimits {
            include_depth: 2,
            ..RequirementsLimits::default()
        },
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("include depth 3 exceeds the maximum of 2"));
    assert!(error.contains("three.txt"));
}

#[test]
fn enforces_file_count_limit_across_repeated_includes() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("requirements.txt");
    write(&root, "-r shared.txt\n-r shared.txt\n");
    write(&directory.path().join("shared.txt"), "shared==1\n");

    let error = parse_with_limits(
        &root,
        RequirementsLimits {
            files: 2,
            ..RequirementsLimits::default()
        },
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("file count exceeds the maximum of 2"));
    assert!(error.contains("shared.txt"));
}

#[test]
fn enforces_total_byte_limit_before_reading_included_file() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("requirements.txt");
    let root_text = "-r included.txt\n";
    write(&root, root_text);
    write(&directory.path().join("included.txt"), "included==1\n");

    let error = parse_with_limits(
        &root,
        RequirementsLimits {
            bytes: u64::try_from(root_text.len()).unwrap(),
            ..RequirementsLimits::default()
        },
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("maximum total"));
    assert!(error.contains("included.txt"));
}
