use super::*;

#[cfg(any(unix, windows))]
#[test]
fn follows_only_intermediate_symlinks_that_remain_inside_the_root_capability() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    let root = project.join("requirements.txt");
    let actual = project.join("actual");
    let alias = project.join("nested/alias");
    write(&root, "-r nested/alias/included.txt\n");
    write(&actual.join("included.txt"), "inside-parent-alias==1\n");
    fs::create_dir_all(alias.parent().unwrap()).unwrap();
    if let Err(error) = symlink_directory(Path::new("../actual"), &alias) {
        #[cfg(windows)]
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            return;
        }
        panic!("create contained parent alias: {error}");
    }

    let packages = parse(&root).unwrap();

    assert_eq!(names(&packages), vec!["inside-parent-alias"]);
    assert_eq!(
        packages[0].source_file,
        fs::canonicalize(actual.join("included.txt")).unwrap()
    );
}

#[cfg(any(unix, windows))]
#[test]
fn resolves_nested_contained_symlink_to_sibling_through_root_capability() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    let root = project.join("requirements.txt");
    let actual = project.join("actual");
    let alias = project.join("nested/deeper/alias");
    write(&root, "-r nested/deeper/alias/included.txt\n");
    write(&actual.join("included.txt"), "root-fallback-alias==1\n");
    fs::create_dir_all(alias.parent().unwrap()).unwrap();
    if let Err(error) = symlink_directory(Path::new("../../actual"), &alias) {
        #[cfg(windows)]
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            return;
        }
        panic!("create nested contained parent alias: {error}");
    }

    let packages = parse(&root).unwrap();

    assert_eq!(names(&packages), vec!["root-fallback-alias"]);
    assert_eq!(
        packages[0].source_file,
        fs::canonicalize(actual.join("included.txt")).unwrap()
    );
}

#[cfg(any(unix, windows))]
#[test]
fn rejects_intermediate_symlink_escape_without_reading_outside_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    let outside = directory.path().join("outside");
    let root = project.join("requirements.txt");
    let alias = project.join("alias");
    let sentinel = "outside-parent-sentinel==9.9.9";
    write(&root, "-r alias/included.txt\n");
    write(&outside.join("included.txt"), sentinel);
    if let Err(error) = symlink_directory(&outside, &alias) {
        #[cfg(windows)]
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            return;
        }
        panic!("create escaping parent alias: {error}");
    }

    let error = parse(&root).unwrap_err().to_string();

    assert!(error.contains("within scan root") || error.contains("outside scan root"));
    assert!(!error.contains(sentinel));
}

#[test]
fn detects_hardlink_alias_cycles_by_open_file_identity() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("requirements.txt");
    let alias = directory.path().join("alias.txt");
    write(&root, "-r alias.txt\n");
    fs::hard_link(&root, &alias).unwrap();

    let error = parse(&root).unwrap_err().to_string();

    assert!(error.contains("include cycle detected"), "{error}");
    assert!(error.contains("requirements.txt"), "{error}");
    assert!(error.contains("alias.txt"), "{error}");
}
