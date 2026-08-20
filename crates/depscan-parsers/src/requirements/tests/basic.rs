use super::*;

#[test]
fn parses_nested_relative_and_long_form_includes() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("requirements.txt");
    write(
        &root,
        "root-package==1.0\n-r nested/base.txt\n--requirement nested/more.txt\n",
    );
    write(
        &directory.path().join("nested/base.txt"),
        "base-package==2.0\n-r ../shared.txt\n",
    );
    write(
        &directory.path().join("nested/more.txt"),
        "more-package==3.0\n",
    );
    write(
        &directory.path().join("shared.txt"),
        "shared-package==4.0\n",
    );

    let packages = parse(&root).unwrap();

    assert_eq!(
        names(&packages),
        vec![
            "base-package",
            "more-package",
            "root-package",
            "shared-package"
        ]
    );
}

#[test]
fn preserves_pep440_constraint_without_extras_or_environment_marker() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("requirements.txt");
    write(
        &root,
        "range-package[security]>=1.0,<2.0,!=1.5; python_version >= '3.11'\n",
    );

    let packages = parse(&root).unwrap();

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "range-package");
    assert_eq!(packages[0].version, ">=1.0,<2.0,!=1.5");
    let constraint = packages[0].manifest_constraint.as_ref().unwrap();
    assert_eq!(constraint.raw(), ">=1.0,<2.0,!=1.5");
    assert_eq!(constraint.normalized(), ">=1.0, !=1.5, <2.0");
}

#[test]
fn rejects_parent_escape_without_exposing_outside_contents() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    let root = project.join("requirements.txt");
    let outside = directory.path().join("outside.txt");
    let secret = "outside-secret-must-not-appear==9.9.9";
    write(&root, "-r ../outside.txt\n");
    write(&outside, secret);

    let error = parse(&root).unwrap_err().to_string();

    assert!(error.contains("outside scan root"));
    assert!(error.contains("requirements include chain"));
    assert!(error.contains("outside.txt"));
    assert!(!error.contains(secret));
}

#[test]
fn rejects_absolute_external_include() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    let root = project.join("requirements.txt");
    let outside = directory.path().join("absolute-outside.txt");
    write(&outside, "outside==1\n");
    write(&root, format!("-r {}\n", outside.display()));

    let error = parse(&root).unwrap_err().to_string();

    assert!(error.contains("outside scan root"));
    assert!(error.contains(&outside.to_string_lossy().into_owned()));
}

#[test]
fn accepts_native_absolute_include_that_remains_inside_root() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("requirements.txt");
    let included = directory.path().join("absolute-inside.txt");
    write(&included, "inside==1\n");
    write(&root, format!("--requirement {}\n", included.display()));

    let packages = parse(&root).unwrap();

    assert_eq!(names(&packages), vec!["inside"]);
}

#[cfg(any(unix, windows))]
#[test]
fn preserves_absolute_includes_spelled_through_the_scan_root_alias() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    let alias = directory.path().join("project-alias");
    let root = alias.join("requirements.txt");
    let included = alias.join("nested/absolute.txt");
    write(
        &project.join("requirements.txt"),
        format!("-r {}\n", included.display()),
    );
    write(&project.join("nested/absolute.txt"), "aliased-inside==1\n");
    if let Err(error) = symlink_directory(&project, &alias) {
        #[cfg(windows)]
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            return;
        }
        panic!("create scan-root alias: {error}");
    }

    let packages = parse(&root).unwrap();

    assert_eq!(names(&packages), vec!["aliased-inside"]);
    assert_eq!(
        packages[0].source_file,
        fs::canonicalize(project.join("nested/absolute.txt")).unwrap()
    );
}

#[cfg(windows)]
#[test]
fn windows_absolute_root_prefix_matching_is_case_insensitive_and_component_bounded() {
    assert_eq!(
        strip_root_prefix(
            Path::new(r"c:\PROJECT\Nested\File.txt"),
            Path::new(r"C:\project")
        ),
        Some(PathBuf::from(r"Nested\File.txt"))
    );
    assert_eq!(
        strip_root_prefix(
            Path::new(r"C:\project-other\File.txt"),
            Path::new(r"C:\project")
        ),
        None
    );
    assert_eq!(
        strip_root_prefix(Path::new(r"D:\project\File.txt"), Path::new(r"C:\project")),
        None
    );
}
