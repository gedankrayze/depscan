use super::*;

#[cfg(any(unix, windows))]
#[test]
fn root_and_parent_replacements_cannot_redirect_capability_reads() {
    for kind in [ReplacementKind::Regular, ReplacementKind::SymbolicLink] {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        let moved_project = directory.path().join("project-original");
        let outside = directory.path().join("outside-root");
        let root = project.join("requirements.txt");
        let sentinel = "outside-root-sentinel";
        write(&root, "safe-root==1\n");
        write(
            &outside.join("requirements.txt"),
            format!("{sentinel}==9.9.9\n"),
        );
        let project_for_swap = project.clone();
        let outcome_project = moved_project.clone();
        let outside_for_swap = outside.clone();
        let (result, outcome) =
            parse_with_boundary_swap(&root, ReadBoundary::RootOpened, Path::new("."), move || {
                attempt_namespace_swap(
                    &project_for_swap,
                    &outcome_project,
                    &outside_for_swap,
                    kind,
                    true,
                )
            });
        assert_swap_result(result, outcome, "safe-root", sentinel);

        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        let nested = project.join("nested");
        let moved_nested = project.join("nested-original");
        let outside = directory.path().join("outside-parent");
        let root = project.join("requirements.txt");
        let sentinel = "outside-parent-sentinel";
        write(&root, "-r nested/included.txt\n");
        write(&nested.join("included.txt"), "safe-parent==1\n");
        write(
            &outside.join("included.txt"),
            format!("{sentinel}==9.9.9\n"),
        );
        let nested_for_swap = nested.clone();
        let moved_for_swap = moved_nested.clone();
        let outside_for_swap = outside.clone();
        let (result, outcome) = parse_with_boundary_swap(
            &root,
            ReadBoundary::DirectoryOpened,
            Path::new("nested"),
            move || {
                attempt_namespace_swap(
                    &nested_for_swap,
                    &moved_for_swap,
                    &outside_for_swap,
                    kind,
                    true,
                )
            },
        );
        assert_swap_result(result, outcome, "safe-parent", sentinel);
    }
}

#[cfg(any(unix, windows))]
#[test]
fn final_file_replacements_at_open_and_read_boundaries_fail_closed() {
    for boundary in [
        ReadBoundary::FileOpened,
        ReadBoundary::BeforeRead,
        ReadBoundary::AfterRead,
    ] {
        for kind in [ReplacementKind::Regular, ReplacementKind::SymbolicLink] {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().join("requirements.txt");
            let included = directory.path().join("included.txt");
            let moved = directory.path().join("included-original.txt");
            let outside = directory.path().join("outside.txt");
            let sentinel = "outside-final-sentinel";
            write(&root, "-r included.txt\n");
            write(&included, "safe-final==1\n");
            write(&outside, format!("{sentinel}==9.9.9\n"));
            let included_for_swap = included.clone();
            let moved_for_swap = moved.clone();
            let outside_for_swap = outside.clone();
            let (result, outcome) =
                parse_with_boundary_swap(&root, boundary, Path::new("included.txt"), move || {
                    attempt_namespace_swap(
                        &included_for_swap,
                        &moved_for_swap,
                        &outside_for_swap,
                        kind,
                        false,
                    )
                });
            assert_swap_result(result, outcome, "safe-final", sentinel);
        }
    }
}

#[cfg(any(unix, windows))]
#[test]
fn rejects_symbolic_include_before_reading_its_target() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    let root = project.join("requirements.txt");
    let outside = directory.path().join("outside.txt");
    let linked = project.join("linked.txt");
    write(&root, "-r linked.txt\n");
    write(&outside, "symlink-secret==1\n");
    if let Err(error) = symlink_file(&outside, &linked) {
        #[cfg(windows)]
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            return;
        }
        panic!("create requirements symlink: {error}");
    }

    let error = parse(&root).unwrap_err().to_string();

    assert!(error.contains("symbolic link"));
    assert!(error.contains("linked.txt"));
    assert!(!error.contains("symlink-secret"));
}
