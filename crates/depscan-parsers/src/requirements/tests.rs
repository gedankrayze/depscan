use super::*;
use std::{
    fs,
    sync::{Arc, Barrier},
    thread,
};

#[cfg(unix)]
use std::os::unix::fs::symlink as symlink_path;
#[cfg(windows)]
use std::os::windows::fs::{symlink_dir, symlink_file};

fn write(path: &Path, text: impl AsRef<[u8]>) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, text).unwrap();
}

#[cfg(unix)]
fn symlink_file(original: &Path, link: &Path) -> std::io::Result<()> {
    symlink_path(original, link)
}

#[cfg(unix)]
fn symlink_directory(original: &Path, link: &Path) -> std::io::Result<()> {
    symlink_path(original, link)
}

#[cfg(windows)]
fn symlink_directory(original: &Path, link: &Path) -> std::io::Result<()> {
    symlink_dir(original, link)
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy)]
enum ReplacementKind {
    Regular,
    SymbolicLink,
}

#[cfg(any(unix, windows))]
enum SwapOutcome {
    Swapped,
    Denied,
    Inconclusive(String),
}

#[cfg(any(unix, windows))]
fn attempt_namespace_swap(
    original: &Path,
    moved: &Path,
    replacement: &Path,
    kind: ReplacementKind,
    directory: bool,
) -> SwapOutcome {
    if fs::rename(original, moved).is_err() {
        return SwapOutcome::Denied;
    }
    let installed = match kind {
        ReplacementKind::Regular => fs::rename(replacement, original),
        ReplacementKind::SymbolicLink if directory => symlink_directory(replacement, original),
        ReplacementKind::SymbolicLink => symlink_file(replacement, original),
    };
    if installed.is_ok() {
        return SwapOutcome::Swapped;
    }
    match fs::rename(moved, original) {
        Ok(()) => SwapOutcome::Denied,
        Err(error) => SwapOutcome::Inconclusive(format!(
            "replacement install failed and original namespace could not be restored: {error}"
        )),
    }
}

#[cfg(any(unix, windows))]
fn parse_with_boundary_swap<F>(
    root: &Path,
    boundary: ReadBoundary,
    target: &Path,
    swap: F,
) -> (Result<Vec<Package>, ParseError>, SwapOutcome)
where
    F: FnOnce() -> SwapOutcome + Send + 'static,
{
    let barrier = Arc::new(Barrier::new(2));
    let worker_barrier = barrier.clone();
    let worker = thread::spawn(move || {
        worker_barrier.wait();
        let outcome = swap();
        worker_barrier.wait();
        outcome
    });
    let mut reached = false;
    let mut hook = |actual, relative: &Path, _display: &Path| {
        if !reached && actual == boundary && relative == target {
            reached = true;
            barrier.wait();
            barrier.wait();
        }
        Ok(())
    };
    let result = parse_with_limits_and_hook(root, RequirementsLimits::default(), &mut hook);
    assert!(
        reached,
        "requirements parser did not reach {boundary:?} for {target:?}"
    );
    (
        result,
        worker.join().expect("join requirements swap worker"),
    )
}

#[cfg(any(unix, windows))]
fn assert_swap_result(
    result: Result<Vec<Package>, ParseError>,
    outcome: SwapOutcome,
    safe_package: &str,
    sentinel: &str,
) {
    match outcome {
        SwapOutcome::Swapped => {
            let error = result.expect_err("a successful namespace swap must fail closed");
            let message = error.to_string();
            assert!(message.contains("changed"), "{message}");
            assert!(!message.contains(sentinel), "{message}");
        }
        SwapOutcome::Denied => {
            let packages = result.expect("an OS-denied swap must preserve the original parse");
            let package_names = names(&packages);
            assert!(package_names.contains(&safe_package), "{package_names:?}");
            assert!(!package_names.contains(&sentinel), "{package_names:?}");
        }
        SwapOutcome::Inconclusive(message) => panic!("{message}"),
    }
}

fn names(packages: &[Package]) -> Vec<&str> {
    packages
        .iter()
        .map(|package| package.name.as_str())
        .collect()
}

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
