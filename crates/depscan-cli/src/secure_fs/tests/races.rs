use super::{support::*, *};

#[cfg(not(windows))]
#[test]
fn output_parent_swap_cannot_redirect_publication_or_cleanup() {
    let directory = tempdir().expect("tempdir");
    let root = directory.path().join("project");
    let reports = root.join("reports");
    let moved_reports = root.join("reports-original");
    fs::create_dir_all(&reports).expect("create reports");
    let output = reports.join("audit.json");
    let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);

    let barrier = Arc::new(Barrier::new(2));
    let worker_barrier = barrier.clone();
    let reports_for_worker = reports.clone();
    let moved_for_worker = moved_reports.clone();
    let worker = thread::spawn(move || {
        worker_barrier.wait();
        fs::rename(reports_for_worker, moved_for_worker).expect("move validated parent");
    });

    let error = capability
        .write_impl(b"safe report", || {
            barrier.wait();
            worker.join().expect("join parent-swap worker");
            fs::create_dir(&reports).expect("replace validated parent");
        })
        .expect_err("parent swap must fail");
    assert!(matches!(error, SecureFsError::Changed { .. }));
    assert!(!reports.join("audit.json").exists());
    assert!(!moved_reports.join("audit.json").exists());
    assert_eq!(
        fs::read_dir(&moved_reports)
            .expect("read moved parent")
            .count(),
        0,
        "temporary output must be cleaned through the held directory handle"
    );
}

#[cfg(windows)]
#[test]
fn output_parent_handle_prevents_a_windows_parent_swap() {
    let directory = tempdir().expect("tempdir");
    let root = directory.path().join("project");
    let reports = root.join("reports");
    let moved_reports = root.join("reports-original");
    fs::create_dir_all(&reports).expect("create reports");
    let output = reports.join("audit.json");
    let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);
    capability
        .write_impl(b"safe report", || {
            let error = fs::rename(&reports, &moved_reports)
                .expect_err("held Windows directory handle must prevent rename");
            assert_windows_handle_blocks_rename(&error);
        })
        .expect("publish through the unchanged parent");
    assert_eq!(
        fs::read_to_string(output).expect("read output"),
        "safe report"
    );
    assert!(!moved_reports.exists());
}

#[cfg(not(windows))]
#[test]
fn output_target_swap_is_detected_and_external_symlink_target_is_untouched() {
    let directory = tempdir().expect("tempdir");
    let root = directory.path().join("project");
    let reports = root.join("reports");
    fs::create_dir_all(&reports).expect("create reports");
    let output = reports.join("audit.json");
    let external = directory.path().join("external.json");
    fs::write(&external, "preserve").expect("write external target");
    let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);

    let barrier = Arc::new(Barrier::new(2));
    let worker_barrier = barrier.clone();
    let external_for_worker = external.clone();
    let output_for_worker = output.clone();
    let worker = thread::spawn(move || {
        worker_barrier.wait();
        create_file_symlink(&external_for_worker, &output_for_worker)
            .expect("create swapped symlink");
    });

    let error = capability
        .write_impl(b"safe report", || {
            barrier.wait();
            worker.join().expect("join symlink-swap worker");
        })
        .expect_err("target swap must fail");
    assert!(matches!(error, SecureFsError::SymbolicLink { .. }));
    assert_eq!(
        fs::read_to_string(external).expect("read external"),
        "preserve"
    );
}

#[cfg(windows)]
#[test]
fn output_target_symlink_swap_is_rejected_when_windows_can_create_it() {
    let directory = tempdir().expect("tempdir");
    let root = directory.path().join("project");
    let reports = root.join("reports");
    fs::create_dir_all(&reports).expect("create reports");
    let output = reports.join("audit.json");
    let external = directory.path().join("external.json");
    fs::write(&external, "preserve").expect("write external target");
    let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);

    if let Err(error) = create_file_symlink(&external, &output) {
        assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "unexpected Windows symlink creation error: {error}"
        );
        assert!(!output.exists());
        assert_eq!(
            fs::read_to_string(external).expect("read external"),
            "preserve"
        );
        eprintln!("Windows runner lacks symlink privilege; the OS prevented the swap fixture");
        return;
    }

    let error = capability
        .write(b"safe report")
        .expect_err("target symlink swap must fail");
    assert!(matches!(error, SecureFsError::SymbolicLink { .. }));
    assert_eq!(
        fs::read_to_string(external).expect("read external"),
        "preserve"
    );
}

#[cfg(any(unix, windows))]
#[test]
fn output_regular_file_replacement_is_denied_or_detected_before_publication() {
    let directory = tempdir().expect("tempdir");
    let root = directory.path().join("project");
    let reports = root.join("reports");
    fs::create_dir_all(&reports).expect("create reports");
    let output = reports.join("audit.json");
    let moved = reports.join("audit.original.json");
    let replacement = reports.join("replacement.json");
    fs::write(&output, "original").expect("write original output");
    fs::write(&replacement, "concurrent replacement").expect("write replacement output");
    let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);

    let mut outcome = None;
    let result = capability.write_impl(b"new report", || {
        outcome = Some(attempt_regular_file_swap(&output, &moved, &replacement));
    });
    let swapped = restore_regular_file_swap(outcome.expect("replacement was attempted"));

    if swapped {
        assert!(matches!(result, Err(SecureFsError::Changed { .. })));
        assert_eq!(
            fs::read_to_string(output).expect("read restored output"),
            "original"
        );
    } else {
        result.expect("denied replacement permits validated publication");
        assert_eq!(
            fs::read_to_string(output).expect("read published output"),
            "new report"
        );
    }
}
