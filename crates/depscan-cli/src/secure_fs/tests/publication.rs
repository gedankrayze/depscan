use super::{support::*, *};

#[test]
fn preexisting_output_parent_symlink_is_rejected() {
    let directory = tempdir().expect("tempdir");
    let root = directory.path().join("project");
    let outside = directory.path().join("outside");
    fs::create_dir(&root).expect("create root");
    fs::create_dir(&outside).expect("create outside");
    if let Err(error) = create_directory_symlink(&outside, &root.join("reports")) {
        if error.kind() == io::ErrorKind::PermissionDenied {
            assert!(!outside.join("audit.json").exists());
            eprintln!(
                "Windows runner lacks symlink privilege; the OS prevented the parent-symlink fixture"
            );
            return;
        }
        panic!("create output-parent symlink: {error}");
    }
    let output = root.join("reports/audit.json");
    assert!(
        ConfinedOutput::prepare(
            ScanRoot::open(&root).expect("open scan root"),
            Path::new("reports/audit.json"),
            &output,
        )
        .is_err()
    );
    assert!(!outside.join("audit.json").exists());
}

#[test]
fn output_is_atomically_replaced_through_the_validated_parent_handle() {
    let directory = tempdir().expect("tempdir");
    let root = directory.path().join("project");
    let reports = root.join("reports");
    fs::create_dir_all(&reports).expect("create reports");
    let output = reports.join("audit.json");
    fs::write(&output, "old").expect("write old output");
    let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);
    capability.write(b"new report").expect("replace output");
    assert_eq!(
        fs::read_to_string(output).expect("read output"),
        "new report"
    );
}

#[cfg(unix)]
#[test]
fn atomic_replacement_preserves_existing_unix_mode() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory = tempdir().expect("tempdir");
    let root = directory.path().join("project");
    let reports = root.join("reports");
    fs::create_dir_all(&reports).expect("create reports");
    let output = reports.join("audit.json");
    fs::write(&output, "old").expect("write old output");
    fs::set_permissions(&output, fs::Permissions::from_mode(0o600)).expect("restrict output mode");

    let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);
    capability.write(b"new report").expect("replace output");

    assert_eq!(
        fs::metadata(output).expect("output metadata").mode() & 0o777,
        0o600
    );
}

#[test]
fn missing_output_is_atomically_created_through_the_validated_parent_handle() {
    let directory = tempdir().expect("tempdir");
    let root = directory.path().join("project");
    let reports = root.join("reports");
    fs::create_dir_all(&reports).expect("create reports");
    let output = reports.join("audit.json");
    let capability = prepare_output(&root, Path::new("reports/audit.json"), &output);
    capability.write(b"new report").expect("publish output");
    assert_eq!(
        fs::read_to_string(output).expect("read output"),
        "new report"
    );
}
