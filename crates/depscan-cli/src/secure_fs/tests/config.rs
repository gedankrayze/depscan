use super::{support::*, *};

#[cfg(any(unix, windows))]
#[test]
fn config_regular_file_replacement_is_denied_or_detected() {
    let directory = tempdir().expect("tempdir");
    let config = directory.path().join("depscan.toml");
    let moved = directory.path().join("depscan.original.toml");
    let replacement = directory.path().join("replacement.toml");
    fs::write(&config, "fail-on = 'never'\n").expect("write config");
    fs::write(&replacement, "allow-tools = true\n").expect("write replacement");
    let mut outcome = None;
    let result = read_config_nofollow_impl(&config, false, || {
        outcome = Some(attempt_regular_file_swap(&config, &moved, &replacement));
    });
    let swapped = restore_regular_file_swap(outcome.expect("replacement was attempted"));

    if swapped {
        assert!(matches!(result, Err(SecureFsError::Changed { .. })));
    } else {
        assert_eq!(
            result.expect("denied replacement keeps config readable"),
            Some("fail-on = 'never'\n".to_owned())
        );
    }
    assert_eq!(
        fs::read_to_string(&config).expect("read restored config"),
        "fail-on = 'never'\n"
    );
}

#[cfg(not(windows))]
#[test]
fn config_parent_swap_is_detected_without_following_the_replacement() {
    let directory = tempdir().expect("tempdir");
    let project = directory.path().join("project");
    let configs = project.join("configs");
    let moved_configs = project.join("configs-original");
    fs::create_dir_all(&configs).expect("create config parent");
    let config = configs.join("policy.toml");
    fs::write(&config, "fail-on = 'never'\n").expect("write config");

    let error = read_config_nofollow_impl(&config, false, || {
        fs::rename(&configs, &moved_configs).expect("move validated parent");
        fs::create_dir(&configs).expect("replace config parent");
        fs::write(configs.join("policy.toml"), "allow-tools = true\n")
            .expect("write replacement config");
    });
    assert!(matches!(error, Err(SecureFsError::Changed { .. })));
}

#[cfg(windows)]
#[test]
fn config_parent_handle_prevents_a_windows_parent_swap() {
    let directory = tempdir().expect("tempdir");
    let configs = directory.path().join("configs");
    let moved_configs = directory.path().join("configs-original");
    fs::create_dir(&configs).expect("create config parent");
    let config = configs.join("policy.toml");
    fs::write(&config, "fail-on = 'never'\n").expect("write config");
    let text = read_config_nofollow_impl(&config, false, || {
        let error = fs::rename(&configs, &moved_configs)
            .expect_err("held Windows directory handle must prevent rename");
        assert_windows_handle_blocks_rename(&error);
    })
    .expect("read validated config")
    .expect("config exists");
    assert_eq!(text, "fail-on = 'never'\n");
}

#[cfg(not(windows))]
#[test]
fn implicit_config_and_output_share_one_scan_root_capability() {
    let directory = tempdir().expect("tempdir");
    let root = directory.path().join("project");
    let moved_root = directory.path().join("project-original");
    fs::create_dir_all(root.join("reports")).expect("create original project");
    fs::write(root.join("depscan.toml"), "output = 'reports/audit.json'\n")
        .expect("write implicit config");
    let scan_root = ScanRoot::open(&root).expect("open scan root");
    let config = scan_root
        .read_optional_config(OsStr::new("depscan.toml"), &root.join("depscan.toml"))
        .expect("read implicit config")
        .expect("implicit config exists");
    assert!(config.contains("reports/audit.json"));

    fs::rename(&root, &moved_root).expect("move original scan root");
    fs::create_dir_all(root.join("reports")).expect("create replacement project");
    let error = ConfinedOutput::prepare(
        scan_root,
        Path::new("reports/audit.json"),
        &root.join("reports/audit.json"),
    )
    .expect_err("a replacement scan root must not receive configured output");
    assert!(matches!(error, SecureFsError::Changed { .. }));
    assert!(!root.join("reports/audit.json").exists());
    assert!(!moved_root.join("reports/audit.json").exists());
}

#[cfg(windows)]
#[test]
fn scan_root_handle_prevents_config_to_output_handoff_swap_on_windows() {
    let directory = tempdir().expect("tempdir");
    let root = directory.path().join("project");
    let moved_root = directory.path().join("project-original");
    fs::create_dir_all(root.join("reports")).expect("create project");
    fs::write(root.join("depscan.toml"), "output = 'reports/audit.json'\n")
        .expect("write implicit config");
    let scan_root = ScanRoot::open(&root).expect("open scan root");
    scan_root
        .read_optional_config(OsStr::new("depscan.toml"), &root.join("depscan.toml"))
        .expect("read implicit config")
        .expect("implicit config exists");

    let error = fs::rename(&root, &moved_root)
        .expect_err("held Windows scan-root handle must prevent rename");
    assert_windows_handle_blocks_rename(&error);
    let capability = ConfinedOutput::prepare(
        scan_root,
        Path::new("reports/audit.json"),
        &root.join("reports/audit.json"),
    )
    .expect("prepare output through unchanged root");
    capability.write(b"safe report").expect("publish report");
    assert_eq!(
        fs::read_to_string(root.join("reports/audit.json")).expect("read report"),
        "safe report"
    );
    assert!(!moved_root.exists());
}
