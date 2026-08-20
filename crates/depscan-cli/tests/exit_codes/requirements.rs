use super::support::*;

#[test]
fn requirements_escape_exits_ten_before_provider_access() {
    let directory = TestDirectory::new("requirements-escape");
    let project = directory.path().join("project");
    let cache = directory.path().join("cache");
    let outside = directory.path().join("outside.txt");
    let secret = "outside-requirements-secret==9.9.9";
    fs::create_dir(&project).expect("create Python project");
    fs::write(project.join("requirements.txt"), "-r ../outside.txt\n")
        .expect("write root requirements");
    fs::write(&outside, secret).expect("write outside requirements");

    let output = command(&cache)
        .args([
            "scan",
            "--offline",
            project.to_str().expect("UTF-8 project path"),
        ])
        .output()
        .expect("run depscan");

    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "outside scan root");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requirements include chain"));
    assert!(stderr.contains("outside.txt"));
    assert!(!stderr.contains(secret));
    assert!(
        !stderr.contains("missing OSV dump") && !stderr.contains("provider"),
        "requirements validation reached provider access: {stderr}"
    );
}

#[cfg(all(unix, debug_assertions))]
#[test]
fn requirements_file_swap_exits_ten_before_cache_or_provider_access() {
    const BARRIER_ENV: &str = "DEPSCAN_INTERNAL_TEST_REQUIREMENTS_BARRIER_83E3A8B5D3B4497A";
    const BARRIER_NONCE: &str = "ds060-5c9847fe18b243c6a417e737d9570bf1";

    let control_directory = TestDirectory::new("requirements-race-control");
    let wrong_nonce_project = TestDirectory::new("requirements-race-no-hook");
    let wrong_nonce_cache = wrong_nonce_project.path().join("absent-cache");
    fs::write(
        wrong_nonce_project.path().join("requirements.txt"),
        "--unsupported-requirements-option\n",
    )
    .expect("write no-hook requirements fixture");
    let wrong_nonce = format!(
        "wrong-nonce\tfile-opened\trequirements.txt\t{}",
        control_directory.path().display()
    );
    let no_hook = command(&wrong_nonce_cache)
        .env(BARRIER_ENV, wrong_nonce)
        .args([
            "scan",
            wrong_nonce_project
                .path()
                .to_str()
                .expect("UTF-8 project path"),
        ])
        .output()
        .expect("run no-hook requirements control");
    assert_exit(&no_hook, 10);
    assert!(
        !control_directory
            .path()
            .join(format!("{BARRIER_NONCE}.ready"))
            .exists()
    );
    assert!(!wrong_nonce_cache.exists());

    let directory = TestDirectory::new("requirements-file-race");
    let project = directory.path().join("project");
    let cache = directory.path().join("absent-cache");
    let included = project.join("included.txt");
    let original = project.join("included-original.txt");
    let outside = directory.path().join("outside.txt");
    let sentinel = "outside-race-sentinel==9.9.9";
    fs::create_dir(&project).expect("create Python project");
    fs::write(project.join("requirements.txt"), "-r included.txt\n")
        .expect("write root requirements");
    fs::write(&included, "safe-before-swap==1\n").expect("write safe include");
    fs::write(&outside, sentinel).expect("write outside requirements sentinel");

    let barrier_configuration = format!(
        "{BARRIER_NONCE}\tfile-opened\tincluded.txt\t{}",
        control_directory.path().display()
    );
    let mut child = command(&cache)
        .env(BARRIER_ENV, barrier_configuration)
        .args([
            "scan",
            "--offline",
            project.to_str().expect("UTF-8 project path"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start depscan requirements race process");
    let ready = control_directory
        .path()
        .join(format!("{BARRIER_NONCE}.ready"));
    let resume = control_directory
        .path()
        .join(format!("{BARRIER_NONCE}.continue"));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.is_file() {
        if let Some(status) = child.try_wait().expect("poll requirements race process") {
            panic!("requirements race process exited before its barrier: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "requirements race process did not reach its barrier"
        );
        thread::sleep(Duration::from_millis(5));
    }
    fs::rename(&included, &original).expect("move opened requirements include");
    fs::rename(&outside, &included).expect("install outside replacement at include name");
    fs::write(&resume, b"continue").expect("release requirements race process");

    let output = child
        .wait_with_output()
        .expect("wait for depscan requirements race process");
    assert_exit(&output, 10);
    assert_diagnostic_only_on_stderr(&output, "changed while reading");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(sentinel),
        "outside bytes leaked into stderr: {stderr}"
    );
    assert!(
        !cache.exists(),
        "provider cache was created before parse rejection"
    );
}
