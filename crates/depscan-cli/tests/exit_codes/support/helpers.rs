use super::*;

pub(crate) fn command(cache: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_depscan"));
    command
        .env("DEPSCAN_CACHE_DIR", cache)
        .env("NO_COLOR", "1")
        .env_remove("RUST_LOG")
        .env_remove("SOURCE_DATE_EPOCH");
    command
}

pub(crate) fn assert_exit(output: &Output, expected: i32) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn assert_report_only_on_stdout(output: &Output) {
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\"schema_version\""),
        "stdout did not contain the JSON report: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn json_report(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not a JSON report: {error}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

pub(crate) fn assert_diagnostic_only_on_stderr(output: &Output, expected: &str) {
    assert!(
        output.stdout.is_empty(),
        "unexpected stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected),
        "stderr did not contain {expected:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(crate) fn assert_stdout_snapshot(output: &Output, expected_sha256: &str) {
    assert_exit(output, 0);
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        sha256_hex(&output.stdout),
        expected_sha256,
        "stdout snapshot changed:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

pub(crate) fn assert_config_preflight_failure(output: &Output, path: &Path, expected: &str) {
    assert_exit(output, 10);
    assert_diagnostic_only_on_stderr(output, expected);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&path.to_string_lossy().into_owned()),
        "stderr did not name config path {}: {stderr}",
        path.display()
    );
    assert!(
        !stderr.contains("provider hard failure") && !stderr.contains("missing OSV dump"),
        "config validation reached provider access: {stderr}"
    );
}

pub(crate) fn python_fixture(case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../depscan-parsers/tests/fixtures/python")
        .join(case)
}

pub(crate) fn npm_fixture(case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../depscan-parsers/tests/fixtures")
        .join(case)
}

pub(crate) fn lock_schema_fixture(format: &str, case: &str, file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../depscan-parsers/tests/fixtures/schema-validation")
        .join(format)
        .join(case)
        .join(file)
}

pub(crate) fn seed_empty_pypi_dump(cache: &Path) {
    seed_empty_osv_dump(cache, "PyPI");
}

pub(crate) fn seed_empty_npm_dump(cache: &Path) {
    seed_empty_osv_dump(cache, "npm");
}

pub(crate) fn seed_empty_cargo_dump(cache: &Path) {
    seed_empty_osv_dump(cache, "crates_io");
}

pub(crate) fn seed_empty_osv_dump(cache: &Path, ecosystem: &str) {
    fs::create_dir_all(cache).expect("create cache directory");
    fs::write(
        cache.join(".depscan-cache.json"),
        r#"{"schema_version":1,"owner":"depscan"}"#,
    )
    .expect("write cache ownership sentinel");
    let offline = cache.join("offline");
    fs::create_dir_all(&offline).expect("create offline cache directory");
    zip::ZipWriter::new(
        fs::File::create(offline.join(format!("{ecosystem}.zip"))).expect("create offline dump"),
    )
    .finish()
    .expect("finish empty offline dump");
    fs::write(
        offline.join(format!("{ecosystem}.synced-at")),
        Utc::now().to_rfc3339(),
    )
    .expect("write offline dump timestamp");
}

pub(crate) fn seed_malformed_cargo_dump(cache: &Path) {
    seed_cargo_dump_entry(
        cache,
        "RUSTSEC-MALFORMED.json",
        br#"{"id":"RUSTSEC-MALFORMED""#,
    );
}

pub(crate) fn seed_cargo_dump_entry(cache: &Path, name: &str, contents: &[u8]) {
    let offline = cache.join("offline");
    fs::create_dir_all(&offline).expect("create offline cache directory");
    let mut archive = zip::ZipWriter::new(
        fs::File::create(offline.join("crates_io.zip")).expect("create offline dump"),
    );
    archive
        .start_file(name, zip::write::SimpleFileOptions::default())
        .expect("start malformed advisory entry");
    archive
        .write_all(contents)
        .expect("write offline advisory entry");
    archive.finish().expect("finish malformed offline dump");
    fs::write(offline.join("crates_io.synced-at"), Utc::now().to_rfc3339())
        .expect("write offline dump timestamp");
}

pub(crate) fn report_packages(report: &serde_json::Value) -> &[serde_json::Value] {
    report
        .get("results")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .expect("JSON report results")
}

pub(crate) fn report_package_names(report: &serde_json::Value) -> BTreeSet<&str> {
    report_packages(report)
        .iter()
        .map(|result| {
            result
                .pointer("/package/name")
                .and_then(serde_json::Value::as_str)
                .expect("reported package name")
        })
        .collect()
}

pub(crate) fn report_package_coordinates(report: &serde_json::Value) -> BTreeSet<String> {
    report_packages(report)
        .iter()
        .map(|result| {
            let name = result
                .pointer("/package/name")
                .and_then(serde_json::Value::as_str)
                .expect("reported package name");
            let version = result
                .pointer("/package/version")
                .and_then(serde_json::Value::as_str)
                .expect("reported package version");
            format!("{name}@{version}")
        })
        .collect()
}
