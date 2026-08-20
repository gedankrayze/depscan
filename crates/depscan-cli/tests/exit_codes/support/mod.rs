pub(crate) use chrono::Utc;
pub(crate) use sha2::{Digest, Sha256};
pub(crate) use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(all(unix, debug_assertions))]
pub(crate) use std::{
    process::Stdio,
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
pub(crate) use std::os::unix::fs::symlink as symlink_file;
#[cfg(windows)]
pub(crate) use std::os::windows::fs::symlink_file;

mod helpers;

pub(crate) use helpers::*;

pub(crate) const QUERY_DIGEST: &str =
    "2f422c499305285ab2b6919c9f3a7749a0ae65f244b52b53b78ea8a3d83444c7";
pub(crate) const REGISTRY_DIGEST: &str =
    "73a7010ca3d255918cf210add4252cd48f0d933c881b68ea9bcf11cf8a400ac1";
pub(crate) const VULNERABILITY_DIGEST: &str =
    "12c66ec82798932e9795db87745d1ac1cebf373cee0ffe9cbd57b2533e2f4530";

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

pub(crate) struct TestDirectory(PathBuf);

impl TestDirectory {
    pub(crate) fn new(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "depscan-cli-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated test directory");
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove isolated test directory");
    }
}

pub(crate) struct TestProject {
    pub(crate) directory: TestDirectory,
    pub(crate) cache: PathBuf,
}

impl TestProject {
    pub(crate) fn rust(label: &str) -> Self {
        let directory = TestDirectory::new(label);
        let cache = directory.path().join("cache");
        fs::create_dir(&cache).expect("create cache directory");
        fs::write(
            cache.join(".depscan-cache.json"),
            r#"{"schema_version":1,"owner":"depscan"}"#,
        )
        .expect("write cache ownership sentinel");
        fs::write(
            directory.path().join("Cargo.lock"),
            r#"version = 3

[[package]]
name = "demo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"
"#,
        )
        .expect("write Cargo.lock fixture");
        Self { directory, cache }
    }

    pub(crate) fn seed_clean(&self, latest: &str) {
        self.seed_cache("osv/query", QUERY_DIGEST, "[]");
        self.seed_cache(
            "registry",
            REGISTRY_DIGEST,
            &format!(
                r#"{{"schema_version":1,"entries":[{{"name":"demo","vers":"1.0.0","yanked":false}},{{"name":"demo","vers":"{latest}","yanked":false}}]}}"#
            ),
        );
    }

    pub(crate) fn add_rust_package(&self, name: &str) {
        let mut lockfile = fs::OpenOptions::new()
            .append(true)
            .open(self.directory.path().join("Cargo.lock"))
            .expect("open Cargo.lock fixture");
        writeln!(
            lockfile,
            r#"
[[package]]
name = "{name}"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1111111111111111111111111111111111111111111111111111111111111111""#
        )
        .expect("append Cargo.lock package");
    }

    pub(crate) fn seed_yanked_current(&self) {
        self.seed_cache("osv/query", QUERY_DIGEST, "[]");
        self.seed_cache(
            "registry",
            REGISTRY_DIGEST,
            r#"{"schema_version":1,"entries":[{"name":"demo","vers":"0.9.0","yanked":false},{"name":"demo","vers":"1.0.0","yanked":true}]}"#,
        );
    }

    pub(crate) fn seed_yanked_outdated(&self) {
        self.seed_cache("osv/query", QUERY_DIGEST, "[]");
        self.seed_cache(
            "registry",
            REGISTRY_DIGEST,
            r#"{"schema_version":1,"entries":[{"name":"demo","vers":"1.0.0","yanked":true},{"name":"demo","vers":"2.0.0","yanked":false}]}"#,
        );
    }

    pub(crate) fn seed_empty_offline_dump(&self) {
        seed_empty_cargo_dump(&self.cache);
    }

    pub(crate) fn set_cache_timestamp(
        &self,
        namespace: &str,
        digest: &str,
        timestamp: chrono::DateTime<Utc>,
    ) {
        let path = self.cache.join(namespace).join(format!("{digest}.json"));
        let mut entry: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read cache fixture"))
                .expect("decode cache fixture");
        entry["stored_at"] = serde_json::Value::String(timestamp.to_rfc3339());
        fs::write(path, serde_json::to_vec(&entry).unwrap()).expect("update cache timestamp");
    }

    pub(crate) fn seed_vulnerability(&self) {
        self.seed_vulnerability_record(false, &[]);
    }

    pub(crate) fn seed_vulnerability_with_aliases(&self, aliases: &[&str]) {
        self.seed_vulnerability_record(false, aliases);
    }

    pub(crate) fn seed_withdrawn_vulnerability(&self) {
        self.seed_vulnerability_record(true, &[]);
    }

    pub(crate) fn seed_vulnerability_record(&self, withdrawn: bool, aliases: &[&str]) {
        self.seed_cache(
            "osv/query",
            QUERY_DIGEST,
            r#"[{"id":"RUSTSEC-TEST","modified":"2026-08-19T00:00:00Z"}]"#,
        );
        let withdrawn_field = if withdrawn {
            r#""withdrawn":"2026-08-19T00:00:00Z","#
        } else {
            ""
        };
        let aliases = serde_json::to_string(aliases).expect("serialize aliases");
        self.seed_cache(
            "osv/vuln",
            VULNERABILITY_DIGEST,
            &format!(
                r#"{{
                "id":"RUSTSEC-TEST",
                "modified":"2026-08-19T00:00:00Z",
                {withdrawn_field}
                "summary":"process-test vulnerability",
                "aliases":{aliases},
                "severity":[{{
                    "type":"CVSS_V3",
                    "score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }}],
                "affected":[{{
                    "package":{{"ecosystem":"crates.io","name":"demo"}},
                    "ranges":[{{
                        "type":"SEMVER",
                        "events":[{{"introduced":"0"}},{{"fixed":"1.1.0"}}]
                    }}]
                }}],
                "references":[]
            }}"#
            ),
        );
    }

    pub(crate) fn seed_osv_revision(&self, package_name: &str, advisory_id: &str) {
        let query_digest = sha256_hex(format!("crates.io:{package_name}:1.0.0").as_bytes());
        self.seed_cache(
            "osv/query",
            &query_digest,
            &format!(r#"[{{"id":"{advisory_id}","modified":"2026-08-19T00:00:00Z"}}]"#),
        );
    }

    pub(crate) fn seed_empty_osv_query(&self, package_name: &str) {
        let query_digest = sha256_hex(format!("crates.io:{package_name}:1.0.0").as_bytes());
        self.seed_cache("osv/query", &query_digest, "[]");
    }

    pub(crate) fn seed_osv_document(&self, advisory_id: &str, document: &str) {
        let hydration_digest = sha256_hex(format!("{advisory_id}@2026-08-19T00:00:00Z").as_bytes());
        self.seed_cache("osv/vuln", &hydration_digest, document);
    }

    pub(crate) fn seed_cache(&self, namespace: &str, digest: &str, value: &str) {
        let directory = self.cache.join(namespace);
        fs::create_dir_all(&directory).expect("create cache namespace");
        let entry = format!(
            r#"{{"stored_at":"{}","etag":null,"value":{value}}}"#,
            Utc::now().to_rfc3339()
        );
        fs::write(directory.join(format!("{digest}.json")), entry).expect("write cache fixture");
    }

    pub(crate) fn run(&self, arguments: &[&str]) -> Output {
        command(&self.cache)
            .args(arguments)
            .output()
            .expect("run depscan")
    }

    pub(crate) fn run_reproducible(&self, epoch: &str, arguments: &[&str]) -> Output {
        command(&self.cache)
            .env("SOURCE_DATE_EPOCH", epoch)
            .args(arguments)
            .output()
            .expect("run reproducible depscan")
    }
}
