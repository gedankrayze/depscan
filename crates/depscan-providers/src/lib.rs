//! Network providers, disk cache, and OSV offline-dump support.

mod osv_document;

use async_trait::async_trait;
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir as CapDir, OpenOptions as CapOpenOptions},
};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use cvss::Cvss;
use depscan_core::{
    Ecosystem, EnrichError, FileIdentity, LatestVersions, NuGetVersion, Package, ProviderError,
    RegistryEnrichment, Severity, VersionProvider, VulnMap, VulnProvider, VulnQueryOutcome,
    Vulnerability, classify_staleness, compare_versions, evaluate_osv_affected,
    latest_matching_version, normalize_name, osv_affected_identity_matches,
    pypi_version_is_prerelease, pypi_version_is_stable,
};
use directories::{BaseDirs, ProjectDirs};
use fs2::FileExt;
use futures::{StreamExt, stream};
use osv_document::{
    ValidatedOsvDocument, affected_entry_is_evaluable, valid_osv_id, validate_osv_document,
};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, PercentEncode, utf8_percent_encode};
use rand::RngExt;
use reqwest::{
    Client, StatusCode, Url,
    header::{ACCEPT, ETAG, HeaderMap, HeaderValue, IF_NONE_MATCH, RETRY_AFTER},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration as StdDuration, SystemTime},
};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::{sync::Semaphore, time::sleep};
use tracing::{debug, warn};
use zip::ZipArchive;

const USER_AGENT_VALUE: &str = concat!(
    "depscan/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/gedankrayze/depscan)"
);
const OSV_QUERY_TTL_SECS: i64 = 60 * 60;
const OSV_MAX_QUERY_PAGES: usize = 1_000;
// Wall-clock bound for one OSV batch query across all of its pagination round-trips. The page
// cap alone would let a slow or adversarial server hold a scan for hours at ten seconds per
// page; five minutes comfortably covers real pagination while keeping the wait interruptible.
const OSV_QUERY_BATCH_DEADLINE: StdDuration = StdDuration::from_secs(5 * 60);
const REGISTRY_TTL_SECS: i64 = 6 * 60 * 60;
const CACHE_COMMIT_ATTEMPTS: usize = 3;
const NPM_REGISTRY_BASE_URL: &str = "https://registry.npmjs.org";
const PYPI_REGISTRY_BASE_URL: &str = "https://pypi.org/pypi";
const NUGET_REGISTRY_BASE_URL: &str = "https://api.nuget.org/v3-flatcontainer";
const NUGET_REGISTRATION_BASE_URL: &str = "https://api.nuget.org/v3/registration5-gz-semver2";
const NUGET_REGISTRATION_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const CRATES_IO_INDEX_BASE_URL: &str = "https://index.crates.io";
const CRATES_IO_MAX_NAME_LEN: usize = 64;
const CRATES_IO_MAX_INDEX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const CRATES_IO_MAX_INDEX_LINE_BYTES: usize = 1024 * 1024;
const CRATES_IO_INDEX_CACHE_SCHEMA_VERSION: u32 = 1;
const CACHE_SENTINEL_FILE: &str = ".depscan-cache.json";
const CACHE_SENTINEL_SCHEMA_VERSION: u32 = 1;
const CACHE_SENTINEL_OWNER: &str = "depscan";
const CACHE_CONTENT_DIRECTORIES: [&str; 3] = ["offline", "osv", "registry"];
const HTTP_REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(10);
const HTTP_MAX_RETRIES: usize = 3;
const HTTP_ATTEMPTS: usize = HTTP_MAX_RETRIES + 1;
const HTTP_BACKOFF_BASE: StdDuration = StdDuration::from_millis(200);
const HTTP_MAX_RETRY_DELAY: StdDuration = StdDuration::from_secs(30);
const OSV_DUMP_BASE_URL: &str = "https://storage.googleapis.com/osv-vulnerabilities";
const OSV_DUMP_TRANSFER_TIMEOUT: StdDuration = StdDuration::from_secs(15 * 60);
const OSV_DUMP_MAX_DOWNLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const OSV_DUMP_MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
const OSV_DUMP_MAX_UNCOMPRESSED_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const OSV_DUMP_MAX_ENTRIES: usize = 2_000_000;
const OSV_DUMP_ATTEMPTS: usize = HTTP_ATTEMPTS;
const OSV_DUMP_BACKOFF_BASE: StdDuration = StdDuration::from_millis(200);
const OSV_DUMP_MAX_RETRY_DELAY: StdDuration = StdDuration::from_secs(30);
const OSV_DUMP_PROGRESS_INTERVAL_BYTES: u64 = 16 * 1024 * 1024;
const OSV_DUMP_TEMP_SUFFIXES: [&str; 3] = [".zip.tmp", ".synced-at.tmp", ".zip.rollback.tmp"];
const OSV_DUMP_DEFAULT_WARNING_AGE_SECS: i64 = 7 * 24 * 60 * 60;
const RFC3986_PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

mod osv;
pub use osv::*;
mod registry;
pub use registry::*;

mod cache;
pub use cache::*;

mod http;
pub use http::*;

#[cfg(test)]
mod tests;
