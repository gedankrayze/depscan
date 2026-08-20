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
    latest_matching_version, normalize_name, pypi_version_is_prerelease, pypi_version_is_stable,
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

fn encode_path_segment(segment: &str) -> PercentEncode<'_> {
    utf8_percent_encode(segment, RFC3986_PATH_SEGMENT_ENCODE_SET)
}

fn osv_query_name(package: &Package) -> &str {
    match package.ecosystem {
        Ecosystem::NuGet => &package.display_name,
        _ => &package.name,
    }
}

fn osv_query_cache_key(package: &Package) -> String {
    format!(
        "{}:{}:{}",
        package.ecosystem.osv_name(),
        osv_query_name(package),
        package.version
    )
}

fn osv_query_body_with_tokens(queries: &[(&Package, Option<&str>)]) -> Value {
    json!({
        "queries": queries
            .iter()
            .map(|(package, page_token)| {
                let mut query = json!({
                    "package": {
                        "name": osv_query_name(package),
                        "ecosystem": package.ecosystem.osv_name()
                    },
                    "version": package.version
                });
                if let Some(page_token) = page_token {
                    query
                        .as_object_mut()
                        .expect("OSV query is an object")
                        .insert("page_token".to_owned(), json!(page_token));
                }
                query
            })
            .collect::<Vec<_>>()
    })
}

#[cfg(test)]
fn osv_query_body(packages: &[Package]) -> Value {
    let queries = packages
        .iter()
        .map(|package| (package, None))
        .collect::<Vec<_>>();
    osv_query_body_with_tokens(&queries)
}

fn invalid_osv_batch_response(message: impl Into<String>) -> ProviderError {
    ProviderError::InvalidResponse(format!(
        "OSV querybatch response is invalid: {}",
        message.into()
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OsvVulnerabilityRevision {
    id: String,
    modified: DateTime<Utc>,
}

impl OsvVulnerabilityRevision {
    fn cache_key(&self) -> String {
        format!(
            "{}@{}",
            self.id,
            self.modified.to_rfc3339_opts(SecondsFormat::AutoSi, true)
        )
    }
}

fn canonical_osv_revisions(value: Value) -> Option<Vec<OsvVulnerabilityRevision>> {
    let parsed = serde_json::from_value::<Vec<OsvVulnerabilityRevision>>(value).ok()?;
    let mut revisions = BTreeMap::<String, DateTime<Utc>>::new();
    for revision in parsed {
        if !valid_osv_id(&revision.id) {
            return None;
        }
        revisions
            .entry(revision.id)
            .and_modify(|modified| *modified = std::cmp::max(*modified, revision.modified))
            .or_insert(revision.modified);
    }
    Some(
        revisions
            .into_iter()
            .map(|(id, modified)| OsvVulnerabilityRevision { id, modified })
            .collect(),
    )
}

fn parse_osv_modified(
    value: &Value,
    context: impl std::fmt::Display,
) -> Result<DateTime<Utc>, ProviderError> {
    let raw = value.as_str().ok_or_else(|| {
        invalid_osv_batch_response(format!("{context} has no string modified timestamp"))
    })?;
    DateTime::parse_from_rfc3339(raw)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| {
            invalid_osv_batch_response(format!("{context} has an invalid modified timestamp"))
        })
}

#[derive(Debug, PartialEq, Eq)]
struct OsvQueryBatchPage {
    revisions: Vec<OsvVulnerabilityRevision>,
    next_page_token: Option<String>,
}

fn parse_osv_query_batch_response(
    response: &Value,
    expected_results: usize,
) -> Result<Vec<Result<OsvQueryBatchPage, ProviderError>>, ProviderError> {
    let object = response
        .as_object()
        .ok_or_else(|| invalid_osv_batch_response("the top-level value is not an object"))?;
    let results = object
        .get("results")
        .ok_or_else(|| invalid_osv_batch_response("the required results field is missing"))?
        .as_array()
        .ok_or_else(|| invalid_osv_batch_response("the results field is not an array"))?;

    if results.len() != expected_results {
        return Err(invalid_osv_batch_response(format!(
            "returned {} results for {expected_results} queries",
            results.len()
        )));
    }

    Ok(results
        .iter()
        .enumerate()
        .map(|(result_index, result)| {
            let result = result.as_object().ok_or_else(|| {
                invalid_osv_batch_response(format!("result {result_index} is not an object"))
            })?;
            let next_page_token = result
                .get("next_page_token")
                .map(|token| {
                    let token = token.as_str().ok_or_else(|| {
                        invalid_osv_batch_response(format!(
                            "result {result_index} has a non-string next_page_token field"
                        ))
                    })?;
                    if token.is_empty() {
                        return Err(invalid_osv_batch_response(format!(
                            "result {result_index} has an empty next_page_token field"
                        )));
                    }
                    Ok(token.to_owned())
                })
                .transpose()?;
            let Some(vulns) = result.get("vulns") else {
                // OSV's protobuf JSON encoding represents a legitimate empty result as `{}`.
                return if result.is_empty() || (result.len() == 1 && next_page_token.is_some()) {
                    Ok(OsvQueryBatchPage {
                        revisions: Vec::new(),
                        next_page_token,
                    })
                } else {
                    Err(invalid_osv_batch_response(format!(
                        "result {result_index} is non-empty but has no vulns field"
                    )))
                };
            };
            let vulns = vulns.as_array().ok_or_else(|| {
                invalid_osv_batch_response(format!(
                    "result {result_index} has a non-array vulns field"
                ))
            })?;

            let revisions = vulns
                .iter()
                .enumerate()
                .map(|(vuln_index, vulnerability)| {
                    let vulnerability = vulnerability.as_object().ok_or_else(|| {
                        invalid_osv_batch_response(format!(
                            "result {result_index} vulnerability {vuln_index} is not an object"
                        ))
                    })?;
                    let id = vulnerability
                        .get("id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            invalid_osv_batch_response(format!(
                                "result {result_index} vulnerability {vuln_index} has no string id"
                            ))
                        })?;
                    if !valid_osv_id(id) {
                        return Err(invalid_osv_batch_response(format!(
                            "result {result_index} vulnerability {vuln_index} has an invalid id"
                        )));
                    }
                    let modified = parse_osv_modified(
                        vulnerability.get("modified").unwrap_or(&Value::Null),
                        format_args!("result {result_index} vulnerability {vuln_index}"),
                    )?;
                    Ok(OsvVulnerabilityRevision {
                        id: id.to_owned(),
                        modified,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(OsvQueryBatchPage {
                revisions,
                next_page_token,
            })
        })
        .collect())
}

fn nuget_registry_cache_key(package: &Package) -> String {
    format!("nuget:{}", package.name)
}

#[cfg(test)]
fn nuget_registry_url(package: &Package) -> String {
    nuget_registry_url_with_base(NUGET_REGISTRY_BASE_URL, package)
}

fn nuget_registry_url_with_base(base_url: &str, package: &Package) -> String {
    format!(
        "{}/{}/index.json",
        base_url,
        encode_path_segment(&package.name)
    )
}

fn nuget_registration_cache_key(package: &Package) -> String {
    format!("nuget-registration:{}", package.name)
}

fn nuget_registration_url_with_base(base_url: &str, package: &Package) -> String {
    format!(
        "{}/{}/index.json",
        base_url,
        encode_path_segment(&package.name)
    )
}

fn nuget_registration_page_cache_key(package: &Package, lower: &str, upper: &str) -> String {
    format!("nuget-registration-page:{}:{lower}:{upper}", package.name)
}

#[derive(Debug)]
enum NugetRegistrationPageSource {
    Inline(Value),
    Linked {
        lower: String,
        upper: String,
        url: String,
    },
}

fn invalid_nuget_registration(reason: impl std::fmt::Display) -> ProviderError {
    ProviderError::InvalidResponse(format!("NuGet registration metadata is invalid: {reason}"))
}

fn nuget_registration_page_for_version(
    document: &Value,
    target_raw: &str,
) -> Result<NugetRegistrationPageSource, ProviderError> {
    let target = NuGetVersion::parse(target_raw).map_err(invalid_nuget_registration)?;
    let root = document
        .as_object()
        .ok_or_else(|| invalid_nuget_registration("index root must be an object"))?;
    let pages = root
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_nuget_registration("index must contain a pages array"))?;
    let count = root
        .get("count")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_nuget_registration("index must contain an integer page count"))?;
    if usize::try_from(count).ok() != Some(pages.len()) {
        return Err(invalid_nuget_registration(format_args!(
            "index page count {count} does not match its {} pages",
            pages.len()
        )));
    }

    let mut selected = None;
    for (index, page) in pages.iter().enumerate() {
        let page = page.as_object().ok_or_else(|| {
            invalid_nuget_registration(format_args!("index page {index} must be an object"))
        })?;
        let lower_raw = page.get("lower").and_then(Value::as_str).ok_or_else(|| {
            invalid_nuget_registration(format_args!("index page {index} has no lower bound"))
        })?;
        let upper_raw = page.get("upper").and_then(Value::as_str).ok_or_else(|| {
            invalid_nuget_registration(format_args!("index page {index} has no upper bound"))
        })?;
        let lower = NuGetVersion::parse(lower_raw).map_err(invalid_nuget_registration)?;
        let upper = NuGetVersion::parse(upper_raw).map_err(invalid_nuget_registration)?;
        if lower > upper {
            return Err(invalid_nuget_registration(format_args!(
                "index page {index} lower bound {lower_raw:?} exceeds {upper_raw:?}"
            )));
        }
        if target < lower || target > upper {
            continue;
        }
        if selected.is_some() {
            return Err(invalid_nuget_registration(format_args!(
                "more than one index page contains version {target_raw:?}"
            )));
        }
        selected = Some(match page.get("items") {
            Some(items) => {
                let items = items.as_array().ok_or_else(|| {
                    invalid_nuget_registration(format_args!(
                        "inline index page {index} items must be an array"
                    ))
                })?;
                let count = page.get("count").and_then(Value::as_u64).ok_or_else(|| {
                    invalid_nuget_registration(format_args!(
                        "inline index page {index} has no integer leaf count"
                    ))
                })?;
                if usize::try_from(count).ok() != Some(items.len()) {
                    return Err(invalid_nuget_registration(format_args!(
                        "inline index page {index} leaf count {count} does not match its {} leaves",
                        items.len()
                    )));
                }
                NugetRegistrationPageSource::Inline(Value::Object(page.clone()))
            }
            None => {
                let url = page.get("@id").and_then(Value::as_str).ok_or_else(|| {
                    invalid_nuget_registration(format_args!(
                        "non-inline index page {index} has no @id"
                    ))
                })?;
                NugetRegistrationPageSource::Linked {
                    lower: lower_raw.to_owned(),
                    upper: upper_raw.to_owned(),
                    url: url.to_owned(),
                }
            }
        });
    }
    selected.ok_or_else(|| {
        invalid_nuget_registration(format_args!(
            "no index page contains version {target_raw:?}"
        ))
    })
}

fn validated_nuget_registration_page_url(
    base_url: &str,
    package: &Package,
    raw_url: &str,
) -> Result<String, ProviderError> {
    let base = Url::parse(base_url).map_err(|error| {
        invalid_nuget_registration(format_args!("registration base URL is invalid: {error}"))
    })?;
    let mut page = Url::parse(raw_url).map_err(|error| {
        invalid_nuget_registration(format_args!("registration page URL is invalid: {error}"))
    })?;
    if page.origin() != base.origin() || !page.username().is_empty() || page.password().is_some() {
        return Err(invalid_nuget_registration(
            "registration page URL must use the registration base origin without credentials",
        ));
    }
    let package_prefix = format!(
        "{}/{}/",
        base.path().trim_end_matches('/'),
        encode_path_segment(&package.name)
    );
    if !page.path().starts_with(&package_prefix) {
        return Err(invalid_nuget_registration(format_args!(
            "registration page URL path must start with {package_prefix:?}"
        )));
    }
    page.set_fragment(None);
    Ok(page.into())
}

fn canonical_nuget_name_from_registration_page(
    package: &Package,
    target_raw: &str,
    page: &Value,
) -> Result<String, ProviderError> {
    let target = NuGetVersion::parse(target_raw).map_err(invalid_nuget_registration)?;
    let page = page
        .as_object()
        .ok_or_else(|| invalid_nuget_registration("page root must be an object"))?;
    let leaves = page
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_nuget_registration("page must contain a leaves array"))?;
    let count = page
        .get("count")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_nuget_registration("page must contain an integer leaf count"))?;
    if usize::try_from(count).ok() != Some(leaves.len()) {
        return Err(invalid_nuget_registration(format_args!(
            "page leaf count {count} does not match its {} leaves",
            leaves.len()
        )));
    }

    let mut canonical = None;
    for (index, leaf) in leaves.iter().enumerate() {
        let catalog = leaf
            .get("catalogEntry")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                invalid_nuget_registration(format_args!(
                    "registration leaf {index} has no catalogEntry object"
                ))
            })?;
        let version_raw = catalog
            .get("version")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                invalid_nuget_registration(format_args!(
                    "registration leaf {index} has no catalogEntry.version"
                ))
            })?;
        let version = NuGetVersion::parse(version_raw).map_err(invalid_nuget_registration)?;
        if version != target {
            continue;
        }
        if canonical.is_some() {
            return Err(invalid_nuget_registration(format_args!(
                "more than one registration leaf matches version {target_raw:?}"
            )));
        }
        let id = catalog.get("id").and_then(Value::as_str).ok_or_else(|| {
            invalid_nuget_registration(format_args!(
                "registration leaf {index} has no catalogEntry.id"
            ))
        })?;
        if normalize_name(Ecosystem::NuGet, id) != package.name {
            return Err(invalid_nuget_registration(format_args!(
                "catalogEntry.id {id:?} does not match requested package {:?}",
                package.name
            )));
        }
        canonical = Some(id.to_owned());
    }
    canonical.ok_or_else(|| {
        invalid_nuget_registration(format_args!(
            "no registration leaf matches version {target_raw:?}"
        ))
    })
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheSentinel {
    schema_version: u32,
    owner: String,
}

fn expected_cache_sentinel() -> CacheSentinel {
    CacheSentinel {
        schema_version: CACHE_SENTINEL_SCHEMA_VERSION,
        owner: CACHE_SENTINEL_OWNER.to_owned(),
    }
}

fn cache_path_error(root: &Path, message: impl std::fmt::Display) -> ProviderError {
    ProviderError::Cache(format!("refusing cache path {}: {message}", root.display()))
}

fn validate_cache_scope_with(
    root: &Path,
    current_directory: &Path,
    home_directory: Option<&Path>,
) -> Result<(), ProviderError> {
    if !root.is_absolute() {
        return Err(cache_path_error(root, "resolved path is not absolute"));
    }
    if root.parent().is_none() {
        return Err(cache_path_error(
            root,
            "filesystem roots are not cache directories",
        ));
    }
    if current_directory.starts_with(root) {
        return Err(cache_path_error(
            root,
            "path is the current workspace or one of its ancestors",
        ));
    }
    if home_directory.is_some_and(|home| home.starts_with(root)) {
        return Err(cache_path_error(
            root,
            "path is the home directory or one of its ancestors",
        ));
    }
    if [".git", ".hg", ".svn"]
        .iter()
        .any(|marker| root.join(marker).exists())
    {
        return Err(cache_path_error(
            root,
            "path is a version-control workspace",
        ));
    }
    Ok(())
}

fn validate_cache_scope(root: &Path) -> Result<(), ProviderError> {
    let current_directory = std::env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(|error| cache_path_error(root, format_args!("cannot resolve cwd: {error}")))?;
    let home_directory = BaseDirs::new().and_then(|dirs| {
        fs::canonicalize(dirs.home_dir())
            .ok()
            .or_else(|| Some(dirs.home_dir().to_path_buf()))
    });
    validate_cache_scope_with(root, &current_directory, home_directory.as_deref())
}

fn validate_cache_sentinel(root: &Path) -> Result<(), ProviderError> {
    let sentinel_path = root.join(CACHE_SENTINEL_FILE);
    let metadata = fs::symlink_metadata(&sentinel_path).map_err(|error| {
        cache_path_error(
            root,
            format_args!("missing ownership sentinel {CACHE_SENTINEL_FILE}: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(cache_path_error(
            root,
            format_args!("ownership sentinel {CACHE_SENTINEL_FILE} is not a regular file"),
        ));
    }
    if metadata.len() > 1024 {
        return Err(cache_path_error(
            root,
            format_args!("ownership sentinel {CACHE_SENTINEL_FILE} is oversized"),
        ));
    }
    let bytes = fs::read(&sentinel_path).map_err(|error| {
        cache_path_error(
            root,
            format_args!("cannot read ownership sentinel: {error}"),
        )
    })?;
    let sentinel = serde_json::from_slice::<CacheSentinel>(&bytes).map_err(|error| {
        cache_path_error(root, format_args!("invalid ownership sentinel: {error}"))
    })?;
    if sentinel != expected_cache_sentinel() {
        return Err(cache_path_error(
            root,
            "ownership sentinel has an unsupported owner or schema version",
        ));
    }
    Ok(())
}

fn write_cache_sentinel(root: &Path) -> Result<(), ProviderError> {
    let sentinel_path = root.join(CACHE_SENTINEL_FILE);
    let bytes = serde_json::to_vec(&expected_cache_sentinel())
        .map_err(|error| ProviderError::Cache(error.to_string()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&sentinel_path)
        .map_err(|error| cache_path_error(root, format_args!("cannot create sentinel: {error}")))?;
    std::io::Write::write_all(&mut file, &bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| cache_path_error(root, format_args!("cannot persist sentinel: {error}")))
}

fn legacy_cache_layout_is_owned(root: &Path) -> Result<bool, ProviderError> {
    let mut entries = fs::read_dir(root).map_err(|error| {
        cache_path_error(root, format_args!("cannot inspect legacy cache: {error}"))
    })?;
    let mut found_entry = false;
    for entry in &mut entries {
        let entry = entry.map_err(|error| {
            cache_path_error(root, format_args!("cannot inspect legacy cache: {error}"))
        })?;
        found_entry = true;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Ok(false);
        };
        if !CACHE_CONTENT_DIRECTORIES.contains(&name) {
            return Ok(false);
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            cache_path_error(root, format_args!("cannot inspect legacy cache: {error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Ok(false);
        }
    }
    Ok(found_entry)
}

fn initialize_cache_root(
    requested: &Path,
    allow_legacy_migration: bool,
) -> Result<PathBuf, ProviderError> {
    if requested.as_os_str().is_empty() {
        return Err(ProviderError::Cache(
            "refusing an empty cache directory path".to_owned(),
        ));
    }
    let absolute = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| ProviderError::Cache(error.to_string()))?
            .join(requested)
    };
    match fs::symlink_metadata(&absolute) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(cache_path_error(&absolute, "directory is a symbolic link"));
            }
            if !metadata.is_dir() {
                return Err(cache_path_error(&absolute, "path is not a directory"));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(&absolute).map_err(|error| {
                cache_path_error(&absolute, format_args!("cannot create directory: {error}"))
            })?;
        }
        Err(error) => {
            return Err(cache_path_error(
                &absolute,
                format_args!("cannot inspect directory: {error}"),
            ));
        }
    }
    let metadata = fs::symlink_metadata(&absolute).map_err(|error| {
        cache_path_error(&absolute, format_args!("cannot inspect directory: {error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(cache_path_error(
            &absolute,
            "created path is not a real directory",
        ));
    }
    let root = fs::canonicalize(&absolute).map_err(|error| {
        cache_path_error(&absolute, format_args!("cannot resolve directory: {error}"))
    })?;
    validate_cache_scope(&root)?;

    let sentinel_path = root.join(CACHE_SENTINEL_FILE);
    match fs::symlink_metadata(&sentinel_path) {
        Ok(_) => validate_cache_sentinel(&root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut entries = fs::read_dir(&root).map_err(|error| {
                cache_path_error(&root, format_args!("cannot inspect directory: {error}"))
            })?;
            let has_entries = entries
                .next()
                .transpose()
                .map_err(|error| {
                    cache_path_error(&root, format_args!("cannot inspect directory: {error}"))
                })?
                .is_some();
            if has_entries && !(allow_legacy_migration && legacy_cache_layout_is_owned(&root)?) {
                return Err(cache_path_error(
                    &root,
                    "directory is non-empty and has no depscan ownership sentinel",
                ));
            }
            write_cache_sentinel(&root)?;
            validate_cache_sentinel(&root)?;
        }
        Err(error) => {
            return Err(cache_path_error(
                &root,
                format_args!("cannot inspect ownership sentinel: {error}"),
            ));
        }
    }
    Ok(root)
}

fn validate_owned_cache_root(root: &Path) -> Result<(), ProviderError> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        cache_path_error(root, format_args!("cannot inspect directory: {error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(cache_path_error(
            root,
            "directory was replaced or is not real",
        ));
    }
    let canonical = fs::canonicalize(root).map_err(|error| {
        cache_path_error(root, format_args!("cannot resolve directory: {error}"))
    })?;
    if canonical != root {
        return Err(cache_path_error(
            root,
            format_args!("directory now resolves to {}", canonical.display()),
        ));
    }
    validate_cache_scope(root)?;
    validate_cache_sentinel(root)
}

#[derive(Debug, Clone, Copy)]
pub struct CachePolicy {
    pub read: bool,
    pub max_age: Option<Duration>,
}
impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            read: true,
            max_age: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    stored_at: DateTime<Utc>,
    etag: Option<String>,
    value: Value,
}

#[derive(Debug, Clone)]
struct CacheLookup {
    etag: Option<String>,
    value: Value,
    fresh: bool,
}

enum CacheCommit {
    Written,
    Conflict(Option<CacheLookup>),
}

fn add_if_none_match(headers: &mut HeaderMap, cached: Option<&CacheLookup>) -> bool {
    let Some(etag) = cached.and_then(|entry| entry.etag.as_deref()) else {
        return false;
    };
    match HeaderValue::from_str(etag) {
        Ok(value) => {
            headers.insert(IF_NONE_MATCH, value);
            true
        }
        Err(error) => {
            debug!(%error, "ignoring invalid cached ETag");
            false
        }
    }
}

#[derive(Debug, Clone)]
pub struct Cache {
    root: PathBuf,
    policy: CachePolicy,
}
impl Cache {
    pub fn new(policy: CachePolicy) -> Result<Self, ProviderError> {
        if let Some(requested) = std::env::var_os("DEPSCAN_CACHE_DIR") {
            return Self::from_root(requested.into(), policy);
        }
        let requested = ProjectDirs::from("dev", "depscan", "depscan")
            .map(|dirs| dirs.cache_dir().to_path_buf())
            .ok_or_else(|| {
                ProviderError::Cache("could not determine cache directory".to_owned())
            })?;
        let root = initialize_cache_root(&requested, true)?;
        Ok(Self { root, policy })
    }
    fn from_root(requested: PathBuf, policy: CachePolicy) -> Result<Self, ProviderError> {
        let root = initialize_cache_root(&requested, false)?;
        Ok(Self { root, policy })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    fn filename(&self, namespace: &str, key: &str) -> PathBuf {
        let digest = Sha256::digest(key.as_bytes());
        let mut encoded = String::with_capacity(digest.len() * 2);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in digest {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        self.root.join(namespace).join(format!("{encoded}.json"))
    }
    pub fn get(
        &self,
        namespace: &str,
        key: &str,
        ttl: Duration,
    ) -> Option<(Value, Option<String>)> {
        self.lookup(namespace, key, ttl)
            .filter(|entry| entry.fresh)
            .map(|entry| (entry.value, entry.etag))
    }
    fn lookup(&self, namespace: &str, key: &str, ttl: Duration) -> Option<CacheLookup> {
        if !self.policy.read {
            return None;
        }
        self.snapshot(namespace, key, ttl)
    }
    fn snapshot(&self, namespace: &str, key: &str, ttl: Duration) -> Option<CacheLookup> {
        let path = self.filename(namespace, key);
        let entry = Self::read_entry(&path)?;
        Some(self.lookup_from_entry(entry, ttl))
    }
    fn read_entry(path: &Path) -> Option<CacheEntry> {
        let text = fs::read_to_string(path).ok()?;
        serde_json::from_str(&text).ok()
    }
    fn lookup_from_entry(&self, entry: CacheEntry, ttl: Duration) -> CacheLookup {
        self.lookup_from_entry_at(entry, ttl, Utc::now())
    }
    fn lookup_from_entry_at(
        &self,
        entry: CacheEntry,
        ttl: Duration,
        now: DateTime<Utc>,
    ) -> CacheLookup {
        let limit = self
            .policy
            .max_age
            .map_or(ttl, |max| std::cmp::min(ttl, max));
        CacheLookup {
            etag: entry.etag,
            value: entry.value,
            fresh: entry.stored_at <= now && now - entry.stored_at <= limit,
        }
    }
    fn lock_for(&self, path: &Path) -> Result<File, ProviderError> {
        let parent = path.parent().expect("cache filename has parent");
        fs::create_dir_all(parent).map_err(|e| ProviderError::Cache(e.to_string()))?;
        let lock =
            File::create(parent.join(".lock")).map_err(|e| ProviderError::Cache(e.to_string()))?;
        lock.lock_exclusive()
            .map_err(|e| ProviderError::Cache(e.to_string()))?;
        Ok(lock)
    }
    fn write_entry(path: &Path, value: &Value, etag: Option<String>) -> Result<(), ProviderError> {
        let entry = CacheEntry {
            stored_at: Utc::now(),
            etag,
            value: value.clone(),
        };
        let tmp = path.with_extension("json.tmp");
        fs::write(
            &tmp,
            serde_json::to_vec(&entry).map_err(|e| ProviderError::Cache(e.to_string()))?,
        )
        .map_err(|e| ProviderError::Cache(e.to_string()))?;
        fs::rename(tmp, path).map_err(|e| ProviderError::Cache(e.to_string()))
    }
    pub fn put(
        &self,
        namespace: &str,
        key: &str,
        value: &Value,
        etag: Option<String>,
    ) -> Result<(), ProviderError> {
        let path = self.filename(namespace, key);
        let lock = self.lock_for(&path)?;
        Self::write_entry(&path, value, etag)?;
        let _ = fs2::FileExt::unlock(&lock);
        Ok(())
    }
    fn put_if_unchanged(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&CacheLookup>,
        value: &Value,
        etag: Option<String>,
        ttl: Duration,
    ) -> Result<CacheCommit, ProviderError> {
        let path = self.filename(namespace, key);
        let lock = self.lock_for(&path)?;
        let current = Self::read_entry(&path);
        let unchanged = match (&current, expected) {
            (None, None) => true,
            (Some(current), Some(expected)) => {
                current.etag == expected.etag && current.value == expected.value
            }
            _ => false,
        };
        if !unchanged {
            let conflict = current.map(|entry| self.lookup_from_entry(entry, ttl));
            let _ = fs2::FileExt::unlock(&lock);
            return Ok(CacheCommit::Conflict(conflict));
        }
        Self::write_entry(&path, value, etag)?;
        let _ = fs2::FileExt::unlock(&lock);
        Ok(CacheCommit::Written)
    }
    pub fn clear(&self) -> Result<(), ProviderError> {
        validate_owned_cache_root(&self.root)?;
        let mut targets = Vec::new();
        for name in CACHE_CONTENT_DIRECTORIES {
            let target = self.root.join(name);
            let metadata = match fs::symlink_metadata(&target) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(cache_path_error(
                        &self.root,
                        format_args!("cannot inspect cache content {name:?}: {error}"),
                    ));
                }
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(cache_path_error(
                    &self.root,
                    format_args!("cache content {name:?} is not a real directory"),
                ));
            }
            let canonical = fs::canonicalize(&target).map_err(|error| {
                cache_path_error(
                    &self.root,
                    format_args!("cannot resolve cache content {name:?}: {error}"),
                )
            })?;
            if canonical.parent() != Some(self.root.as_path()) {
                return Err(cache_path_error(
                    &self.root,
                    format_args!("cache content {name:?} resolves outside the owned directory"),
                ));
            }
            targets.push(canonical);
        }
        validate_owned_cache_root(&self.root)?;
        for target in targets {
            fs::remove_dir_all(&target).map_err(|error| {
                cache_path_error(
                    &self.root,
                    format_args!("cannot remove {}: {error}", target.display()),
                )
            })?;
        }
        Ok(())
    }
    pub fn stats(&self) -> Result<CacheStats, ProviderError> {
        fn visit(path: &Path, stats: &mut CacheStats) -> std::io::Result<()> {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let meta = entry.metadata()?;
                if meta.is_dir() {
                    visit(&entry.path(), stats)?;
                } else {
                    stats.files += 1;
                    stats.bytes += meta.len();
                }
            }
            Ok(())
        }
        let mut stats = CacheStats::default();
        if self.root.exists() {
            visit(&self.root, &mut stats).map_err(|e| ProviderError::Cache(e.to_string()))?;
        }
        Ok(stats)
    }
}
#[derive(Debug, Default, Serialize)]
pub struct CacheStats {
    pub files: u64,
    pub bytes: u64,
}

#[derive(Debug)]
enum Revalidated<T> {
    Modified { value: T, etag: Option<String> },
    NotModified { etag: Option<String> },
}

struct PublishedHydration {
    value: Value,
    reusable: bool,
}

struct HydratedDocument {
    value: Value,
    cache_warning: Option<ProviderError>,
}

#[derive(Debug, Clone, Copy)]
struct RetrySettings {
    attempts: usize,
    backoff_base: StdDuration,
    max_delay: StdDuration,
}

impl Default for RetrySettings {
    fn default() -> Self {
        Self {
            attempts: HTTP_ATTEMPTS,
            backoff_base: HTTP_BACKOFF_BASE,
            max_delay: HTTP_MAX_RETRY_DELAY,
        }
    }
}

#[async_trait]
trait RetryRuntime: Send + Sync {
    fn now(&self) -> SystemTime;
    fn jitter(&self, upper_bound: StdDuration) -> StdDuration;
    async fn sleep(&self, duration: StdDuration);
}

struct SystemRetryRuntime;

#[async_trait]
impl RetryRuntime for SystemRetryRuntime {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn jitter(&self, upper_bound: StdDuration) -> StdDuration {
        let upper_millis = u64::try_from(upper_bound.as_millis()).unwrap_or(u64::MAX);
        StdDuration::from_millis(rand::rng().random_range(0..=upper_millis))
    }

    async fn sleep(&self, duration: StdDuration) {
        sleep(duration).await;
    }
}

fn retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn retryable_transport(error: &reqwest::Error) -> bool {
    error.is_connect() || error.is_timeout()
}

fn request_context(method: &reqwest::Method, url: &str) -> String {
    let Ok(mut sanitized) = reqwest::Url::parse(url) else {
        return format!("{method} <invalid URL>");
    };
    let _ = sanitized.set_username("");
    let _ = sanitized.set_password(None);
    sanitized.set_query(None);
    sanitized.set_fragment(None);
    format!("{method} {sanitized}")
}

fn network_attempt_error(
    context: &str,
    detail: &str,
    attempt: usize,
    attempts: usize,
) -> ProviderError {
    ProviderError::Network(format!(
        "{context}: {detail} (attempt {attempt}/{attempts})"
    ))
}

fn transport_attempt_error(
    context: &str,
    error: &reqwest::Error,
    attempt: usize,
    attempts: usize,
) -> ProviderError {
    let detail = if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_builder() {
        "request could not be built"
    } else {
        "request failed"
    };
    network_attempt_error(context, detail, attempt, attempts)
}

fn retry_after_delay(
    headers: &HeaderMap,
    now: SystemTime,
    cap: StdDuration,
) -> Option<StdDuration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    let delay = if let Ok(seconds) = value.parse::<u64>() {
        StdDuration::from_secs(seconds)
    } else {
        httpdate::parse_http_date(value)
            .ok()?
            .duration_since(now)
            .unwrap_or(StdDuration::ZERO)
    };
    Some(std::cmp::min(delay, cap))
}

fn retry_backoff(
    settings: RetrySettings,
    retry_index: usize,
    runtime: &dyn RetryRuntime,
) -> StdDuration {
    let multiplier = 1u32
        .checked_shl(retry_index.min(31) as u32)
        .unwrap_or(u32::MAX);
    let base = std::cmp::min(
        settings.backoff_base.saturating_mul(multiplier),
        settings.max_delay,
    );
    let jitter_bound_millis = u64::try_from(base.as_millis() / 4).unwrap_or(u64::MAX);
    let jitter_bound = std::cmp::min(
        StdDuration::from_millis(jitter_bound_millis),
        settings.max_delay.saturating_sub(base),
    );
    let jitter = std::cmp::min(runtime.jitter(jitter_bound), jitter_bound);
    base.saturating_add(jitter)
}

#[derive(Clone)]
pub struct HttpClient {
    inner: Client,
    request_timeout: StdDuration,
    retry_runtime: Arc<dyn RetryRuntime>,
    retry_settings: RetrySettings,
}
impl HttpClient {
    pub fn new() -> Result<Self, ProviderError> {
        Self::with_timeouts(HTTP_REQUEST_TIMEOUT, HTTP_REQUEST_TIMEOUT)
    }

    fn with_timeouts(
        request_timeout: StdDuration,
        network_idle_timeout: StdDuration,
    ) -> Result<Self, ProviderError> {
        Self::with_retry_runtime(
            request_timeout,
            network_idle_timeout,
            RetrySettings::default(),
            Arc::new(SystemRetryRuntime),
        )
    }

    fn with_retry_runtime(
        request_timeout: StdDuration,
        network_idle_timeout: StdDuration,
        retry_settings: RetrySettings,
        retry_runtime: Arc<dyn RetryRuntime>,
    ) -> Result<Self, ProviderError> {
        let client = Client::builder()
            .user_agent(USER_AGENT_VALUE)
            .connect_timeout(network_idle_timeout)
            .read_timeout(network_idle_timeout)
            .gzip(true)
            .http2_adaptive_window(true)
            .build()
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        Ok(Self {
            inner: client,
            request_timeout,
            retry_runtime,
            retry_settings,
        })
    }

    async fn wait_before_retry(
        &self,
        retry_after: Option<StdDuration>,
        retry_index: usize,
        settings: RetrySettings,
    ) {
        let delay = retry_after
            .unwrap_or_else(|| retry_backoff(settings, retry_index, self.retry_runtime.as_ref()));
        self.retry_runtime.sleep(delay).await;
    }

    async fn request_json(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<Value>,
        headers: HeaderMap,
    ) -> Result<Revalidated<Value>, ProviderError> {
        let settings = self.retry_settings;
        let context = request_context(&method, url);
        for attempt_index in 0..settings.attempts {
            let attempt = attempt_index + 1;
            let mut request = self
                .inner
                .request(method.clone(), url)
                .headers(headers.clone())
                .timeout(self.request_timeout);
            if let Some(body) = &body {
                request = request.json(body);
            }
            match request.send().await {
                Ok(response) if response.status() == StatusCode::NOT_MODIFIED => {
                    let etag = response
                        .headers()
                        .get(ETAG)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned);
                    return Ok(Revalidated::NotModified { etag });
                }
                Ok(response) if response.status().is_success() => {
                    let etag = response
                        .headers()
                        .get(ETAG)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    match response.json::<Value>().await {
                        Ok(value) => return Ok(Revalidated::Modified { value, etag }),
                        Err(error) if retryable_transport(&error) => {
                            let final_error = transport_attempt_error(
                                &context,
                                &error,
                                attempt,
                                settings.attempts,
                            );
                            if attempt == settings.attempts {
                                return Err(final_error);
                            }
                            self.wait_before_retry(None, attempt_index, settings).await;
                        }
                        Err(_) => {
                            return Err(ProviderError::InvalidResponse(format!(
                                "{context}: invalid JSON response"
                            )));
                        }
                    }
                }
                Ok(response) => {
                    let status = response.status();
                    let final_error = network_attempt_error(
                        &context,
                        &format!("HTTP {status}"),
                        attempt,
                        settings.attempts,
                    );
                    if !retryable_status(status) || attempt == settings.attempts {
                        return Err(final_error);
                    }
                    let retry_after = retry_after_delay(
                        response.headers(),
                        self.retry_runtime.now(),
                        settings.max_delay,
                    );
                    self.wait_before_retry(retry_after, attempt_index, settings)
                        .await;
                }
                Err(error) => {
                    let final_error =
                        transport_attempt_error(&context, &error, attempt, settings.attempts);
                    if !retryable_transport(&error) || attempt == settings.attempts {
                        return Err(final_error);
                    }
                    self.wait_before_retry(None, attempt_index, settings).await;
                }
            }
        }
        Err(ProviderError::Network(format!(
            "{context}: retry policy allowed no attempts"
        )))
    }
    pub async fn get_json(
        &self,
        url: &str,
        headers: HeaderMap,
    ) -> Result<(Value, Option<String>), ProviderError> {
        match self
            .request_json(reqwest::Method::GET, url, None, headers)
            .await?
        {
            Revalidated::Modified { value, etag } => Ok((value, etag)),
            Revalidated::NotModified { .. } => Err(ProviderError::InvalidResponse(format!(
                "{url}: received HTTP 304 without a conditional cache request"
            ))),
        }
    }
    async fn get_json_revalidated(
        &self,
        url: &str,
        headers: HeaderMap,
    ) -> Result<Revalidated<Value>, ProviderError> {
        self.request_json(reqwest::Method::GET, url, None, headers)
            .await
    }
    pub async fn post_json(&self, url: &str, body: Value) -> Result<Value, ProviderError> {
        match self
            .request_json(reqwest::Method::POST, url, Some(body), HeaderMap::new())
            .await?
        {
            Revalidated::Modified { value, .. } => Ok(value),
            Revalidated::NotModified { .. } => Err(ProviderError::InvalidResponse(format!(
                "{url}: received HTTP 304 for a POST request"
            ))),
        }
    }
    async fn get_bytes_limited_revalidated(
        &self,
        url: &str,
        max_bytes: usize,
        headers: HeaderMap,
    ) -> Result<Revalidated<Vec<u8>>, ProviderError> {
        let settings = self.retry_settings;
        let method = reqwest::Method::GET;
        let context = request_context(&method, url);
        'request: for attempt_index in 0..settings.attempts {
            let attempt = attempt_index + 1;
            let response = match self
                .inner
                .get(url)
                .headers(headers.clone())
                .timeout(self.request_timeout)
                .send()
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    let final_error =
                        transport_attempt_error(&context, &error, attempt, settings.attempts);
                    if !retryable_transport(&error) || attempt == settings.attempts {
                        return Err(final_error);
                    }
                    self.wait_before_retry(None, attempt_index, settings).await;
                    continue;
                }
            };
            let etag = response
                .headers()
                .get(ETAG)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            if response.status() == StatusCode::NOT_MODIFIED {
                return Ok(Revalidated::NotModified { etag });
            }
            let status = response.status();
            if !status.is_success() {
                let final_error = network_attempt_error(
                    &context,
                    &format!("HTTP {status}"),
                    attempt,
                    settings.attempts,
                );
                if !retryable_status(status) || attempt == settings.attempts {
                    return Err(final_error);
                }
                let retry_after = retry_after_delay(
                    response.headers(),
                    self.retry_runtime.now(),
                    settings.max_delay,
                );
                self.wait_before_retry(retry_after, attempt_index, settings)
                    .await;
                continue;
            }
            let mut response = response;
            let content_length = response.content_length();
            if content_length.is_some_and(|length| length > max_bytes as u64) {
                return Err(ProviderError::InvalidResponse(format!(
                    "{context}: response exceeds the {max_bytes}-byte limit"
                )));
            }

            let initial_capacity = content_length
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or_default()
                .min(max_bytes);
            let mut bytes = Vec::with_capacity(initial_capacity);
            loop {
                let chunk = match response.chunk().await {
                    Ok(chunk) => chunk,
                    Err(error) => {
                        let final_error =
                            transport_attempt_error(&context, &error, attempt, settings.attempts);
                        if !retryable_transport(&error) || attempt == settings.attempts {
                            return Err(final_error);
                        }
                        self.wait_before_retry(None, attempt_index, settings).await;
                        continue 'request;
                    }
                };
                let Some(chunk) = chunk else {
                    break;
                };
                let Some(new_len) = bytes.len().checked_add(chunk.len()) else {
                    return Err(ProviderError::InvalidResponse(format!(
                        "{context}: response size overflowed"
                    )));
                };
                if new_len > max_bytes {
                    return Err(ProviderError::InvalidResponse(format!(
                        "{context}: response exceeds the {max_bytes}-byte limit"
                    )));
                }
                bytes.extend_from_slice(&chunk);
            }
            return Ok(Revalidated::Modified { value: bytes, etag });
        }
        Err(ProviderError::Network(format!(
            "{context}: retry policy allowed no attempts"
        )))
    }

    async fn get_json_limited_revalidated(
        &self,
        url: &str,
        max_bytes: usize,
        headers: HeaderMap,
    ) -> Result<Revalidated<Value>, ProviderError> {
        match self
            .get_bytes_limited_revalidated(url, max_bytes, headers)
            .await?
        {
            Revalidated::Modified { value, etag } => {
                let value = serde_json::from_slice(&value).map_err(|_| {
                    ProviderError::InvalidResponse(format!("GET {url}: invalid JSON response"))
                })?;
                Ok(Revalidated::Modified { value, etag })
            }
            Revalidated::NotModified { etag } => Ok(Revalidated::NotModified { etag }),
        }
    }
}

#[derive(Clone)]
pub struct OsvClient {
    http: HttpClient,
    cache: Cache,
    concurrency: Arc<Semaphore>,
    base_url: String,
}
impl OsvClient {
    pub fn new(http: HttpClient, cache: Cache) -> Self {
        Self::with_base_url(http, cache, "https://api.osv.dev")
    }

    fn with_base_url(http: HttpClient, cache: Cache, base_url: impl Into<String>) -> Self {
        Self {
            http,
            cache,
            concurrency: Arc::new(Semaphore::new(16)),
            base_url: base_url.into().trim_end_matches('/').to_owned(),
        }
    }
    #[cfg(test)]
    async fn query_batch(
        &self,
        batch: &[Package],
    ) -> Result<Vec<Vec<OsvVulnerabilityRevision>>, ProviderError> {
        self.query_batch_outcomes(batch).await.into_iter().collect()
    }

    async fn query_batch_outcomes(
        &self,
        batch: &[Package],
    ) -> Vec<Result<Vec<OsvVulnerabilityRevision>, ProviderError>> {
        let url = format!("{}/v1/querybatch", self.base_url);
        let mut revisions = vec![BTreeMap::<String, DateTime<Utc>>::new(); batch.len()];
        let mut failures = vec![None::<ProviderError>; batch.len()];
        let mut seen_tokens = vec![BTreeSet::new(); batch.len()];
        let mut pages_seen = vec![0usize; batch.len()];
        let mut pending = (0..batch.len())
            .map(|index| (index, None::<String>))
            .collect::<Vec<_>>();

        while !pending.is_empty() {
            let queries = pending
                .iter()
                .map(|(index, page_token)| (&batch[*index], page_token.as_deref()))
                .collect::<Vec<_>>();
            let body = osv_query_body_with_tokens(&queries);
            let _permit = match self.concurrency.acquire().await {
                Ok(permit) => permit,
                Err(error) => {
                    let error = ProviderError::Network(error.to_string());
                    for (index, _) in &pending {
                        failures[*index] = Some(error.clone());
                    }
                    break;
                }
            };
            let response = match self.http.post_json(&url, body).await {
                Ok(response) => response,
                Err(error) => {
                    for (index, _) in &pending {
                        failures[*index] = Some(error.clone());
                    }
                    break;
                }
            };
            drop(_permit);
            let pages = match parse_osv_query_batch_response(&response, pending.len()) {
                Ok(pages) => pages,
                Err(error) => {
                    for (index, _) in &pending {
                        failures[*index] = Some(error.clone());
                    }
                    break;
                }
            };
            let mut next = Vec::new();
            for ((index, _), page) in pending.into_iter().zip(pages) {
                let page = match page {
                    Ok(page) => page,
                    Err(error) => {
                        failures[index] = Some(error);
                        continue;
                    }
                };
                pages_seen[index] += 1;
                for revision in page.revisions {
                    revisions[index]
                        .entry(revision.id)
                        .and_modify(|modified| {
                            *modified = std::cmp::max(*modified, revision.modified)
                        })
                        .or_insert(revision.modified);
                }
                if let Some(token) = page.next_page_token {
                    if !seen_tokens[index].insert(token.clone()) {
                        failures[index] = Some(invalid_osv_batch_response(format!(
                            "result for query {index} repeated a next_page_token"
                        )));
                        continue;
                    }
                    if pages_seen[index] >= OSV_MAX_QUERY_PAGES {
                        failures[index] = Some(invalid_osv_batch_response(format!(
                            "result for query {index} exceeded the {OSV_MAX_QUERY_PAGES}-page limit"
                        )));
                        continue;
                    }
                    next.push((index, Some(token)));
                }
            }
            pending = next;
        }

        revisions
            .into_iter()
            .zip(failures)
            .map(|(revisions, failure)| {
                failure.map_or_else(
                    || {
                        Ok(revisions
                            .into_iter()
                            .map(|(id, modified)| OsvVulnerabilityRevision { id, modified })
                            .collect())
                    },
                    Err,
                )
            })
            .collect()
    }
    fn publish_hydrated_document(
        &self,
        cache_key: &str,
        id: &str,
        value: &Value,
        etag: Option<String>,
        candidate_reusable: bool,
    ) -> Result<PublishedHydration, ProviderError> {
        let candidate_modified = validate_osv_document(value, Some(id))?.modified;
        let ttl = Duration::hours(24 * 3650);
        let mut generation = self.cache.snapshot("osv/vuln", cache_key, ttl);
        for _ in 0..CACHE_COMMIT_ATTEMPTS {
            if let Some(current) = &generation
                && let Ok(current_modified) = validate_osv_document(&current.value, Some(id))
                    .map(|document| document.modified)
                && current_modified >= candidate_modified
            {
                return Ok(PublishedHydration {
                    value: current.value.clone(),
                    reusable: self.cache.policy.read && current.fresh,
                });
            }
            match self.cache.put_if_unchanged(
                "osv/vuln",
                cache_key,
                generation.as_ref(),
                value,
                etag.clone(),
                ttl,
            )? {
                CacheCommit::Written => {
                    return Ok(PublishedHydration {
                        value: value.clone(),
                        reusable: candidate_reusable,
                    });
                }
                CacheCommit::Conflict(current) => generation = current,
            }
        }
        Err(ProviderError::Cache(format!(
            "OSV hydration cache entry for {id} changed repeatedly during publication"
        )))
    }
    async fn hydrate(
        &self,
        revision: &OsvVulnerabilityRevision,
    ) -> Result<HydratedDocument, ProviderError> {
        let cache_key = revision.cache_key();
        if let Some((value, _)) = self
            .cache
            .get("osv/vuln", &cache_key, Duration::hours(24 * 3650))
        {
            match validate_osv_document(&value, Some(&revision.id)) {
                Ok(document) if document.modified >= revision.modified => {
                    return Ok(HydratedDocument {
                        value,
                        cache_warning: None,
                    });
                }
                Ok(_) => debug!(
                    id = %revision.id,
                    "ignoring hydrated OSV cache entry older than its query revision"
                ),
                Err(error) => debug!(
                    id = %revision.id,
                    %error,
                    "ignoring invalid hydrated OSV cache entry"
                ),
            }
        }
        let _permit = self
            .concurrency
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let url = format!("{}/v1/vulns/{}", self.base_url, revision.id);
        let (value, etag) = self.http.get_json(&url, HeaderMap::new()).await?;
        let actual_modified = validate_osv_document(&value, Some(&revision.id))?.modified;
        if actual_modified < revision.modified {
            return Err(ProviderError::InvalidResponse(format!(
                "OSV hydration for {} is older than query revision {}",
                revision.id, revision.modified
            )));
        }
        let actual_revision = OsvVulnerabilityRevision {
            id: revision.id.clone(),
            modified: actual_modified,
        };
        let mut published = match self.publish_hydrated_document(
            &actual_revision.cache_key(),
            &revision.id,
            &value,
            etag,
            true,
        ) {
            Ok(published) => published,
            Err(error) => {
                return Ok(HydratedDocument {
                    value,
                    cache_warning: Some(error),
                });
            }
        };
        if actual_revision != *revision {
            published = match self.publish_hydrated_document(
                &cache_key,
                &revision.id,
                &published.value,
                None,
                published.reusable,
            ) {
                Ok(published) => published,
                Err(error) => {
                    let value = if self.cache.policy.read && published.reusable {
                        published.value
                    } else {
                        value
                    };
                    return Ok(HydratedDocument {
                        value,
                        cache_warning: Some(error),
                    });
                }
            };
        }
        let value = if self.cache.policy.read && published.reusable {
            published.value
        } else {
            value
        };
        Ok(HydratedDocument {
            value,
            cache_warning: None,
        })
    }
}

fn record_osv_failure(
    errors: &mut HashMap<String, Vec<EnrichError>>,
    first_failure: &mut Option<ProviderError>,
    package_key: &str,
    context: &str,
    error: ProviderError,
) {
    if first_failure.is_none() {
        *first_failure = Some(error.clone());
    }
    record_osv_warning(errors, package_key, context, error);
}

fn record_osv_warning(
    errors: &mut HashMap<String, Vec<EnrichError>>,
    package_key: &str,
    context: &str,
    error: ProviderError,
) {
    errors
        .entry(package_key.to_owned())
        .or_default()
        .push(EnrichError {
            provider: "osv".to_owned(),
            message: format!("{context}: {error}"),
        });
}

#[async_trait]
impl VulnProvider for OsvClient {
    async fn query(&self, packages: &[Package]) -> Result<VulnQueryOutcome, ProviderError> {
        let query_ttl = Duration::seconds(OSV_QUERY_TTL_SECS);
        let mut revisions_by_package = HashMap::<String, Vec<OsvVulnerabilityRevision>>::new();
        let mut errors = HashMap::<String, Vec<EnrichError>>::new();
        let mut first_failure = None;
        let mut missing = Vec::new();
        let eligible = packages
            .iter()
            .filter(|p| p.enrichable && !p.resolved_from_range)
            .collect::<Vec<_>>();
        let eligible_count = eligible.len();
        for package in eligible.iter().copied() {
            let query_cache_key = osv_query_cache_key(package);
            let generation = self
                .cache
                .snapshot("osv/query", &query_cache_key, query_ttl);
            if self.cache.policy.read
                && let Some(cached) = &generation
                && cached.fresh
            {
                if let Some(revisions) = canonical_osv_revisions(cached.value.clone()) {
                    revisions_by_package.insert(package.key(), revisions);
                } else {
                    debug!(
                        package = %package.display_name,
                        "ignoring legacy or invalid OSV query cache entry"
                    );
                    missing.push((package.clone(), generation, true));
                }
            } else {
                missing.push((package.clone(), generation, self.cache.policy.read));
            }
        }

        for _ in 0..CACHE_COMMIT_ATTEMPTS {
            if missing.is_empty() {
                break;
            }
            let mut conflicts = Vec::new();
            for chunk in missing.chunks(1000) {
                let batch = chunk
                    .iter()
                    .map(|(package, _, _)| package.clone())
                    .collect::<Vec<_>>();
                let lists = self.query_batch_outcomes(&batch).await;
                for ((package, generation, enforce_regression), outcome) in
                    chunk.iter().cloned().zip(lists)
                {
                    let revisions = match outcome {
                        Ok(revisions) => revisions,
                        Err(error) => {
                            record_osv_failure(
                                &mut errors,
                                &mut first_failure,
                                &package.key(),
                                "query failed",
                                error,
                            );
                            continue;
                        }
                    };
                    if let Some(previous) = enforce_regression
                        .then(|| {
                            generation
                                .as_ref()
                                .and_then(|entry| canonical_osv_revisions(entry.value.clone()))
                        })
                        .flatten()
                    {
                        let next = revisions
                            .iter()
                            .map(|revision| (revision.id.as_str(), revision.modified))
                            .collect::<HashMap<_, _>>();
                        if let Some(regressed) = previous.iter().find(|revision| {
                            next.get(revision.id.as_str())
                                .is_some_and(|modified| *modified < revision.modified)
                        }) {
                            let error = ProviderError::InvalidResponse(format!(
                                "OSV query revision for {} regressed below {}",
                                regressed.id, regressed.modified
                            ));
                            record_osv_failure(
                                &mut errors,
                                &mut first_failure,
                                &package.key(),
                                "query failed",
                                error,
                            );
                            continue;
                        }
                    }
                    let package_key = package.key();
                    revisions_by_package.insert(package_key.clone(), revisions.clone());
                    let value = match serde_json::to_value(&revisions) {
                        Ok(value) => value,
                        Err(error) => {
                            record_osv_warning(
                                &mut errors,
                                &package_key,
                                "query cache serialization failed",
                                ProviderError::Cache(error.to_string()),
                            );
                            continue;
                        }
                    };
                    match self.cache.put_if_unchanged(
                        "osv/query",
                        &osv_query_cache_key(&package),
                        generation.as_ref(),
                        &value,
                        None,
                        query_ttl,
                    ) {
                        Ok(CacheCommit::Written) => {
                            // The validated network result was already retained for this scan.
                        }
                        Ok(CacheCommit::Conflict(current)) => {
                            if self.cache.policy.read
                                && let Some(current) = &current
                                && current.fresh
                                && let Some(winner) = canonical_osv_revisions(current.value.clone())
                            {
                                revisions_by_package.insert(package_key, winner);
                            }
                            conflicts.push((package, current, true));
                        }
                        Err(error) => record_osv_warning(
                            &mut errors,
                            &package.key(),
                            "query cache publication failed",
                            error,
                        ),
                    }
                }
            }
            missing = conflicts;
        }
        if !missing.is_empty() {
            for (package, _, _) in missing {
                record_osv_warning(
                    &mut errors,
                    &package.key(),
                    "query cache publication failed",
                    ProviderError::Cache(
                        "OSV query cache changed repeatedly during refresh".to_owned(),
                    ),
                );
            }
        }

        // A provider error is hard only when no eligible package produced a complete query from
        // either a fresh cache entry or the network. Any completed query (including a legitimate
        // empty result) makes failures for other packages soft and visible in the outcome.
        if eligible_count > 0 && revisions_by_package.is_empty() {
            return Err(first_failure.unwrap_or_else(|| {
                ProviderError::InvalidResponse(
                    "OSV returned no usable result for any eligible package".to_owned(),
                )
            }));
        }

        let mut latest_revisions = BTreeMap::<String, OsvVulnerabilityRevision>::new();
        for revisions in revisions_by_package.values() {
            for revision in revisions {
                latest_revisions
                    .entry(revision.id.clone())
                    .and_modify(|current| {
                        if revision.modified > current.modified {
                            *current = revision.clone();
                        }
                    })
                    .or_insert_with(|| revision.clone());
            }
        }
        let hydrated = stream::iter(latest_revisions.into_values().map(|revision| {
            let client = self.clone();
            async move {
                let id = revision.id.clone();
                (id, client.hydrate(&revision).await)
            }
        }))
        .buffer_unordered(16)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<HashMap<_, _>>();

        let mut vulnerabilities = VulnMap::new();
        let mut usable_packages = 0usize;
        for package in eligible {
            let key = package.key();
            let Some(revisions) = revisions_by_package.get(&key) else {
                continue;
            };
            let mut evaluated = Vec::with_capacity(revisions.len());
            let mut successful_evaluations = 0usize;
            for revision in revisions {
                let Some(document) = hydrated.get(&revision.id) else {
                    record_osv_failure(
                        &mut errors,
                        &mut first_failure,
                        &key,
                        &format!("advisory {} hydration failed", revision.id),
                        ProviderError::InvalidResponse(format!(
                            "OSV advisory {} has no hydration outcome",
                            revision.id
                        )),
                    );
                    continue;
                };
                let document = match document {
                    Ok(document) => document,
                    Err(error) => {
                        record_osv_failure(
                            &mut errors,
                            &mut first_failure,
                            &key,
                            &format!("advisory {} hydration failed", revision.id),
                            error.clone(),
                        );
                        continue;
                    }
                };
                if let Some(error) = &document.cache_warning {
                    record_osv_warning(
                        &mut errors,
                        &key,
                        &format!("advisory {} cache publication failed", revision.id),
                        error.clone(),
                    );
                }
                match vulnerability_from_osv_query_hit(&document.value, package) {
                    Ok(Some(vulnerability)) => {
                        successful_evaluations += 1;
                        evaluated.push(vulnerability);
                    }
                    Ok(None) => successful_evaluations += 1,
                    Err(error) => record_osv_failure(
                        &mut errors,
                        &mut first_failure,
                        &key,
                        &format!("advisory {} evaluation failed", revision.id),
                        error,
                    ),
                }
            }
            if revisions.is_empty() || successful_evaluations > 0 {
                usable_packages += 1;
            }
            vulnerabilities.insert(key, evaluated);
        }

        // A package with only failed advisory hydrations/evaluations has no trustworthy
        // vulnerability result. If that is true for every completed query, the provider is wholly
        // unusable and must retain the hard-failure exit path.
        if eligible_count > 0 && usable_packages == 0 {
            return Err(first_failure.unwrap_or_else(|| {
                ProviderError::InvalidResponse(
                    "OSV returned no usable vulnerability result for any eligible package"
                        .to_owned(),
                )
            }));
        }
        Ok(VulnQueryOutcome {
            vulnerabilities,
            errors,
        })
    }
}

#[cfg(test)]
fn vulnerability_from_osv(
    doc: &Value,
    package: Option<&Package>,
) -> Result<Option<Vulnerability>, ProviderError> {
    vulnerability_from_osv_with_match_policy(doc, package, false)
}

fn vulnerability_from_osv_query_hit(
    doc: &Value,
    package: &Package,
) -> Result<Option<Vulnerability>, ProviderError> {
    vulnerability_from_osv_with_match_policy(doc, Some(package), true)
}

fn vulnerability_from_osv_with_match_policy(
    doc: &Value,
    package: Option<&Package>,
    require_matching_affected: bool,
) -> Result<Option<Vulnerability>, ProviderError> {
    let document = validate_osv_document(doc, None)?;
    vulnerability_from_validated_osv(doc, &document, package, require_matching_affected)
}

fn vulnerability_from_validated_osv(
    doc: &Value,
    document: &ValidatedOsvDocument<'_>,
    package: Option<&Package>,
    require_matching_affected: bool,
) -> Result<Option<Vulnerability>, ProviderError> {
    if let Some(package) = package {
        let mut matching = document
            .affected
            .iter()
            .filter(|affected| affected_matches_package(affected, package));
        let first = matching.next();
        let evaluable = first
            .into_iter()
            .chain(matching)
            .any(affected_entry_is_evaluable);
        if !evaluable && (require_matching_affected || first.is_some()) {
            let source = if require_matching_affected {
                "OSV query hit"
            } else {
                "OSV advisory"
            };
            return Err(ProviderError::InvalidResponse(format!(
                "{source} {} has no matching evaluable affected entry for {} {}",
                document.id, package.display_name, package.version
            )));
        }
    }
    let score = osv_cvss_score(doc, package);
    let evaluation = package
        .map(|package| {
            evaluate_osv_affected(package, document.affected).map_err(|error| {
                ProviderError::InvalidResponse(format!(
                    "OSV advisory {} cannot be evaluated for {} {}: {error}",
                    document.id, package.display_name, package.version
                ))
            })
        })
        .transpose()?;
    if evaluation.as_ref().is_some_and(|result| !result.affected) {
        return Ok(None);
    }
    let fixed_in = evaluation
        .map(|result| result.fixed_versions)
        .unwrap_or_default();
    Ok(Some(Vulnerability {
        id: document.id.to_owned(),
        aliases: doc
            .get("aliases")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        summary: doc
            .get("summary")
            .and_then(Value::as_str)
            .or_else(|| doc.get("details").and_then(Value::as_str))
            .unwrap_or("No summary supplied")
            .to_owned(),
        severity: score.map(Severity::from_cvss),
        cvss_score: score,
        fixed_in,
        references: doc
            .get("references")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.get("url").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        withdrawn: document.withdrawn,
    }))
}

#[derive(Clone, Copy)]
enum OsvCvssVersion {
    V3,
    V4,
}

impl OsvCvssVersion {
    fn osv_type(self) -> &'static str {
        match self {
            Self::V3 => "CVSS_V3",
            Self::V4 => "CVSS_V4",
        }
    }

    fn accepts(self, vector: &Cvss) -> bool {
        matches!(
            (self, vector),
            (Self::V3, Cvss::CvssV30(_) | Cvss::CvssV31(_)) | (Self::V4, Cvss::CvssV40(_))
        )
    }
}

/// OSV top-level severity takes precedence over affected-entry severity. Within either source,
/// prefer a valid CVSS v4 vector and then fall back to a valid CVSS v3 vector.
fn osv_cvss_score(doc: &Value, package: Option<&Package>) -> Option<f32> {
    doc.get("severity")
        .and_then(Value::as_array)
        .and_then(|severity| cvss_score_from_severity_lists(&[severity.as_slice()]))
        .or_else(|| matching_affected_cvss_score(doc, package?))
}

fn matching_affected_cvss_score(doc: &Value, package: &Package) -> Option<f32> {
    let severity_lists = doc
        .get("affected")
        .and_then(Value::as_array)?
        .iter()
        .filter(|affected| affected_matches_package(affected, package))
        .filter_map(|affected| affected.get("severity").and_then(Value::as_array))
        .map(Vec::as_slice)
        .collect::<Vec<_>>();

    cvss_score_from_severity_lists(&severity_lists)
}

fn affected_matches_package(affected: &Value, package: &Package) -> bool {
    let Some(affected_package) = affected.get("package") else {
        return false;
    };
    let Some(ecosystem) = affected_package.get("ecosystem").and_then(Value::as_str) else {
        return false;
    };
    let Some(name) = affected_package.get("name").and_then(Value::as_str) else {
        return false;
    };

    ecosystem == package.ecosystem.osv_name()
        && (name == "*" || normalize_name(package.ecosystem, name) == package.name)
}

fn cvss_score_from_severity_lists(severity_lists: &[&[Value]]) -> Option<f32> {
    [OsvCvssVersion::V4, OsvCvssVersion::V3]
        .into_iter()
        .find_map(|version| {
            severity_lists
                .iter()
                .flat_map(|severity| severity.iter())
                .filter(|entry| {
                    entry.get("type").and_then(Value::as_str) == Some(version.osv_type())
                })
                .filter_map(|entry| entry.get("score").and_then(Value::as_str))
                .filter_map(|vector| vector.parse::<Cvss>().ok())
                .filter(|vector| version.accepts(vector))
                .map(|vector| vector.score())
                .max_by(f64::total_cmp)
                .map(|score| score as f32)
        })
}

#[derive(Debug, Clone, Copy)]
struct OsvDumpLimits {
    max_compressed_bytes: u64,
    max_entry_bytes: u64,
    max_uncompressed_bytes: u64,
    max_entries: usize,
}

impl OsvDumpLimits {
    fn production() -> Self {
        Self {
            max_compressed_bytes: OSV_DUMP_MAX_DOWNLOAD_BYTES,
            max_entry_bytes: OSV_DUMP_MAX_ENTRY_BYTES,
            max_uncompressed_bytes: OSV_DUMP_MAX_UNCOMPRESSED_BYTES,
            max_entries: OSV_DUMP_MAX_ENTRIES,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum OsvDumpValidationContext<'a> {
    Sync(Ecosystem),
    Offline(&'a Path),
}

impl OsvDumpValidationContext<'_> {
    fn invalid(self, reason: impl std::fmt::Display) -> ProviderError {
        match self {
            Self::Sync(ecosystem) => ProviderError::InvalidResponse(format!(
                "OSV dump for {} is invalid: {reason}",
                ecosystem.osv_name()
            )),
            Self::Offline(path) => {
                ProviderError::Offline(format!("OSV dump {} is invalid: {reason}", path.display()))
            }
        }
    }
}

#[derive(Clone)]
pub struct OsvOffline {
    cache: Cache,
    limits: OsvDumpLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OsvDumpAge {
    Current,
    Warn {
        synced_at: DateTime<Utc>,
        age: Duration,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OsvOfflineReadBoundary {
    BeforeMarker,
    BeforeArchive,
    AfterArchive,
}

struct OfflineDumpRead {
    archive: File,
    marker: File,
    archive_name: OsString,
    marker_name: OsString,
    archive_path: PathBuf,
    marker_path: PathBuf,
    archive_identity: FileIdentity,
    marker_identity: FileIdentity,
}

fn offline_capability_error(error: ProviderError) -> ProviderError {
    ProviderError::Offline(error.to_string())
}

impl OsvOffline {
    pub fn new(cache: Cache) -> Self {
        Self {
            cache,
            limits: OsvDumpLimits::production(),
        }
    }
    fn validate_dump_age_from_file(
        &self,
        archive_path: &Path,
        marker_path: &Path,
        marker: &mut File,
        ecosystem: Ecosystem,
        now: DateTime<Utc>,
    ) -> Result<OsvDumpAge, ProviderError> {
        marker.rewind().map_err(|error| {
            ProviderError::Offline(format!(
                "cannot seek OSV dump timestamp {}: {error}",
                marker_path.display()
            ))
        })?;
        let mut raw = String::new();
        marker.read_to_string(&mut raw).map_err(|error| {
            ProviderError::Offline(format!(
                "cannot read OSV dump timestamp {}: {error}",
                marker_path.display()
            ))
        })?;
        let synced_at = DateTime::parse_from_rfc3339(raw.trim())
            .map(|timestamp| timestamp.with_timezone(&Utc))
            .map_err(|error| {
                ProviderError::Offline(format!(
                    "invalid OSV dump timestamp {}: {error}; run `depscan sync --ecosystem {}`",
                    marker_path.display(),
                    ecosystem.display_name()
                ))
            })?;
        if synced_at > now {
            return Err(ProviderError::Offline(format!(
                "OSV dump timestamp {} is in the future ({synced_at} > {now}); run `depscan sync --ecosystem {}`",
                marker_path.display(),
                ecosystem.display_name()
            )));
        }
        let age = now - synced_at;
        if let Some(max_age) = self.cache.policy.max_age {
            if age > max_age {
                return Err(ProviderError::Offline(format!(
                    "OSV dump {} is stale: its age of {} seconds exceeds --max-cache-age ({} seconds); run `depscan sync --ecosystem {}`",
                    archive_path.display(),
                    age.num_seconds(),
                    max_age.num_seconds(),
                    ecosystem.display_name()
                )));
            }
            return Ok(OsvDumpAge::Current);
        }
        if age > Duration::seconds(OSV_DUMP_DEFAULT_WARNING_AGE_SECS) {
            Ok(OsvDumpAge::Warn { synced_at, age })
        } else {
            Ok(OsvDumpAge::Current)
        }
    }

    #[cfg(test)]
    fn validate_dump_age_at(
        &self,
        archive_path: &Path,
        ecosystem: Ecosystem,
        now: DateTime<Utc>,
    ) -> Result<OsvDumpAge, ProviderError> {
        let directory =
            OfflineDirectory::open(self.cache.root()).map_err(offline_capability_error)?;
        let mut dump = directory.open_dump(ecosystem)?;
        debug_assert_eq!(dump.archive_path, archive_path);
        self.validate_dump_age_from_file(
            &dump.archive_path,
            &dump.marker_path,
            &mut dump.marker,
            ecosystem,
            now,
        )
    }

    fn query_blocking_at(
        &self,
        packages: &[Package],
        now: DateTime<Utc>,
    ) -> Result<VulnMap, ProviderError> {
        self.query_blocking_at_with_hook(packages, now, |_| {})
    }

    fn query_blocking_at_with_hook<F>(
        &self,
        packages: &[Package],
        now: DateTime<Utc>,
        hook: F,
    ) -> Result<VulnMap, ProviderError>
    where
        F: Fn(OsvOfflineReadBoundary),
    {
        let mut output = VulnMap::new();
        for package in packages {
            output.entry(package.key()).or_default();
        }
        let mut offline_directory = None;
        for ecosystem in [
            Ecosystem::Npm,
            Ecosystem::PyPI,
            Ecosystem::NuGet,
            Ecosystem::CratesIo,
        ] {
            let scoped: Vec<_> = packages
                .iter()
                .filter(|p| p.ecosystem == ecosystem && p.enrichable && !p.resolved_from_range)
                .collect();
            if scoped.is_empty() {
                continue;
            }
            if offline_directory.is_none() {
                offline_directory = Some(
                    OfflineDirectory::open(self.cache.root()).map_err(offline_capability_error)?,
                );
            }
            let directory = offline_directory
                .as_ref()
                .expect("offline directory is opened for a scoped ecosystem");
            let mut dump = directory.open_dump(ecosystem)?;
            hook(OsvOfflineReadBoundary::BeforeMarker);
            if let OsvDumpAge::Warn { synced_at, age } = self.validate_dump_age_from_file(
                &dump.archive_path,
                &dump.marker_path,
                &mut dump.marker,
                ecosystem,
                now,
            )? {
                warn!(
                    ecosystem = ecosystem.osv_name(),
                    path = %dump.archive_path.display(),
                    %synced_at,
                    age_seconds = age.num_seconds(),
                    warning_age_seconds = OSV_DUMP_DEFAULT_WARNING_AGE_SECS,
                    "OSV dump is older than the default seven-day warning age; run `depscan sync`"
                );
            }
            hook(OsvOfflineReadBoundary::BeforeArchive);
            let archive = dump
                .archive
                .try_clone()
                .map_err(|error| ProviderError::Offline(error.to_string()))?;
            let context = OsvDumpValidationContext::Offline(&dump.archive_path);
            visit_osv_dump_file(
                archive,
                context,
                self.limits,
                true,
                |entry_name, document, validated| {
                    for package in &scoped {
                        if let Some(vulnerability) = vulnerability_from_validated_osv(
                            document,
                            validated,
                            Some(package),
                            false,
                        )
                        .map_err(|error| {
                            context.invalid(format_args!(
                                "entry {entry_name:?} cannot be evaluated: {error}"
                            ))
                        })? {
                            output.entry(package.key()).or_default().push(vulnerability);
                        }
                    }
                    Ok(())
                },
            )?;
            hook(OsvOfflineReadBoundary::AfterArchive);
            directory.revalidate_dump(&dump)?;
        }
        Ok(output)
    }

    fn query_blocking(&self, packages: &[Package]) -> Result<VulnMap, ProviderError> {
        self.query_blocking_at(packages, Utc::now())
    }
}
#[async_trait]
impl VulnProvider for OsvOffline {
    async fn query(&self, packages: &[Package]) -> Result<VulnQueryOutcome, ProviderError> {
        let this = self.clone();
        let owned = packages.to_vec();
        let vulnerabilities = tokio::task::spawn_blocking(move || this.query_blocking(&owned))
            .await
            .map_err(|e| ProviderError::Offline(e.to_string()))??;
        Ok(VulnQueryOutcome::complete(vulnerabilities))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OsvSyncOptions {
    /// Maximum wall-clock time for one dump transfer attempt.
    ///
    /// The HTTP client's ten-second connect/read-idle deadline still applies. A transfer may run
    /// longer than ten seconds while bytes continue to arrive, up to this overall deadline.
    pub transfer_timeout: StdDuration,
}

impl Default for OsvSyncOptions {
    fn default() -> Self {
        Self {
            transfer_timeout: OSV_DUMP_TRANSFER_TIMEOUT,
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OsvSyncBoundary {
    AfterTemporaryCreation,
    BeforeValidation,
    BeforeRollbackStaging,
    BeforeArchivePublication,
    BeforeMarkerPublication,
    BeforeHandledErrorCleanup,
}

#[derive(Clone)]
struct OsvSyncConfig {
    base_url: String,
    transfer_timeout: StdDuration,
    max_download_bytes: u64,
    max_entry_bytes: u64,
    max_uncompressed_bytes: u64,
    max_entries: usize,
    attempts: usize,
    backoff_base: StdDuration,
    max_retry_delay: StdDuration,
    #[cfg(test)]
    boundary_hook: Option<Arc<dyn Fn(OsvSyncBoundary) + Send + Sync>>,
    #[cfg(test)]
    force_rollback_staging_error: bool,
    #[cfg(test)]
    observed_max_chunk_bytes: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    stream_progress: Option<tokio::sync::watch::Sender<u64>>,
}

impl OsvSyncConfig {
    fn new(options: OsvSyncOptions) -> Result<Self, ProviderError> {
        if options.transfer_timeout.is_zero() {
            return Err(ProviderError::InvalidResponse(
                "OSV dump transfer timeout must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            base_url: OSV_DUMP_BASE_URL.to_owned(),
            transfer_timeout: options.transfer_timeout,
            max_download_bytes: OSV_DUMP_MAX_DOWNLOAD_BYTES,
            max_entry_bytes: OSV_DUMP_MAX_ENTRY_BYTES,
            max_uncompressed_bytes: OSV_DUMP_MAX_UNCOMPRESSED_BYTES,
            max_entries: OSV_DUMP_MAX_ENTRIES,
            attempts: OSV_DUMP_ATTEMPTS,
            backoff_base: OSV_DUMP_BACKOFF_BASE,
            max_retry_delay: OSV_DUMP_MAX_RETRY_DELAY,
            #[cfg(test)]
            boundary_hook: None,
            #[cfg(test)]
            force_rollback_staging_error: false,
            #[cfg(test)]
            observed_max_chunk_bytes: None,
            #[cfg(test)]
            stream_progress: None,
        })
    }

    fn retry_settings(&self) -> RetrySettings {
        RetrySettings {
            attempts: self.attempts,
            backoff_base: self.backoff_base,
            max_delay: self.max_retry_delay,
        }
    }

    fn dump_limits(&self) -> OsvDumpLimits {
        OsvDumpLimits {
            max_compressed_bytes: self.max_download_bytes,
            max_entry_bytes: self.max_entry_bytes,
            max_uncompressed_bytes: self.max_uncompressed_bytes,
            max_entries: self.max_entries,
        }
    }

    #[cfg(test)]
    fn reach_boundary(&self, boundary: OsvSyncBoundary) {
        if let Some(hook) = &self.boundary_hook {
            hook(boundary);
        }
    }
}

#[derive(Debug)]
enum OsvDownloadFailure {
    Retryable {
        message: String,
        retry_after: Option<StdDuration>,
    },
    Fatal(ProviderError),
}

async fn stream_osv_dump_body<S, C, E, W>(
    mut chunks: S,
    destination: &mut W,
    url: &str,
    config: &OsvSyncConfig,
) -> Result<u64, OsvDownloadFailure>
where
    S: futures::Stream<Item = Result<C, E>> + Unpin,
    C: AsRef<[u8]>,
    E: std::fmt::Display,
    W: AsyncWrite + Unpin,
{
    let mut downloaded = 0u64;
    let mut next_progress = OSV_DUMP_PROGRESS_INTERVAL_BYTES;
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|error| OsvDownloadFailure::Retryable {
            message: format!("{url}: interrupted OSV dump transfer: {error}"),
            retry_after: None,
        })?;
        let bytes = chunk.as_ref();
        #[cfg(test)]
        if let Some(observed) = &config.observed_max_chunk_bytes {
            observed.fetch_max(bytes.len(), std::sync::atomic::Ordering::Relaxed);
        }
        downloaded = downloaded.checked_add(bytes.len() as u64).ok_or_else(|| {
            OsvDownloadFailure::Fatal(ProviderError::InvalidResponse(format!(
                "{url}: OSV dump size overflowed"
            )))
        })?;
        if downloaded > config.max_download_bytes {
            return Err(OsvDownloadFailure::Fatal(ProviderError::InvalidResponse(
                format!(
                    "{url}: OSV dump exceeds the {}-byte compressed-size limit",
                    config.max_download_bytes
                ),
            )));
        }
        destination
            .write_all(bytes)
            .await
            .map_err(|error| OsvDownloadFailure::Fatal(ProviderError::Cache(error.to_string())))?;
        #[cfg(test)]
        if let Some(progress) = &config.stream_progress {
            progress.send_replace(downloaded);
        }
        if downloaded >= next_progress {
            debug!(%url, downloaded, "streaming OSV dump");
            next_progress = downloaded.saturating_add(OSV_DUMP_PROGRESS_INTERVAL_BYTES);
        }
    }
    destination
        .flush()
        .await
        .map_err(|error| OsvDownloadFailure::Fatal(ProviderError::Cache(error.to_string())))?;
    Ok(downloaded)
}

impl HttpClient {
    async fn download_osv_dump_attempt(
        &self,
        url: &str,
        destination: &File,
        config: &OsvSyncConfig,
    ) -> Result<u64, OsvDownloadFailure> {
        let method = reqwest::Method::GET;
        let context = request_context(&method, url);
        let response = match self
            .inner
            .get(url)
            .timeout(config.transfer_timeout)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let message = match (error.is_timeout(), error.is_connect()) {
                    (true, _) => format!("{context}: request timed out"),
                    (_, true) => format!("{context}: connection failed"),
                    _ => format!("{context}: request failed"),
                };
                if retryable_transport(&error) {
                    return Err(OsvDownloadFailure::Retryable {
                        message,
                        retry_after: None,
                    });
                }
                return Err(OsvDownloadFailure::Fatal(ProviderError::Network(message)));
            }
        };
        let status = response.status();
        if retryable_status(status) {
            return Err(OsvDownloadFailure::Retryable {
                message: format!("{context}: HTTP {status}"),
                retry_after: retry_after_delay(
                    response.headers(),
                    self.retry_runtime.now(),
                    config.max_retry_delay,
                ),
            });
        }
        if !status.is_success() {
            return Err(OsvDownloadFailure::Fatal(ProviderError::Network(format!(
                "{context}: HTTP {status}"
            ))));
        }
        if response
            .content_length()
            .is_some_and(|length| length > config.max_download_bytes)
        {
            return Err(OsvDownloadFailure::Fatal(ProviderError::InvalidResponse(
                format!(
                    "{context}: OSV dump exceeds the {}-byte compressed-size limit",
                    config.max_download_bytes
                ),
            )));
        }

        let mut destination = destination
            .try_clone()
            .and_then(|mut file| {
                file.set_len(0)?;
                file.seek(SeekFrom::Start(0))?;
                Ok(file)
            })
            .map(tokio::fs::File::from_std)
            .map_err(|error| OsvDownloadFailure::Fatal(ProviderError::Cache(error.to_string())))?;
        let downloaded =
            stream_osv_dump_body(response.bytes_stream(), &mut destination, &context, config)
                .await?;
        destination
            .sync_all()
            .await
            .map_err(|error| OsvDownloadFailure::Fatal(ProviderError::Cache(error.to_string())))?;
        debug!(%url, downloaded, "OSV dump transfer complete");
        Ok(downloaded)
    }

    async fn download_osv_dump(
        &self,
        url: &str,
        destination: &File,
        config: &OsvSyncConfig,
    ) -> Result<u64, ProviderError> {
        let settings = config.retry_settings();
        for attempt_index in 0..settings.attempts {
            match self
                .download_osv_dump_attempt(url, destination, config)
                .await
            {
                Ok(downloaded) => return Ok(downloaded),
                Err(OsvDownloadFailure::Fatal(error)) => return Err(error),
                Err(OsvDownloadFailure::Retryable {
                    message,
                    retry_after,
                }) => {
                    if attempt_index + 1 < settings.attempts {
                        self.wait_before_retry(retry_after, attempt_index, settings)
                            .await;
                    } else {
                        return Err(ProviderError::Network(format!(
                            "{message} (attempt {}/{})",
                            attempt_index + 1,
                            settings.attempts
                        )));
                    }
                }
            }
        }
        Err(ProviderError::Network(format!(
            "{}: OSV dump transfer had no attempts",
            request_context(&reqwest::Method::GET, url)
        )))
    }
}

fn validate_osv_dump_document<'a>(
    entry_name: &str,
    document: &'a Value,
) -> Result<ValidatedOsvDocument<'a>, String> {
    let validated = validate_osv_document(document, None).map_err(|error| error.to_string())?;
    if entry_name != format!("{}.json", validated.id) {
        return Err(format!(
            "filename does not match advisory id {:?}",
            validated.id
        ));
    }
    Ok(validated)
}

fn visit_osv_dump_file<F>(
    file: File,
    context: OsvDumpValidationContext<'_>,
    limits: OsvDumpLimits,
    allow_empty: bool,
    mut visit: F,
) -> Result<(), ProviderError>
where
    F: for<'a> FnMut(&str, &'a Value, &ValidatedOsvDocument<'a>) -> Result<(), ProviderError>,
{
    let compressed_bytes = file
        .metadata()
        .map_err(|error| context.invalid(format_args!("cannot inspect archive: {error}")))?
        .len();
    if compressed_bytes > limits.max_compressed_bytes {
        return Err(context.invalid(format_args!(
            "compressed size exceeds {} bytes",
            limits.max_compressed_bytes
        )));
    }
    let mut archive =
        ZipArchive::new(file).map_err(|error| context.invalid(format_args!("bad ZIP: {error}")))?;
    if archive.len() > limits.max_entries {
        return Err(context.invalid(format_args!("entry count exceeds {}", limits.max_entries)));
    }

    let mut json_entries = 0usize;
    let mut declared_uncompressed_bytes = 0u64;
    let mut actual_uncompressed_bytes = 0u64;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| {
            context.invalid(format_args!("cannot open entry at index {index}: {error}"))
        })?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_owned();
        if !name.ends_with(".json") {
            return Err(context.invalid(format_args!("unexpected non-JSON entry {name:?}")));
        }
        if entry.size() > limits.max_entry_bytes {
            return Err(context.invalid(format_args!(
                "entry {name:?} exceeds {} declared uncompressed bytes",
                limits.max_entry_bytes
            )));
        }
        declared_uncompressed_bytes = declared_uncompressed_bytes
            .checked_add(entry.size())
            .ok_or_else(|| context.invalid("declared uncompressed size overflowed"))?;
        if declared_uncompressed_bytes > limits.max_uncompressed_bytes {
            return Err(context.invalid(format_args!(
                "declared uncompressed size exceeds {} bytes at entry {name:?}",
                limits.max_uncompressed_bytes
            )));
        }

        let entry_read_limit = limits.max_entry_bytes.saturating_add(1);
        let mut limited = (&mut entry).take(entry_read_limit);
        let mut deserializer = serde_json::Deserializer::from_reader(&mut limited);
        let parsed = Value::deserialize(&mut deserializer).and_then(|document| {
            deserializer.end()?;
            Ok(document)
        });
        drop(deserializer);
        let actual_entry_bytes = entry_read_limit.saturating_sub(limited.limit());
        if actual_entry_bytes > limits.max_entry_bytes {
            return Err(context.invalid(format_args!(
                "entry {name:?} exceeds {} actual uncompressed bytes",
                limits.max_entry_bytes
            )));
        }
        actual_uncompressed_bytes = actual_uncompressed_bytes
            .checked_add(actual_entry_bytes)
            .ok_or_else(|| context.invalid("actual uncompressed size overflowed"))?;
        if actual_uncompressed_bytes > limits.max_uncompressed_bytes {
            return Err(context.invalid(format_args!(
                "actual uncompressed size exceeds {} bytes at entry {name:?}",
                limits.max_uncompressed_bytes
            )));
        }
        let document = parsed.map_err(|error| {
            context.invalid(format_args!(
                "entry {name:?} is not complete valid UTF-8 JSON: {error}"
            ))
        })?;
        let validated = validate_osv_dump_document(&name, &document).map_err(|error| {
            context.invalid(format_args!(
                "entry {name:?} is not an OSV document: {error}"
            ))
        })?;
        visit(&name, &document, &validated)?;
        json_entries += 1;
    }
    if json_entries == 0 && !allow_empty {
        return Err(context.invalid("archive contains no JSON entries"));
    }
    Ok(())
}

#[cfg(test)]
fn validate_osv_dump(
    path: &Path,
    ecosystem: Ecosystem,
    config: &OsvSyncConfig,
) -> Result<(), ProviderError> {
    let file = File::open(path).map_err(|error| ProviderError::Cache(error.to_string()))?;
    validate_osv_dump_file(file, ecosystem, config)
}

fn validate_osv_dump_file(
    file: File,
    ecosystem: Ecosystem,
    config: &OsvSyncConfig,
) -> Result<(), ProviderError> {
    visit_osv_dump_file(
        file,
        OsvDumpValidationContext::Sync(ecosystem),
        config.dump_limits(),
        false,
        |_, _, _| Ok(()),
    )
}

fn capability_directory_identity(
    directory: &CapDir,
    path: &Path,
) -> Result<FileIdentity, ProviderError> {
    let file = directory
        .try_clone()
        .map_err(|error| cache_path_error(path, format_args!("cannot clone directory: {error}")))?
        .into_std_file();
    FileIdentity::from_owned_file(file)
        .map_err(|error| cache_path_error(path, format_args!("cannot identify directory: {error}")))
}

fn std_file_identity(file: &File, path: &Path) -> Result<FileIdentity, ProviderError> {
    let clone = file
        .try_clone()
        .map_err(|error| cache_path_error(path, format_args!("cannot clone file: {error}")))?;
    FileIdentity::from_owned_file(clone)
        .map_err(|error| cache_path_error(path, format_args!("cannot identify file: {error}")))
}

fn open_capability_regular_file(
    directory: &CapDir,
    name: &OsStr,
    display_path: &Path,
    write: bool,
) -> Result<Option<File>, ProviderError> {
    let metadata = match directory.symlink_metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(cache_path_error(
                display_path,
                format_args!("cannot inspect file: {error}"),
            ));
        }
    };
    if metadata.is_symlink() || !metadata.is_file() {
        return Err(cache_path_error(
            display_path,
            "path is not a real regular file",
        ));
    }
    let mut options = CapOpenOptions::new();
    options.read(true).write(write).follow(FollowSymlinks::No);
    let file = directory.open_with(name, &options).map_err(|error| {
        cache_path_error(
            display_path,
            format_args!("cannot open regular file without following links: {error}"),
        )
    })?;
    if !file
        .metadata()
        .map_err(|error| {
            cache_path_error(
                display_path,
                format_args!("cannot inspect opened file: {error}"),
            )
        })?
        .is_file()
    {
        return Err(cache_path_error(
            display_path,
            "opened path is not a regular file",
        ));
    }
    Ok(Some(file.into_std()))
}

fn validate_capability_sentinel(root: &CapDir, root_path: &Path) -> Result<(), ProviderError> {
    validate_capability_sentinel_with(root, root_path, || {})
}

fn validate_capability_sentinel_with(
    root: &CapDir,
    root_path: &Path,
    before_reopen: impl FnOnce(),
) -> Result<(), ProviderError> {
    let sentinel_path = root_path.join(CACHE_SENTINEL_FILE);
    let mut file =
        open_capability_regular_file(root, OsStr::new(CACHE_SENTINEL_FILE), &sentinel_path, false)?
            .ok_or_else(|| {
                cache_path_error(
                    root_path,
                    format_args!("missing ownership sentinel {CACHE_SENTINEL_FILE}"),
                )
            })?;
    let metadata = file.metadata().map_err(|error| {
        cache_path_error(
            root_path,
            format_args!("cannot inspect ownership sentinel: {error}"),
        )
    })?;
    if metadata.len() > 1024 {
        return Err(cache_path_error(
            root_path,
            format_args!("ownership sentinel {CACHE_SENTINEL_FILE} is oversized"),
        ));
    }
    let identity = std_file_identity(&file, &sentinel_path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).map_err(|error| {
        cache_path_error(
            root_path,
            format_args!("cannot read ownership sentinel: {error}"),
        )
    })?;
    let sentinel: CacheSentinel = serde_json::from_slice(&bytes).map_err(|error| {
        cache_path_error(
            root_path,
            format_args!("invalid ownership sentinel: {error}"),
        )
    })?;
    if sentinel != expected_cache_sentinel() {
        return Err(cache_path_error(
            root_path,
            "ownership sentinel does not identify a supported depscan cache",
        ));
    }
    before_reopen();
    let current =
        open_capability_regular_file(root, OsStr::new(CACHE_SENTINEL_FILE), &sentinel_path, false)?
            .ok_or_else(|| {
                cache_path_error(root_path, "ownership sentinel changed while validating")
            })?;
    if std_file_identity(&current, &sentinel_path)? != identity {
        return Err(cache_path_error(
            root_path,
            "ownership sentinel changed while validating",
        ));
    }
    Ok(())
}

fn validate_root_capability_attachment(
    root: &CapDir,
    root_path: &Path,
    expected_identity: &FileIdentity,
) -> Result<(), ProviderError> {
    let metadata = fs::symlink_metadata(root_path).map_err(|error| {
        cache_path_error(
            root_path,
            format_args!("cannot inspect cache root during revalidation: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(cache_path_error(
            root_path,
            "cache root changed while synchronizing",
        ));
    }
    let current_root =
        CapDir::open_ambient_dir(root_path, ambient_authority()).map_err(|error| {
            cache_path_error(
                root_path,
                format_args!("cannot reopen cache root during revalidation: {error}"),
            )
        })?;
    if &capability_directory_identity(&current_root, root_path)? != expected_identity {
        return Err(cache_path_error(
            root_path,
            "cache root changed while synchronizing",
        ));
    }
    validate_capability_sentinel(root, root_path)
}

struct OfflineDirectory {
    root: CapDir,
    root_path: PathBuf,
    root_identity: FileIdentity,
    directory: CapDir,
    path: PathBuf,
    identity: FileIdentity,
}

impl OfflineDirectory {
    fn open(root_path: &Path) -> Result<Self, ProviderError> {
        Self::open_with(root_path, || {})
    }

    fn open_with(root_path: &Path, after_root_open: impl FnOnce()) -> Result<Self, ProviderError> {
        validate_owned_cache_root(root_path)?;
        let root = CapDir::open_ambient_dir(root_path, ambient_authority()).map_err(|error| {
            cache_path_error(
                root_path,
                format_args!("cannot open cache capability: {error}"),
            )
        })?;
        let root_identity = capability_directory_identity(&root, root_path)?;
        after_root_open();
        validate_root_capability_attachment(&root, root_path, &root_identity)?;
        let path = root_path.join("offline");
        let directory = match root.open_dir_nofollow("offline") {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match root.create_dir("offline") {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(cache_path_error(
                            &path,
                            format_args!("cannot create offline namespace: {error}"),
                        ));
                    }
                }
                root.open_dir_nofollow("offline").map_err(|error| {
                    cache_path_error(
                        &path,
                        format_args!(
                            "cannot open offline namespace without following links: {error}"
                        ),
                    )
                })?
            }
            Err(error) => {
                return Err(cache_path_error(
                    &path,
                    format_args!("cannot open offline namespace without following links: {error}"),
                ));
            }
        };
        let identity = capability_directory_identity(&directory, &path)?;
        let instance = Self {
            root,
            root_path: root_path.to_path_buf(),
            root_identity,
            directory,
            path,
            identity,
        };
        instance.revalidate()?;
        Ok(instance)
    }

    fn revalidate(&self) -> Result<(), ProviderError> {
        validate_root_capability_attachment(&self.root, &self.root_path, &self.root_identity)?;
        let current = self.root.open_dir_nofollow("offline").map_err(|error| {
            cache_path_error(
                &self.path,
                format_args!("offline namespace changed while synchronizing: {error}"),
            )
        })?;
        if capability_directory_identity(&current, &self.path)? != self.identity {
            return Err(cache_path_error(
                &self.path,
                "offline namespace changed while synchronizing",
            ));
        }
        Ok(())
    }

    fn display_path(&self, name: &OsStr) -> PathBuf {
        self.path.join(name)
    }

    fn open_dump(&self, ecosystem: Ecosystem) -> Result<OfflineDumpRead, ProviderError> {
        self.revalidate().map_err(offline_capability_error)?;
        let ecosystem_slug = ecosystem.osv_name().replace('.', "_");
        let archive_name = OsString::from(format!("{ecosystem_slug}.zip"));
        let marker_name = OsString::from(format!("{ecosystem_slug}.synced-at"));
        let archive_path = self.display_path(&archive_name);
        let marker_path = self.display_path(&marker_name);
        let archive =
            open_capability_regular_file(&self.directory, &archive_name, &archive_path, false)
                .map_err(offline_capability_error)?
                .ok_or_else(|| {
                    ProviderError::Offline(format!(
                        "missing OSV dump {}; run `depscan sync --ecosystem {}`",
                        archive_path.display(),
                        ecosystem.display_name()
                    ))
                })?;
        let marker =
            open_capability_regular_file(&self.directory, &marker_name, &marker_path, false)
                .map_err(offline_capability_error)?
                .ok_or_else(|| {
                    ProviderError::Offline(format!(
                        "missing OSV dump timestamp {}; run `depscan sync --ecosystem {}`",
                        marker_path.display(),
                        ecosystem.display_name()
                    ))
                })?;
        let archive_identity =
            std_file_identity(&archive, &archive_path).map_err(offline_capability_error)?;
        let marker_identity =
            std_file_identity(&marker, &marker_path).map_err(offline_capability_error)?;
        let dump = OfflineDumpRead {
            archive,
            marker,
            archive_name,
            marker_name,
            archive_path,
            marker_path,
            archive_identity,
            marker_identity,
        };
        self.revalidate_dump(&dump)?;
        Ok(dump)
    }

    fn revalidate_dump(&self, dump: &OfflineDumpRead) -> Result<(), ProviderError> {
        self.revalidate().map_err(offline_capability_error)?;
        self.revalidate_dump_file(
            &dump.archive_name,
            &dump.archive_path,
            &dump.archive_identity,
        )?;
        self.revalidate_dump_file(&dump.marker_name, &dump.marker_path, &dump.marker_identity)
    }

    fn revalidate_dump_file(
        &self,
        name: &OsStr,
        path: &Path,
        expected_identity: &FileIdentity,
    ) -> Result<(), ProviderError> {
        let current = open_capability_regular_file(&self.directory, name, path, false)
            .map_err(offline_capability_error)?
            .ok_or_else(|| {
                ProviderError::Offline(format!(
                    "OSV dump file {} changed while it was being read; refusing offline scan",
                    path.display()
                ))
            })?;
        let current_identity =
            std_file_identity(&current, path).map_err(offline_capability_error)?;
        if &current_identity != expected_identity {
            return Err(ProviderError::Offline(format!(
                "OSV dump file {} changed while it was being read; refusing offline scan",
                path.display()
            )));
        }
        Ok(())
    }
}

struct CapabilityTempFile {
    directory: CapDir,
    directory_path: PathBuf,
    file: Option<File>,
    name: Option<OsString>,
    cleanup: bool,
}

impl CapabilityTempFile {
    fn new(
        directory: &OfflineDirectory,
        prefix: &str,
        suffix: &str,
    ) -> Result<Self, ProviderError> {
        for _ in 0..128 {
            let name = OsString::from(format!(
                "{prefix}{:016x}{suffix}",
                rand::rng().random::<u64>()
            ));
            let mut options = CapOpenOptions::new();
            options
                .read(true)
                .write(true)
                .create_new(true)
                .follow(FollowSymlinks::No);
            match directory.directory.open_with(&name, &options) {
                Ok(file) => {
                    return Ok(Self {
                        directory: directory.directory.try_clone().map_err(|error| {
                            cache_path_error(
                                &directory.path,
                                format_args!("cannot clone offline capability: {error}"),
                            )
                        })?,
                        directory_path: directory.path.clone(),
                        file: Some(file.into_std()),
                        name: Some(name),
                        cleanup: true,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(cache_path_error(
                        &directory.path,
                        format_args!("cannot create temporary file: {error}"),
                    ));
                }
            }
        }
        Err(cache_path_error(
            &directory.path,
            "cannot allocate a unique temporary file name",
        ))
    }

    fn from_link(directory: &OfflineDirectory, name: OsString) -> Result<Self, ProviderError> {
        let display = directory.display_path(&name);
        let file = open_capability_regular_file(&directory.directory, &name, &display, false)?
            .ok_or_else(|| cache_path_error(&display, "staged rollback link disappeared"))?;
        Ok(Self {
            directory: directory.directory.try_clone().map_err(|error| {
                cache_path_error(
                    &directory.path,
                    format_args!("cannot clone offline capability: {error}"),
                )
            })?,
            directory_path: directory.path.clone(),
            file: Some(file),
            name: Some(name),
            cleanup: true,
        })
    }

    fn as_file(&self) -> &File {
        self.file
            .as_ref()
            .expect("temporary file handle is present before publication")
    }

    fn as_file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .expect("temporary file handle is present before publication")
    }

    fn logical_path(&self) -> PathBuf {
        self.directory_path.join(
            self.name
                .as_deref()
                .expect("temporary file name is present before publication"),
        )
    }

    fn persist(mut self, target: &OsStr) -> Result<(), CapabilityPersistError> {
        drop(self.file.take());
        let name = self
            .name
            .take()
            .expect("temporary file name is present before publication");
        match self.directory.rename(&name, &self.directory, target) {
            Ok(()) => {
                self.cleanup = false;
                Ok(())
            }
            Err(source) => {
                self.name = Some(name);
                Err(CapabilityPersistError {
                    source,
                    temporary: self,
                })
            }
        }
    }

    fn retain(mut self) -> PathBuf {
        self.cleanup = false;
        self.logical_path()
    }
}

impl Write for CapabilityTempFile {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.as_file_mut().write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.as_file_mut().flush()
    }
}

impl Drop for CapabilityTempFile {
    fn drop(&mut self) {
        drop(self.file.take());
        if self.cleanup
            && let Some(name) = self.name.take()
        {
            let _ = self.directory.remove_file(name);
        }
    }
}

struct CapabilityPersistError {
    source: std::io::Error,
    temporary: CapabilityTempFile,
}

fn persist_capability_temp(
    temporary: CapabilityTempFile,
    target: &OsStr,
) -> Result<(), ProviderError> {
    match temporary.persist(target) {
        Ok(()) => Ok(()),
        Err(error) => {
            let source = error.source.to_string();
            drop(error.temporary);
            Err(ProviderError::Cache(source))
        }
    }
}

fn cleanup_abandoned_osv_temps(
    directory: &OfflineDirectory,
    ecosystem_slug: &str,
) -> Result<(), ProviderError> {
    let prefix = format!(".{ecosystem_slug}-");
    let entries = directory.directory.entries().map_err(|error| {
        cache_path_error(
            &directory.path,
            format_args!("cannot inspect offline namespace: {error}"),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            cache_path_error(
                &directory.path,
                format_args!("cannot inspect offline namespace: {error}"),
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&prefix)
            || !OSV_DUMP_TEMP_SUFFIXES
                .iter()
                .any(|suffix| name.ends_with(suffix))
        {
            continue;
        }
        let metadata = directory
            .directory
            .symlink_metadata(name)
            .map_err(|error| {
                cache_path_error(
                    &directory.path,
                    format_args!("cannot inspect abandoned temporary file {name:?}: {error}"),
                )
            })?;
        if metadata.is_dir() || (!metadata.is_file() && !metadata.is_symlink()) {
            return Err(cache_path_error(
                &directory.path,
                format_args!("refusing non-file abandoned temporary path {name:?}"),
            ));
        }
        directory.directory.remove_file(name).map_err(|error| {
            cache_path_error(
                &directory.path,
                format_args!("cannot remove abandoned temporary file {name:?}: {error}"),
            )
        })?;
    }
    Ok(())
}

fn acquire_osv_sync_lock(
    root: &Path,
    ecosystem_slug: &str,
) -> Result<(OfflineDirectory, File), ProviderError> {
    acquire_osv_sync_lock_with(root, ecosystem_slug, || {}, || {})
}

fn acquire_osv_sync_lock_with(
    root: &Path,
    ecosystem_slug: &str,
    before_lock_open: impl FnOnce(),
    before_cleanup: impl FnOnce(),
) -> Result<(OfflineDirectory, File), ProviderError> {
    let directory = OfflineDirectory::open(root)?;
    let lock_name = OsString::from(format!(".{ecosystem_slug}.sync.lock"));
    let lock_path = directory.display_path(&lock_name);
    if let Ok(metadata) = directory.directory.symlink_metadata(&lock_name)
        && (metadata.is_symlink() || !metadata.is_file())
    {
        return Err(cache_path_error(
            &lock_path,
            "sync lock is not a regular file",
        ));
    }
    before_lock_open();
    let mut options = CapOpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .follow(FollowSymlinks::No);
    let lock = directory
        .directory
        .open_with(&lock_name, &options)
        .map_err(|error| {
            cache_path_error(&lock_path, format_args!("cannot open sync lock: {error}"))
        })?
        .into_std();
    if !lock.metadata().is_ok_and(|value| value.is_file()) {
        return Err(cache_path_error(
            &lock_path,
            "sync lock is not a regular file",
        ));
    }
    lock.lock_exclusive().map_err(|error| {
        cache_path_error(
            &lock_path,
            format_args!("cannot acquire sync lock: {error}"),
        )
    })?;
    directory.revalidate()?;
    before_cleanup();
    cleanup_abandoned_osv_temps(&directory, ecosystem_slug)?;
    directory.revalidate()?;
    Ok((directory, lock))
}

fn validate_marker_target(directory: &OfflineDirectory, name: &OsStr) -> Result<(), ProviderError> {
    let path = directory.display_path(name);
    match directory.directory.symlink_metadata(name) {
        Ok(metadata) if metadata.is_symlink() || !metadata.is_file() => Err(ProviderError::Cache(
            format!("cannot replace non-file sync marker {}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ProviderError::Cache(error.to_string())),
    }
}

fn stage_previous_archive(
    directory: &OfflineDirectory,
    archive_name: &OsStr,
    temp_prefix: &str,
) -> Result<Option<CapabilityTempFile>, ProviderError> {
    let path = directory.display_path(archive_name);
    let Some(mut source) =
        open_capability_regular_file(&directory.directory, archive_name, &path, false)?
    else {
        return Ok(None);
    };
    let source_identity = std_file_identity(&source, &path)?;
    let mut link_error = None;
    for _ in 0..128 {
        let candidate = OsString::from(format!(
            "{temp_prefix}{:016x}.zip.rollback.tmp",
            rand::rng().random::<u64>()
        ));
        match directory
            .directory
            .hard_link(archive_name, &directory.directory, &candidate)
        {
            Ok(()) => {
                let backup = match CapabilityTempFile::from_link(directory, candidate.clone()) {
                    Ok(backup) => backup,
                    Err(error) => {
                        let _ = directory.directory.remove_file(candidate);
                        return Err(error);
                    }
                };
                if std_file_identity(backup.as_file(), &backup.logical_path())? == source_identity {
                    return Ok(Some(backup));
                }
                drop(backup);
                link_error = Some("archive changed while creating the hard link".to_owned());
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                link_error = Some(error.to_string());
                break;
            }
        }
    }
    let link_error =
        link_error.unwrap_or_else(|| "could not allocate a unique hard-link name".to_owned());
    let expected_bytes = source
        .metadata()
        .map_err(|error| ProviderError::Cache(error.to_string()))?
        .len();
    let source_permissions = source
        .metadata()
        .map_err(|error| ProviderError::Cache(error.to_string()))?
        .permissions();
    let mut backup = CapabilityTempFile::new(directory, temp_prefix, ".zip.rollback.tmp").map_err(
        |copy_error| {
            ProviderError::Cache(format!(
                "cannot stage {} for rollback (hard link: {link_error}; copy: {copy_error})",
                path.display()
            ))
        },
    )?;
    let copied_bytes = std::io::copy(&mut source, backup.as_file_mut())
        .and_then(|bytes| {
            backup.as_file().set_permissions(source_permissions)?;
            backup.as_file().sync_all().map(|()| bytes)
        })
        .map_err(|copy_error| {
            ProviderError::Cache(format!(
                "cannot stage {} for rollback (hard link: {link_error}; copy: {copy_error})",
                path.display()
            ))
        })?;
    if copied_bytes != expected_bytes {
        return Err(ProviderError::Cache(format!(
            "cannot stage {} for rollback: copied {copied_bytes} of {expected_bytes} bytes",
            path.display()
        )));
    }
    Ok(Some(backup))
}

fn restore_previous_archive(
    directory: &OfflineDirectory,
    previous: Option<CapabilityTempFile>,
    archive_name: &OsStr,
) -> Result<(), ProviderError> {
    let Some(previous) = previous else {
        return match directory.directory.remove_file(archive_name) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ProviderError::Cache(error.to_string())),
        };
    };
    match previous.persist(archive_name) {
        Ok(()) => Ok(()),
        Err(error) => {
            let restore_error = error.source;
            let recovery_path = error.temporary.retain();
            Err(ProviderError::Cache(format!(
                "{restore_error}; rollback copy retained at {}",
                recovery_path.display()
            )))
        }
    }
}

#[derive(Clone, Copy)]
struct OsvPairNames<'a> {
    archive: &'a OsStr,
    marker: &'a OsStr,
}

fn publish_osv_pair_with<F>(
    directory: &OfflineDirectory,
    archive_temp: CapabilityTempFile,
    marker_temp: CapabilityTempFile,
    names: OsvPairNames<'_>,
    previous_archive: Option<CapabilityTempFile>,
    before_archive: impl FnOnce() -> Result<(), ProviderError>,
    publish_marker: F,
) -> Result<(), ProviderError>
where
    F: FnOnce(CapabilityTempFile, &OsStr) -> Result<(), ProviderError>,
{
    let archive_path = directory.display_path(names.archive);
    let marker_path = directory.display_path(names.marker);
    before_archive()?;
    if let Err(error) = archive_temp.persist(names.archive) {
        let publication_error = error.source.to_string();
        drop(error.temporary);
        return Err(ProviderError::Cache(format!(
            "replacing {}: {publication_error}",
            archive_path.display()
        )));
    }
    if let Err(error) = publish_marker(marker_temp, names.marker) {
        let publication_error = error.to_string();
        restore_previous_archive(directory, previous_archive, names.archive).map_err(|rollback_error| {
            ProviderError::Cache(format!(
                "replacing {} failed: {publication_error}; restoring {} also failed: {rollback_error}",
                marker_path.display(),
                archive_path.display()
            ))
        })?;
        return Err(ProviderError::Cache(format!(
            "replacing {} failed: {publication_error}; restored previous archive",
            marker_path.display()
        )));
    }
    drop(previous_archive);
    Ok(())
}

fn publish_osv_pair(
    directory: &OfflineDirectory,
    archive_temp: CapabilityTempFile,
    marker_temp: CapabilityTempFile,
    archive_name: &OsStr,
    marker_name: &OsStr,
    previous_archive: Option<CapabilityTempFile>,
    _config: &OsvSyncConfig,
) -> Result<(), ProviderError> {
    publish_osv_pair_with(
        directory,
        archive_temp,
        marker_temp,
        OsvPairNames {
            archive: archive_name,
            marker: marker_name,
        },
        previous_archive,
        || {
            #[cfg(test)]
            _config.reach_boundary(OsvSyncBoundary::BeforeArchivePublication);
            directory.revalidate()
        },
        |temporary, target| {
            #[cfg(test)]
            _config.reach_boundary(OsvSyncBoundary::BeforeMarkerPublication);
            directory.revalidate()?;
            persist_capability_temp(temporary, target)
        },
    )
}

pub async fn sync_osv_dumps(
    http: &HttpClient,
    cache: &Cache,
    ecosystems: &[Ecosystem],
) -> Result<Vec<PathBuf>, ProviderError> {
    sync_osv_dumps_with_options(http, cache, ecosystems, OsvSyncOptions::default()).await
}

pub async fn sync_osv_dumps_with_options(
    http: &HttpClient,
    cache: &Cache,
    ecosystems: &[Ecosystem],
    options: OsvSyncOptions,
) -> Result<Vec<PathBuf>, ProviderError> {
    let config = OsvSyncConfig::new(options)?;
    sync_osv_dumps_with_config(http, cache, ecosystems, &config).await
}

async fn sync_osv_dumps_with_config(
    http: &HttpClient,
    cache: &Cache,
    ecosystems: &[Ecosystem],
    config: &OsvSyncConfig,
) -> Result<Vec<PathBuf>, ProviderError> {
    let list: Vec<Ecosystem> = if ecosystems.is_empty() {
        vec![
            Ecosystem::Npm,
            Ecosystem::PyPI,
            Ecosystem::NuGet,
            Ecosystem::CratesIo,
        ]
    } else {
        ecosystems.to_vec()
    };
    let mut written = Vec::new();
    for eco in list {
        let ecosystem_slug = eco.osv_name().replace('.', "_");
        let cache_root = cache.root().to_path_buf();
        let lock_slug = ecosystem_slug.clone();
        let (dir, sync_lock) =
            tokio::task::spawn_blocking(move || acquire_osv_sync_lock(&cache_root, &lock_slug))
                .await
                .map_err(|error| {
                    ProviderError::Cache(format!(
                        "OSV sync lock task for {} failed: {error}",
                        eco.osv_name()
                    ))
                })??;
        let dir = Arc::new(dir);
        let url = format!("{}/{}/all.zip", config.base_url, eco.osv_name());
        debug!(%url, "downloading OSV dump");
        let archive_name = OsString::from(format!("{ecosystem_slug}.zip"));
        let marker_name = OsString::from(format!("{ecosystem_slug}.synced-at"));
        let path = dir.display_path(&archive_name);
        validate_marker_target(&dir, &marker_name)?;
        let temp_prefix = format!(".{ecosystem_slug}-");
        let archive_temp = CapabilityTempFile::new(&dir, &temp_prefix, ".zip.tmp")?;
        #[cfg(test)]
        config.reach_boundary(OsvSyncBoundary::AfterTemporaryCreation);
        dir.revalidate()?;
        if let Err(error) = http
            .download_osv_dump(&url, archive_temp.as_file(), config)
            .await
        {
            #[cfg(test)]
            config.reach_boundary(OsvSyncBoundary::BeforeHandledErrorCleanup);
            dir.revalidate()?;
            return Err(error);
        }

        #[cfg(test)]
        config.reach_boundary(OsvSyncBoundary::BeforeValidation);
        dir.revalidate()?;
        let validation_file = archive_temp
            .as_file()
            .try_clone()
            .map_err(|error| ProviderError::Cache(error.to_string()))?;
        let validation_config = config.clone();
        let validation = tokio::task::spawn_blocking(move || {
            validate_osv_dump_file(validation_file, eco, &validation_config)
        })
        .await
        .map_err(|error| {
            ProviderError::InvalidResponse(format!(
                "OSV dump validation task for {} failed: {error}",
                eco.osv_name()
            ))
        })?;
        if let Err(error) = validation {
            #[cfg(test)]
            config.reach_boundary(OsvSyncBoundary::BeforeHandledErrorCleanup);
            dir.revalidate()?;
            return Err(error);
        }

        dir.revalidate()?;
        let mut marker_temp = CapabilityTempFile::new(&dir, &temp_prefix, ".synced-at.tmp")?;
        marker_temp
            .write_all(Utc::now().to_rfc3339().as_bytes())
            .and_then(|_| marker_temp.as_file().sync_all())
            .map_err(|error| ProviderError::Cache(error.to_string()))?;
        #[cfg(test)]
        config.reach_boundary(OsvSyncBoundary::BeforeRollbackStaging);
        dir.revalidate()?;
        #[cfg(test)]
        if config.force_rollback_staging_error {
            return Err(ProviderError::Cache(
                "injected rollback staging failure".to_owned(),
            ));
        }
        let stage_directory = dir.clone();
        let stage_name = archive_name.clone();
        let stage_prefix = temp_prefix.clone();
        let previous_archive = tokio::task::spawn_blocking(move || {
            stage_previous_archive(&stage_directory, &stage_name, &stage_prefix)
        })
        .await
        .map_err(|error| {
            ProviderError::Cache(format!(
                "OSV rollback staging task for {} failed: {error}",
                eco.osv_name()
            ))
        })??;

        dir.revalidate()?;
        validate_marker_target(&dir, &marker_name)?;
        publish_osv_pair(
            &dir,
            archive_temp,
            marker_temp,
            &archive_name,
            &marker_name,
            previous_archive,
            config,
        )?;
        dir.revalidate()?;
        let _ = fs2::FileExt::unlock(&sync_lock);
        written.push(path);
    }
    Ok(written)
}

fn invalid_crates_io_name(name: &str, reason: impl Into<String>) -> ProviderError {
    ProviderError::InvalidPackageName {
        ecosystem: Ecosystem::CratesIo,
        name: name.to_owned(),
        reason: reason.into(),
    }
}

/// Builds the lowercase crates.io sparse-index path after applying the registry's structural
/// package-name restrictions. Reserved-name and collision policies are registry concerns; this
/// validation covers the grammar needed to construct one safe index path.
fn crates_io_sparse_path(name: &str) -> Result<String, ProviderError> {
    if name.is_empty() {
        return Err(invalid_crates_io_name(name, "the name cannot be empty"));
    }
    if !name.is_ascii() {
        return Err(invalid_crates_io_name(
            name,
            "only ASCII characters are allowed",
        ));
    }
    if name.len() > CRATES_IO_MAX_NAME_LEN {
        return Err(invalid_crates_io_name(
            name,
            format!("the name exceeds {CRATES_IO_MAX_NAME_LEN} ASCII characters"),
        ));
    }

    let first = name
        .as_bytes()
        .first()
        .copied()
        .ok_or_else(|| invalid_crates_io_name(name, "the name cannot be empty"))?;
    if !first.is_ascii_alphabetic() {
        return Err(invalid_crates_io_name(
            name,
            "the first character must be an ASCII letter",
        ));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid_crates_io_name(
            name,
            "only ASCII letters, digits, '-' and '_' are allowed",
        ));
    }

    let normalized = name.to_ascii_lowercase();
    Ok(match normalized.len() {
        1 => format!("1/{normalized}"),
        2 => format!("2/{normalized}"),
        3 => {
            let first: String = normalized.chars().take(1).collect();
            format!("3/{first}/{normalized}")
        }
        _ => {
            let first_two: String = normalized.chars().take(2).collect();
            let second_two: String = normalized.chars().skip(2).take(2).collect();
            format!("{first_two}/{second_two}/{normalized}")
        }
    })
}

#[derive(Clone)]
pub struct RegistryClient {
    http: HttpClient,
    cache: Cache,
    limits: Arc<HashMap<Ecosystem, Arc<Semaphore>>>,
    npm_base_url: String,
    pypi_base_url: String,
    nuget_base_url: String,
    nuget_registration_base_url: String,
    crates_index_base_url: String,
}
impl RegistryClient {
    pub fn new(http: HttpClient, cache: Cache) -> Self {
        Self::with_registry_base_urls(
            http,
            cache,
            NPM_REGISTRY_BASE_URL,
            PYPI_REGISTRY_BASE_URL,
            NUGET_REGISTRY_BASE_URL,
            NUGET_REGISTRATION_BASE_URL,
            CRATES_IO_INDEX_BASE_URL,
        )
    }

    #[cfg(test)]
    fn with_crates_index_base_url(
        http: HttpClient,
        cache: Cache,
        crates_index_base_url: impl Into<String>,
    ) -> Self {
        Self::with_registry_base_urls(
            http,
            cache,
            NPM_REGISTRY_BASE_URL,
            PYPI_REGISTRY_BASE_URL,
            NUGET_REGISTRY_BASE_URL,
            NUGET_REGISTRATION_BASE_URL,
            crates_index_base_url,
        )
    }

    fn with_registry_base_urls(
        http: HttpClient,
        cache: Cache,
        npm_base_url: impl Into<String>,
        pypi_base_url: impl Into<String>,
        nuget_base_url: impl Into<String>,
        nuget_registration_base_url: impl Into<String>,
        crates_index_base_url: impl Into<String>,
    ) -> Self {
        let limits = HashMap::from([
            (Ecosystem::Npm, Arc::new(Semaphore::new(16))),
            (Ecosystem::PyPI, Arc::new(Semaphore::new(16))),
            (Ecosystem::NuGet, Arc::new(Semaphore::new(16))),
            (Ecosystem::CratesIo, Arc::new(Semaphore::new(8))),
        ]);
        Self {
            http,
            cache,
            limits: Arc::new(limits),
            npm_base_url: npm_base_url.into().trim_end_matches('/').to_owned(),
            pypi_base_url: pypi_base_url.into().trim_end_matches('/').to_owned(),
            nuget_base_url: nuget_base_url.into().trim_end_matches('/').to_owned(),
            nuget_registration_base_url: nuget_registration_base_url
                .into()
                .trim_end_matches('/')
                .to_owned(),
            crates_index_base_url: crates_index_base_url
                .into()
                .trim_end_matches('/')
                .to_owned(),
        }
    }
    async fn metadata(
        &self,
        namespace: &str,
        url: &str,
        headers: HeaderMap,
    ) -> Result<Value, ProviderError> {
        self.metadata_with_limit(namespace, url, headers, None)
            .await
    }

    async fn metadata_limited(
        &self,
        namespace: &str,
        url: &str,
        headers: HeaderMap,
        max_bytes: usize,
    ) -> Result<Value, ProviderError> {
        self.metadata_with_limit(namespace, url, headers, Some(max_bytes))
            .await
    }

    async fn metadata_with_limit(
        &self,
        namespace: &str,
        url: &str,
        headers: HeaderMap,
        max_bytes: Option<usize>,
    ) -> Result<Value, ProviderError> {
        let ttl = Duration::seconds(REGISTRY_TTL_SECS);
        let mut generation = self.cache.snapshot("registry", namespace, ttl);
        let mut cached = self.cache.policy.read.then(|| generation.clone()).flatten();
        let mut force_revalidate = false;
        for _ in 0..CACHE_COMMIT_ATTEMPTS {
            if !force_revalidate
                && let Some(cached) = &cached
                && cached.fresh
            {
                return Ok(cached.value.clone());
            }
            force_revalidate = false;
            let mut request_headers = headers.clone();
            let conditional = add_if_none_match(&mut request_headers, cached.as_ref());
            let response = if let Some(max_bytes) = max_bytes {
                self.http
                    .get_json_limited_revalidated(url, max_bytes, request_headers)
                    .await?
            } else {
                self.http.get_json_revalidated(url, request_headers).await?
            };
            match response {
                Revalidated::Modified { value, etag } => {
                    match self.cache.put_if_unchanged(
                        "registry",
                        namespace,
                        generation.as_ref(),
                        &value,
                        etag,
                        ttl,
                    )? {
                        CacheCommit::Written => return Ok(value),
                        CacheCommit::Conflict(current) => {
                            generation = current;
                            cached = self.cache.policy.read.then(|| generation.clone()).flatten();
                            force_revalidate = true;
                        }
                    }
                }
                Revalidated::NotModified { etag } => {
                    if !conditional {
                        return Err(ProviderError::InvalidResponse(format!(
                            "{url}: received HTTP 304 without sending If-None-Match"
                        )));
                    }
                    let snapshot = cached.as_ref().ok_or_else(|| {
                        ProviderError::InvalidResponse(format!(
                            "{url}: received HTTP 304 without a cached registry value"
                        ))
                    })?;
                    let value = snapshot.value.clone();
                    let etag = etag.or_else(|| snapshot.etag.clone());
                    match self.cache.put_if_unchanged(
                        "registry",
                        namespace,
                        generation.as_ref(),
                        &value,
                        etag,
                        ttl,
                    )? {
                        CacheCommit::Written => return Ok(value),
                        CacheCommit::Conflict(Some(current)) if current.fresh => {
                            if self.cache.policy.read {
                                return Ok(current.value);
                            }
                            generation = Some(current);
                            cached = None;
                        }
                        CacheCommit::Conflict(current) => {
                            generation = current;
                            cached = self.cache.policy.read.then(|| generation.clone()).flatten();
                        }
                    }
                }
            }
        }
        Err(ProviderError::Cache(format!(
            "registry cache entry {namespace:?} changed repeatedly during revalidation"
        )))
    }

    async fn nuget_canonical_name(
        &self,
        package: &Package,
        target_version: &str,
    ) -> Result<String, ProviderError> {
        let index_url =
            nuget_registration_url_with_base(&self.nuget_registration_base_url, package);
        let index = self
            .metadata_limited(
                &nuget_registration_cache_key(package),
                &index_url,
                HeaderMap::new(),
                NUGET_REGISTRATION_MAX_RESPONSE_BYTES,
            )
            .await?;
        let page = match nuget_registration_page_for_version(&index, target_version)? {
            NugetRegistrationPageSource::Inline(page) => page,
            NugetRegistrationPageSource::Linked { lower, upper, url } => {
                let url = validated_nuget_registration_page_url(
                    &self.nuget_registration_base_url,
                    package,
                    &url,
                )?;
                self.metadata_limited(
                    &nuget_registration_page_cache_key(package, &lower, &upper),
                    &url,
                    HeaderMap::new(),
                    NUGET_REGISTRATION_MAX_RESPONSE_BYTES,
                )
                .await?
            }
        };
        canonical_nuget_name_from_registration_page(package, target_version, &page)
    }

    async fn npm(&self, p: &Package) -> Result<RegistryEnrichment, ProviderError> {
        let _permit = self.limits[&Ecosystem::Npm]
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let url = format!("{}/{}", self.npm_base_url, encode_path_segment(&p.name));
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.npm.install-v1+json"),
        );
        let data = self
            .metadata(&format!("npm:{}", p.name), &url, headers)
            .await?;
        npm_version_result(p, &data).map(RegistryEnrichment::versions_only)
    }
    async fn pypi(&self, p: &Package) -> Result<RegistryEnrichment, ProviderError> {
        let _permit = self.limits[&Ecosystem::PyPI]
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let url = format!(
            "{}/{}/json",
            self.pypi_base_url,
            encode_path_segment(&p.name)
        );
        let data = self
            .metadata(&format!("pypi:{}", p.name), &url, HeaderMap::new())
            .await?;
        pypi_version_result(p, &data).map(RegistryEnrichment::versions_only)
    }
    async fn nuget(&self, p: &Package) -> Result<RegistryEnrichment, ProviderError> {
        let _permit = self.limits[&Ecosystem::NuGet]
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let url = nuget_registry_url_with_base(&self.nuget_base_url, p);
        let cache_key = nuget_registry_cache_key(p);
        let data = self.metadata(&cache_key, &url, HeaderMap::new()).await?;
        let latest = nuget_version_result(p, &data)?;
        let target_version = latest
            .latest_matching
            .as_deref()
            .unwrap_or(p.version.as_str());
        let canonical_name = self.nuget_canonical_name(p, target_version).await?;
        Ok(RegistryEnrichment {
            latest,
            canonical_name: Some(canonical_name),
        })
    }
    async fn crates(&self, p: &Package) -> Result<RegistryEnrichment, ProviderError> {
        let path = crates_io_sparse_path(&p.name)?;
        let _permit = self.limits[&Ecosystem::CratesIo]
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let name = &p.name;
        let url = format!("{}/{path}", self.crates_index_base_url);
        let entries = self
            .crates_metadata_for_index(&format!("crates:{}", name), name, &url)
            .await?;
        crates_version_result(p, &entries).map(RegistryEnrichment::versions_only)
    }
}
#[async_trait]
impl VersionProvider for RegistryClient {
    async fn latest(&self, package: &Package) -> Result<RegistryEnrichment, ProviderError> {
        match package.ecosystem {
            Ecosystem::Npm => self.npm(package).await,
            Ecosystem::PyPI => self.pypi(package).await,
            Ecosystem::NuGet => self.nuget(package).await,
            Ecosystem::CratesIo => self.crates(package).await,
        }
    }
}

fn matching_version<'a>(
    package: &Package,
    versions: impl IntoIterator<Item = &'a str>,
) -> Result<Option<String>, ProviderError> {
    let Some(constraint) = package.manifest_constraint.as_ref() else {
        if package.resolved_from_range {
            return Err(ProviderError::InvalidResponse(format!(
                "{} is marked range-derived but has no preserved manifest constraint",
                package.display_name
            )));
        }
        return Ok(None);
    };
    latest_matching_version(package.ecosystem, constraint.normalized(), versions)
        .map_err(|error| ProviderError::InvalidResponse(error.to_string()))
}

fn version_result(
    package: &Package,
    latest: String,
    latest_matching: Option<String>,
    yanked: bool,
) -> LatestVersions {
    let staleness = if package.resolved_from_range {
        depscan_core::Staleness::Unknown
    } else {
        classify_staleness(package.ecosystem, &package.version, &latest)
    };
    LatestVersions {
        latest_stable: latest,
        latest_matching,
        staleness,
        yanked,
    }
}

fn npm_version_result(package: &Package, data: &Value) -> Result<LatestVersions, ProviderError> {
    let latest = data
        .get("dist-tags")
        .and_then(|value| value.get("latest"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::InvalidResponse(format!(
                "npm response lacked latest for {}",
                package.name
            ))
        })?
        .to_owned();
    let matching = if package.manifest_constraint.is_some() {
        let versions = data
            .get("versions")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ProviderError::InvalidResponse(format!(
                    "npm response lacked release versions for manifest-only package {}",
                    package.name
                ))
            })?;
        matching_version(package, versions.keys().map(String::as_str))?
    } else {
        matching_version(package, std::iter::empty())?
    };
    Ok(version_result(package, latest, matching, false))
}

fn pypi_version_result(package: &Package, data: &Value) -> Result<LatestVersions, ProviderError> {
    let releases = data
        .get("releases")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ProviderError::InvalidResponse("PyPI response lacked releases".to_owned())
        })?;
    let latest = select_pypi_release(releases, &package.version).ok_or_else(|| {
        ProviderError::InvalidResponse(format!("PyPI has no suitable release for {}", package.name))
    })?;
    let yanked = releases
        .get(&package.version)
        .is_some_and(pypi_release_is_yanked);
    let matching = matching_version(
        package,
        releases
            .iter()
            .filter(|(_, files)| !pypi_release_is_yanked(files))
            .map(|(version, _)| version.as_str()),
    )?;
    Ok(version_result(package, latest, matching, yanked))
}

fn nuget_version_result(package: &Package, data: &Value) -> Result<LatestVersions, ProviderError> {
    let versions = data
        .get("versions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProviderError::InvalidResponse("NuGet response lacked versions".to_owned())
        })?;
    let latest =
        select_nuget_release(versions.iter().filter_map(Value::as_str)).ok_or_else(|| {
            ProviderError::InvalidResponse(format!(
                "NuGet has no stable version for {}",
                package.name
            ))
        })?;
    let matching = matching_version(package, versions.iter().filter_map(Value::as_str))?;
    Ok(version_result(package, latest, matching, false))
}

fn crates_version_result(
    package: &Package,
    entries: &[CratesIndexEntry],
) -> Result<LatestVersions, ProviderError> {
    let mut all: Vec<&str> = Vec::new();
    let mut matchable: Vec<&str> = Vec::new();
    let mut yanked = false;
    for entry in entries {
        if entry.vers == package.version {
            yanked = entry.yanked;
        }
        if !entry.yanked {
            matchable.push(&entry.vers);
            if !is_prerelease(Ecosystem::CratesIo, &entry.vers) {
                all.push(&entry.vers);
            }
        }
    }
    let latest = maximum_version(Ecosystem::CratesIo, all).ok_or_else(|| {
        ProviderError::InvalidResponse(format!(
            "crates.io has no stable version for {}",
            package.name
        ))
    })?;
    let matching = matching_version(package, matchable)?;
    Ok(version_result(package, latest, matching, yanked))
}
fn maximum_version<'a>(
    eco: Ecosystem,
    versions: impl IntoIterator<Item = &'a str>,
) -> Option<String> {
    versions
        .into_iter()
        .max_by(|a, b| compare_versions(eco, a, b))
        .map(str::to_owned)
}

fn select_nuget_release<'a>(versions: impl IntoIterator<Item = &'a str>) -> Option<String> {
    versions
        .into_iter()
        .filter_map(|raw| {
            NuGetVersion::parse(raw)
                .ok()
                .filter(|version| !version.is_prerelease())
                .map(|version| (raw, version))
        })
        .max_by(|(left_raw, left), (right_raw, right)| {
            left.cmp(right).then_with(|| left_raw.cmp(right_raw))
        })
        .map(|(raw, _)| raw.to_owned())
}

fn select_pypi_release(
    releases: &serde_json::Map<String, Value>,
    installed: &str,
) -> Option<String> {
    let allow_prerelease = pypi_version_is_prerelease(installed);
    releases
        .iter()
        .filter(|(version, files)| {
            let valid_candidate = pypi_version_is_stable(version)
                || (allow_prerelease && pypi_version_is_prerelease(version));
            valid_candidate && !pypi_release_is_yanked(files)
        })
        .map(|(version, _)| version.as_str())
        .max_by(|a, b| compare_versions(Ecosystem::PyPI, a, b))
        .map(str::to_owned)
}

fn pypi_release_is_yanked(files: &Value) -> bool {
    files.as_array().is_some_and(|files| {
        !files.is_empty()
            && files
                .iter()
                .all(|file| file.get("yanked").and_then(Value::as_bool).unwrap_or(false))
    })
}

fn is_prerelease(eco: Ecosystem, version: &str) -> bool {
    match eco {
        Ecosystem::Npm | Ecosystem::CratesIo => version.contains('-'),
        Ecosystem::NuGet => {
            NuGetVersion::parse(version).is_ok_and(|version| version.is_prerelease())
        }
        Ecosystem::PyPI => pypi_version_is_prerelease(version),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CratesIndexEntry {
    name: String,
    vers: String,
    yanked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CratesIndexCache {
    schema_version: u32,
    entries: Vec<CratesIndexEntry>,
}

fn invalid_sparse_index(source: &str, message: impl std::fmt::Display) -> ProviderError {
    ProviderError::InvalidResponse(format!("{source}: {message}"))
}

fn invalid_sparse_index_line(
    source: &str,
    line_number: usize,
    message: impl std::fmt::Display,
) -> ProviderError {
    invalid_sparse_index(
        source,
        format_args!("sparse-index line {line_number}: {message}"),
    )
}

fn validate_crates_index_entries<'a>(
    entries: impl IntoIterator<Item = (usize, &'a CratesIndexEntry)>,
    expected_name: &str,
    source: &str,
) -> Result<(), ProviderError> {
    let mut seen_versions: HashMap<&'a str, usize> = HashMap::new();
    let mut entry_count = 0_usize;

    for (line_number, entry) in entries {
        entry_count += 1;
        if !entry.name.eq_ignore_ascii_case(expected_name) {
            return Err(invalid_sparse_index_line(
                source,
                line_number,
                format_args!(
                    "crate name {:?} does not match requested crate {expected_name:?}",
                    entry.name
                ),
            ));
        }
        semver::Version::parse(&entry.vers).map_err(|error| {
            invalid_sparse_index_line(
                source,
                line_number,
                format_args!("field `vers` is not valid SemVer: {error}"),
            )
        })?;
        if let Some(first_line) = seen_versions.insert(&entry.vers, line_number) {
            return Err(invalid_sparse_index_line(
                source,
                line_number,
                format_args!(
                    "duplicate version {:?}; first declared on line {first_line}",
                    entry.vers
                ),
            ));
        }
    }

    if entry_count == 0 {
        return Err(invalid_sparse_index(
            source,
            "sparse index contains no version entries",
        ));
    }
    Ok(())
}

fn decode_crates_index(
    bytes: &[u8],
    expected_name: &str,
    source: &str,
) -> Result<Vec<CratesIndexEntry>, ProviderError> {
    if bytes.len() > CRATES_IO_MAX_INDEX_RESPONSE_BYTES {
        return Err(invalid_sparse_index(
            source,
            format_args!("response exceeds the {CRATES_IO_MAX_INDEX_RESPONSE_BYTES}-byte limit"),
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|error| {
        let line_number = bytes[..error.valid_up_to()]
            .iter()
            .filter(|&&byte| byte == b'\n')
            .count()
            + 1;
        invalid_sparse_index_line(source, line_number, "line is not valid UTF-8")
    })?;
    let mut parsed = Vec::new();

    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if line.is_empty() {
            continue;
        }
        if line.len() > CRATES_IO_MAX_INDEX_LINE_BYTES {
            return Err(invalid_sparse_index_line(
                source,
                line_number,
                format_args!("line exceeds the {CRATES_IO_MAX_INDEX_LINE_BYTES}-byte limit"),
            ));
        }
        let entry = serde_json::from_str::<CratesIndexEntry>(line).map_err(|error| {
            invalid_sparse_index_line(source, line_number, format_args!("invalid JSON: {error}"))
        })?;
        parsed.push((line_number, entry));
    }

    validate_crates_index_entries(
        parsed
            .iter()
            .map(|(line_number, entry)| (*line_number, entry)),
        expected_name,
        source,
    )?;
    Ok(parsed.into_iter().map(|(_, entry)| entry).collect())
}

fn validated_cached_crates_index(
    entry: &CacheLookup,
    expected_name: &str,
) -> Option<CratesIndexCache> {
    let cached = serde_json::from_value::<CratesIndexCache>(entry.value.clone()).ok()?;
    (cached.schema_version == CRATES_IO_INDEX_CACHE_SCHEMA_VERSION
        && validate_crates_index_entries(
            cached
                .entries
                .iter()
                .enumerate()
                .map(|(index, entry)| (index + 1, entry)),
            expected_name,
            "cached crates.io sparse index",
        )
        .is_ok())
    .then_some(cached)
}

#[derive(Clone)]
pub struct RegistryOffline {
    cache: Cache,
    now: DateTime<Utc>,
}

impl RegistryOffline {
    pub fn new(cache: Cache) -> Self {
        Self {
            cache,
            now: Utc::now(),
        }
    }

    fn cache_key(package: &Package) -> String {
        match package.ecosystem {
            Ecosystem::Npm => format!("npm:{}", package.name),
            Ecosystem::PyPI => format!("pypi:{}", package.name),
            Ecosystem::NuGet => nuget_registry_cache_key(package),
            Ecosystem::CratesIo => format!("crates:{}", package.name),
        }
    }

    fn cached_value_at(
        &self,
        package: &Package,
        now: DateTime<Utc>,
    ) -> Result<Value, ProviderError> {
        let key = Self::cache_key(package);
        if !self.cache.policy.read {
            return Err(ProviderError::Offline(format!(
                "registry metadata for {} is unknown because cache reads are disabled by --no-cache",
                package.display_name
            )));
        }
        let path = self.cache.filename("registry", &key);
        let namespace = path.parent().expect("registry cache path has a parent");
        let namespace_metadata = fs::symlink_metadata(namespace).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ProviderError::Offline(format!(
                    "registry metadata for {} is unknown because no cached entry exists",
                    package.display_name
                ))
            } else {
                ProviderError::Offline(format!(
                    "registry metadata for {} is unknown because the cache namespace cannot be inspected: {error}",
                    package.display_name
                ))
            }
        })?;
        if namespace_metadata.file_type().is_symlink() || !namespace_metadata.is_dir() {
            return Err(ProviderError::Offline(format!(
                "registry metadata for {} is unknown because the cache namespace is not a real directory",
                package.display_name
            )));
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ProviderError::Offline(format!(
                    "registry metadata for {} is unknown because no cached entry exists",
                    package.display_name
                ))
            } else {
                ProviderError::Offline(format!(
                    "registry metadata for {} is unknown because the cached entry cannot be inspected: {error}",
                    package.display_name
                ))
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ProviderError::Offline(format!(
                "registry metadata for {} is unknown because the cached entry is not a real regular file",
                package.display_name
            )));
        }
        let raw = fs::read_to_string(&path).map_err(|error| {
            ProviderError::Offline(format!(
                "registry metadata for {} is unknown because the cached entry cannot be read: {error}",
                package.display_name
            ))
        })?;
        let entry = serde_json::from_str::<CacheEntry>(&raw).map_err(|error| {
            ProviderError::Offline(format!(
                "registry metadata for {} is unknown because the cached entry is corrupt: {error}",
                package.display_name
            ))
        })?;
        if entry.stored_at > now {
            return Err(ProviderError::Offline(format!(
                "registry metadata for {} is unknown because its cache timestamp is in the future ({} > {})",
                package.display_name, entry.stored_at, now
            )));
        }
        let age = now - entry.stored_at;
        let max_age = self
            .cache
            .policy
            .max_age
            .unwrap_or_else(|| Duration::seconds(REGISTRY_TTL_SECS));
        if age > max_age {
            return Err(ProviderError::Offline(format!(
                "registry metadata for {} is unknown because the cached entry is stale ({} seconds old; maximum {} seconds)",
                package.display_name,
                age.num_seconds(),
                max_age.num_seconds()
            )));
        }
        Ok(entry.value)
    }

    fn latest_at(
        &self,
        package: &Package,
        now: DateTime<Utc>,
    ) -> Result<LatestVersions, ProviderError> {
        let value = self.cached_value_at(package, now)?;
        let result = (|| -> Result<LatestVersions, ProviderError> {
            match package.ecosystem {
                Ecosystem::Npm => npm_version_result(package, &value),
                Ecosystem::PyPI => pypi_version_result(package, &value),
                Ecosystem::NuGet => nuget_version_result(package, &value),
                Ecosystem::CratesIo => {
                    let cached =
                        serde_json::from_value::<CratesIndexCache>(value).map_err(|error| {
                            ProviderError::InvalidResponse(format!(
                                "cached crates.io sparse index has an invalid envelope: {error}"
                            ))
                        })?;
                    if cached.schema_version != CRATES_IO_INDEX_CACHE_SCHEMA_VERSION {
                        return Err(ProviderError::InvalidResponse(format!(
                            "cached crates.io schema version {} is unsupported",
                            cached.schema_version
                        )));
                    }
                    validate_crates_index_entries(
                        cached
                            .entries
                            .iter()
                            .enumerate()
                            .map(|(index, entry)| (index + 1, entry)),
                        &package.name,
                        "cached crates.io sparse index",
                    )?;
                    crates_version_result(package, &cached.entries)
                }
            }
        })();
        result.map_err(|error| {
            ProviderError::Offline(format!(
                "registry metadata for {} is unknown because the cached entry is invalid: {error}",
                package.display_name
            ))
        })
    }
}

#[async_trait]
impl VersionProvider for RegistryOffline {
    async fn latest(&self, package: &Package) -> Result<RegistryEnrichment, ProviderError> {
        self.latest_at(package, self.now)
            .map(RegistryEnrichment::versions_only)
    }
}

// crates.io sparse-index entries are newline-delimited JSON. Decode and validate the entire
// response before writing the versioned cache envelope, so a truncated response cannot be reused.
impl RegistryClient {
    async fn crates_metadata_for_index(
        &self,
        key: &str,
        expected_name: &str,
        url: &str,
    ) -> Result<Vec<CratesIndexEntry>, ProviderError> {
        let ttl = Duration::seconds(REGISTRY_TTL_SECS);
        let mut generation = self.cache.snapshot("registry", key, ttl);
        let mut force_revalidate = false;
        for _ in 0..CACHE_COMMIT_ATTEMPTS {
            let cached = self.cache.policy.read.then(|| {
                generation
                    .as_ref()
                    .and_then(|entry| validated_cached_crates_index(entry, expected_name))
            });
            let cached = cached.flatten();
            if !force_revalidate
                && let (Some(entry), Some(cached)) = (&generation, &cached)
                && entry.fresh
            {
                return Ok(cached.entries.clone());
            }
            force_revalidate = false;
            if cached.is_none() && generation.is_some() && self.cache.policy.read {
                debug!(%key, "ignoring legacy or invalid crates.io sparse-index cache entry");
            }
            let mut headers = HeaderMap::new();
            let conditional =
                add_if_none_match(&mut headers, cached.as_ref().and(generation.as_ref()));
            let response = self
                .http
                .get_bytes_limited_revalidated(url, CRATES_IO_MAX_INDEX_RESPONSE_BYTES, headers)
                .await?;
            match response {
                Revalidated::Modified { value: bytes, etag } => {
                    let entries = decode_crates_index(&bytes, expected_name, url)?;
                    let value = serde_json::to_value(CratesIndexCache {
                        schema_version: CRATES_IO_INDEX_CACHE_SCHEMA_VERSION,
                        entries: entries.clone(),
                    })
                    .map_err(|error| ProviderError::Cache(error.to_string()))?;
                    match self.cache.put_if_unchanged(
                        "registry",
                        key,
                        generation.as_ref(),
                        &value,
                        etag,
                        ttl,
                    )? {
                        CacheCommit::Written => return Ok(entries),
                        CacheCommit::Conflict(current) => {
                            generation = current;
                            force_revalidate = true;
                        }
                    }
                }
                Revalidated::NotModified { etag } => {
                    if !conditional {
                        return Err(ProviderError::InvalidResponse(format!(
                            "{url}: received HTTP 304 without sending If-None-Match"
                        )));
                    }
                    let cached = cached.ok_or_else(|| {
                        ProviderError::InvalidResponse(format!(
                            "{url}: received HTTP 304 without a valid cached sparse index"
                        ))
                    })?;
                    let snapshot = generation.as_ref().expect("conditional cache exists");
                    let value = snapshot.value.clone();
                    let etag = etag.or_else(|| snapshot.etag.clone());
                    match self.cache.put_if_unchanged(
                        "registry",
                        key,
                        Some(snapshot),
                        &value,
                        etag,
                        ttl,
                    )? {
                        CacheCommit::Written => return Ok(cached.entries),
                        CacheCommit::Conflict(current) => {
                            generation = current;
                            if self.cache.policy.read
                                && let Some(entry) = &generation
                                && entry.fresh
                                && let Some(current) =
                                    validated_cached_crates_index(entry, expected_name)
                            {
                                return Ok(current.entries);
                            }
                        }
                    }
                }
            }
        }
        Err(ProviderError::Cache(format!(
            "crates.io cache entry {key:?} changed repeatedly during revalidation"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Cursor, Write},
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt as TokioAsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::Notify,
        task::JoinHandle,
    };
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };
    use zip::write::SimpleFileOptions;

    const TEST_OSV_MODIFIED: &str = "2026-08-19T00:00:00Z";

    fn osv_query_vulnerability_at(id: &str, modified: &str) -> Value {
        json!({"id": id, "modified": modified})
    }

    fn osv_query_vulnerability(id: &str) -> Value {
        osv_query_vulnerability_at(id, TEST_OSV_MODIFIED)
    }

    fn read_cache_entry(cache: &Cache, namespace: &str, key: &str) -> CacheEntry {
        serde_json::from_str(
            &fs::read_to_string(cache.filename(namespace, key)).expect("read cache entry"),
        )
        .expect("decode cache entry")
    }

    fn write_cache_entry(cache: &Cache, namespace: &str, key: &str, entry: &CacheEntry) {
        let path = cache.filename(namespace, key);
        fs::create_dir_all(path.parent().unwrap()).expect("create cache namespace");
        fs::write(path, serde_json::to_vec(entry).unwrap()).expect("write cache entry");
    }

    fn age_cache_entry(cache: &Cache, namespace: &str, key: &str, age: Duration) {
        let mut entry = read_cache_entry(cache, namespace, key);
        entry.stored_at = Utc::now() - age;
        write_cache_entry(cache, namespace, key, &entry);
    }

    fn set_cache_entry_timestamp(
        cache: &Cache,
        namespace: &str,
        key: &str,
        stored_at: DateTime<Utc>,
    ) {
        let mut entry = read_cache_entry(cache, namespace, key);
        entry.stored_at = stored_at;
        write_cache_entry(cache, namespace, key, &entry);
    }

    fn test_timestamp(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn common_cache_freshness_rejects_future_timestamps_and_honors_boundaries() {
        fn entry(stored_at: DateTime<Utc>) -> CacheEntry {
            CacheEntry {
                stored_at,
                etag: None,
                value: Value::Null,
            }
        }

        let now = test_timestamp("2026-08-19T12:00:00Z");
        let ttl = Duration::hours(1);
        let cache = Cache {
            root: PathBuf::new(),
            policy: CachePolicy::default(),
        };

        assert!(cache.lookup_from_entry_at(entry(now), ttl, now).fresh);
        assert!(cache.lookup_from_entry_at(entry(now - ttl), ttl, now).fresh);
        assert!(
            !cache
                .lookup_from_entry_at(entry(now - ttl - Duration::nanoseconds(1)), ttl, now)
                .fresh
        );
        assert!(
            !cache
                .lookup_from_entry_at(entry(now + Duration::nanoseconds(1)), ttl, now)
                .fresh
        );

        let max_age = Duration::minutes(30);
        let strict = Cache {
            root: PathBuf::new(),
            policy: CachePolicy {
                read: true,
                max_age: Some(max_age),
            },
        };
        assert!(
            strict
                .lookup_from_entry_at(entry(now - max_age), ttl, now)
                .fresh
        );
        assert!(
            !strict
                .lookup_from_entry_at(entry(now - max_age - Duration::nanoseconds(1)), ttl, now,)
                .fresh
        );
        assert!(
            !strict
                .lookup_from_entry_at(entry(now + Duration::nanoseconds(1)), ttl, now)
                .fresh
        );
    }

    #[test]
    fn future_concurrent_winner_remains_a_non_reusable_cas_generation() {
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let ttl = Duration::hours(1);
        cache
            .put("registry", "future-conflict", &json!({"revision": 1}), None)
            .unwrap();
        let expected = cache
            .snapshot("registry", "future-conflict", ttl)
            .expect("initial cache generation");
        cache
            .put("registry", "future-conflict", &json!({"revision": 2}), None)
            .unwrap();
        set_cache_entry_timestamp(
            &cache,
            "registry",
            "future-conflict",
            Utc::now() + Duration::days(1),
        );

        let conflict = cache
            .put_if_unchanged(
                "registry",
                "future-conflict",
                Some(&expected),
                &json!({"revision": 3}),
                None,
                ttl,
            )
            .unwrap();

        let CacheCommit::Conflict(Some(current)) = conflict else {
            panic!("concurrent future entry must remain the raw conflict generation");
        };
        assert!(!current.fresh);
        assert_eq!(current.value, json!({"revision": 2}));
        assert_eq!(
            read_cache_entry(&cache, "registry", "future-conflict").value,
            current.value
        );
    }

    fn valid_offline_document(id: &str, details: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "id": id,
            "modified": TEST_OSV_MODIFIED,
            "details": details,
            "affected": []
        }))
        .unwrap()
    }

    fn valid_osv_document_value(id: &str, package: &Package) -> Value {
        json!({
            "schema_version": "1.7.4",
            "id": id,
            "modified": TEST_OSV_MODIFIED,
            "published": "2026-08-18T00:00:00Z",
            "aliases": ["CVE-2026-1234"],
            "related": ["TEST-RELATED-1"],
            "upstream": ["TEST-UPSTREAM-1"],
            "summary": "validated advisory",
            "details": "validation fixture",
            "severity": [{
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "source": "SELF"
            }],
            "affected": [{
                "package": {
                    "ecosystem": package.ecosystem.osv_name(),
                    "name": osv_query_name(package),
                    "purl": "pkg:generic/fixture@1.0.0"
                },
                "versions": [package.version],
                "ecosystem_specific": {},
                "database_specific": {}
            }],
            "references": [{
                "type": "ADVISORY",
                "url": "https://example.invalid/advisory"
            }],
            "database_specific": {}
        })
    }

    fn scan_offline_archive(
        archive_bytes: &[u8],
        limits: OsvDumpLimits,
    ) -> Result<VulnMap, ProviderError> {
        let directory = tempfile::tempdir().unwrap();
        let cache =
            Cache::from_root(directory.path().join("cache"), CachePolicy::default()).unwrap();
        let archive = cache.root().join("offline/npm.zip");
        fs::create_dir_all(archive.parent().unwrap()).unwrap();
        fs::write(&archive, archive_bytes).unwrap();
        fs::write(archive.with_extension("synced-at"), TEST_OSV_MODIFIED).unwrap();
        let provider = OsvOffline { cache, limits };
        let package = Package::new(
            Ecosystem::Npm,
            "offline-fixture",
            "1.0.0",
            PathBuf::from("package-lock.json"),
        );
        provider.query_blocking_at(
            std::slice::from_ref(&package),
            test_timestamp("2026-08-19T12:00:00Z"),
        )
    }

    #[test]
    fn offline_dump_age_handles_fresh_stale_missing_malformed_and_future_markers() {
        let directory = tempfile::tempdir().unwrap();
        let cache =
            Cache::from_root(directory.path().join("cache"), CachePolicy::default()).unwrap();
        let archive = cache.root().join("offline/npm.zip");
        fs::create_dir_all(archive.parent().unwrap()).unwrap();
        fs::write(&archive, b"archive fixture").unwrap();
        let marker = archive.with_extension("synced-at");
        let now = test_timestamp("2026-08-19T12:00:00Z");
        let provider = OsvOffline::new(cache.clone());

        fs::write(&marker, "2026-08-18T12:00:00Z").unwrap();
        assert_eq!(
            provider
                .validate_dump_age_at(&archive, Ecosystem::Npm, now)
                .unwrap(),
            OsvDumpAge::Current
        );

        fs::write(&marker, "2026-08-11T11:59:59Z").unwrap();
        assert!(matches!(
            provider
                .validate_dump_age_at(&archive, Ecosystem::Npm, now)
                .unwrap(),
            OsvDumpAge::Warn { age, .. } if age == Duration::seconds(8 * 24 * 60 * 60 + 1)
        ));

        let strict = OsvOffline::new(Cache {
            root: cache.root.clone(),
            policy: CachePolicy {
                read: true,
                max_age: Some(Duration::days(7)),
            },
        });
        let stale = strict
            .validate_dump_age_at(&archive, Ecosystem::Npm, now)
            .unwrap_err();
        assert!(stale.to_string().contains("exceeds --max-cache-age"));

        fs::remove_file(&marker).unwrap();
        let missing = provider
            .validate_dump_age_at(&archive, Ecosystem::Npm, now)
            .unwrap_err();
        assert!(missing.to_string().contains("missing OSV dump timestamp"));

        fs::write(&marker, "not-a-timestamp").unwrap();
        let malformed = provider
            .validate_dump_age_at(&archive, Ecosystem::Npm, now)
            .unwrap_err();
        assert!(malformed.to_string().contains("invalid OSV dump timestamp"));

        fs::write(&marker, "2026-08-19T12:00:01Z").unwrap();
        let future = provider
            .validate_dump_age_at(&archive, Ecosystem::Npm, now)
            .unwrap_err();
        assert!(future.to_string().contains("is in the future"));
    }

    #[test]
    fn offline_dump_rejects_malformed_utf8_schema_and_truncated_entries_with_context() {
        let limits = OsvDumpLimits::production();
        let cases = [
            (
                "malformed JSON",
                archive_with_entry("TEST-MALFORMED.json", br#"{not-json}"#),
                "valid UTF-8 JSON",
            ),
            (
                "truncated JSON entry",
                archive_with_entry("TEST-TRUNCATED.json", br#"{"id":"TEST-TRUNCATED""#),
                "valid UTF-8 JSON",
            ),
            (
                "invalid UTF-8",
                archive_with_entry("TEST-UTF8.json", &[0xff, 0xfe, 0xfd]),
                "valid UTF-8 JSON",
            ),
            (
                "schema-invalid object",
                archive_with_entry("TEST-SCHEMA.json", br#"{}"#),
                "not an OSV document",
            ),
            (
                "missing affected",
                archive_with_entry(
                    "TEST-MISSING-AFFECTED.json",
                    br#"{"id":"TEST-MISSING-AFFECTED","modified":"2026-08-19T00:00:00Z"}"#,
                ),
                "affected must be a present array",
            ),
            (
                "malformed package identity",
                archive_with_entry(
                    "TEST-MALFORMED-IDENTITY.json",
                    br#"{"id":"TEST-MALFORMED-IDENTITY","modified":"2026-08-19T00:00:00Z","affected":[{"package":{"ecosystem":"npm"},"versions":["1.0.0"]}]}"#,
                ),
                "package.name must be a string",
            ),
            (
                "null withdrawn",
                archive_with_entry(
                    "TEST-NULL-WITHDRAWN.json",
                    br#"{"id":"TEST-NULL-WITHDRAWN","modified":"2026-08-19T00:00:00Z","withdrawn":null,"affected":[]}"#,
                ),
                "withdrawn must be an RFC 3339 string",
            ),
            (
                "trailing data",
                archive_with_entry(
                    "TEST-TRAILING.json",
                    br#"{"id":"TEST-TRAILING","modified":"2026-08-19T00:00:00Z"} trailing"#,
                ),
                "valid UTF-8 JSON",
            ),
        ];

        for (case, archive, expected) in cases {
            let error = scan_offline_archive(&archive, limits).unwrap_err();
            let message = error.to_string();
            assert!(message.contains("npm.zip"), "{case}: {message}");
            assert!(message.contains("entry \"TEST-"), "{case}: {message}");
            assert!(message.contains(expected), "{case}: {message}");
        }

        let valid = valid_offline_document("TEST-TRUNCATED-ZIP", "fixture");
        let mut truncated_zip = archive_with_entry("TEST-TRUNCATED-ZIP.json", &valid);
        truncated_zip.truncate(truncated_zip.len() - 10);
        let error = scan_offline_archive(&truncated_zip, limits).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("npm.zip"), "{message}");
        assert!(message.contains("bad ZIP"), "{message}");
    }

    #[test]
    fn offline_dump_enforces_entry_aggregate_count_and_actual_decompression_limits() {
        let bomb = valid_offline_document("TEST-BOMB", &"x".repeat(8 * 1024));
        let bomb_archive = archive_with_entries(
            &[("TEST-BOMB.json", bomb.as_slice())],
            zip::CompressionMethod::Deflated,
        );
        let mut limits = OsvDumpLimits::production();
        limits.max_entry_bytes = 1024;
        let error = scan_offline_archive(&bomb_archive, limits).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("npm.zip"), "{message}");
        assert!(message.contains("TEST-BOMB.json"), "{message}");
        assert!(message.contains("declared uncompressed"), "{message}");

        let first = valid_offline_document("TEST-AGGREGATE-1", "first");
        let second = valid_offline_document("TEST-AGGREGATE-2", "second");
        let aggregate = archive_with_entries(
            &[
                ("TEST-AGGREGATE-1.json", first.as_slice()),
                ("TEST-AGGREGATE-2.json", second.as_slice()),
            ],
            zip::CompressionMethod::Stored,
        );
        limits = OsvDumpLimits::production();
        limits.max_uncompressed_bytes = first.len() as u64 + second.len() as u64 - 1;
        let error = scan_offline_archive(&aggregate, limits).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("declared uncompressed size"), "{message}");
        assert!(message.contains("TEST-AGGREGATE-2.json"), "{message}");

        limits = OsvDumpLimits::production();
        limits.max_entries = 1;
        let error = scan_offline_archive(&aggregate, limits).unwrap_err();
        assert!(error.to_string().contains("entry count exceeds 1"));

        limits = OsvDumpLimits::production();
        limits.max_compressed_bytes = aggregate.len() as u64 - 1;
        let error = scan_offline_archive(&aggregate, limits).unwrap_err();
        assert!(error.to_string().contains("compressed size exceeds"));

        let actual = valid_offline_document("TEST-ACTUAL", "forged declared size");
        let mut forged = archive_with_entry("TEST-ACTUAL.json", &actual);
        let central_header = forged
            .windows(4)
            .rposition(|window| window == b"PK\x01\x02")
            .unwrap();
        let forged_declared_size = u32::try_from(actual.len() - 2).unwrap();
        forged[central_header + 24..central_header + 28]
            .copy_from_slice(&forged_declared_size.to_le_bytes());
        limits = OsvDumpLimits::production();
        limits.max_entry_bytes = actual.len() as u64 - 1;
        let error = scan_offline_archive(&forged, limits).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("TEST-ACTUAL.json"), "{message}");
        assert!(message.contains("actual uncompressed"), "{message}");
    }

    #[test]
    fn offline_dump_accepts_a_valid_empty_ecosystem_archive() {
        let archive = archive_with_entries(&[], zip::CompressionMethod::Stored);
        let result = scan_offline_archive(&archive, OsvDumpLimits::production()).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.values().all(Vec::is_empty));
    }

    #[test]
    fn offline_registry_reuses_valid_cached_metadata_for_every_ecosystem() {
        let directory = tempfile::tempdir().unwrap();
        let cache =
            Cache::from_root(directory.path().join("cache"), CachePolicy::default()).unwrap();
        let provider = RegistryOffline::new(cache.clone());
        let now = test_timestamp("2026-08-19T12:00:00Z");
        let stored_at = now - Duration::hours(1);
        let fixtures = [
            (
                Package::new(
                    Ecosystem::Npm,
                    "npm-demo",
                    "1.0.0",
                    PathBuf::from("package-lock.json"),
                ),
                json!({"dist-tags": {"latest": "2.0.0"}}),
            ),
            (
                Package::new(
                    Ecosystem::PyPI,
                    "pypi-demo",
                    "1.0.0",
                    PathBuf::from("uv.lock"),
                ),
                json!({"releases": {
                    "1.0.0": [{"yanked": false}],
                    "2.0.0": [{"yanked": false}]
                }}),
            ),
            (
                Package::new(
                    Ecosystem::NuGet,
                    "NuGet.Demo",
                    "1.0.0",
                    PathBuf::from("packages.lock.json"),
                ),
                json!({"versions": ["1.0.0", "2.0.0"]}),
            ),
            (
                Package::new(
                    Ecosystem::CratesIo,
                    "crate-demo",
                    "1.0.0",
                    PathBuf::from("Cargo.lock"),
                ),
                json!({
                    "schema_version": CRATES_IO_INDEX_CACHE_SCHEMA_VERSION,
                    "entries": [
                        {"name": "crate-demo", "vers": "1.0.0", "yanked": false},
                        {"name": "crate-demo", "vers": "2.0.0", "yanked": false}
                    ]
                }),
            ),
        ];

        for (package, value) in fixtures {
            write_cache_entry(
                &cache,
                "registry",
                &RegistryOffline::cache_key(&package),
                &CacheEntry {
                    stored_at,
                    etag: None,
                    value,
                },
            );
            let latest = provider.latest_at(&package, now).unwrap();
            assert_eq!(latest.latest_stable, "2.0.0");
            assert_eq!(latest.staleness, depscan_core::Staleness::Major);
        }
    }

    #[test]
    fn offline_registry_reports_cache_age_and_integrity_failures_without_network() {
        let directory = tempfile::tempdir().unwrap();
        let cache =
            Cache::from_root(directory.path().join("cache"), CachePolicy::default()).unwrap();
        let now = test_timestamp("2026-08-19T12:00:00Z");
        let package = Package::new(
            Ecosystem::Npm,
            "offline-demo",
            "1.0.0",
            PathBuf::from("package-lock.json"),
        );
        let key = RegistryOffline::cache_key(&package);
        let value = json!({"dist-tags": {"latest": "2.0.0"}});

        write_cache_entry(
            &cache,
            "registry",
            &key,
            &CacheEntry {
                stored_at: now - Duration::days(2),
                etag: None,
                value: value.clone(),
            },
        );
        let default_provider = RegistryOffline::new(cache.clone());
        let stale = default_provider.latest_at(&package, now).unwrap_err();
        assert!(stale.to_string().contains("cached entry is stale"));

        let tolerant_provider = RegistryOffline::new(Cache {
            root: cache.root.clone(),
            policy: CachePolicy {
                read: true,
                max_age: Some(Duration::days(7)),
            },
        });
        assert_eq!(
            tolerant_provider
                .latest_at(&package, now)
                .unwrap()
                .latest_stable,
            "2.0.0"
        );

        let missing_package = Package::new(
            Ecosystem::Npm,
            "missing-demo",
            "1.0.0",
            PathBuf::from("package-lock.json"),
        );
        let missing = default_provider
            .latest_at(&missing_package, now)
            .unwrap_err();
        assert!(missing.to_string().contains("no cached entry exists"));

        let path = cache.filename("registry", &key);
        fs::write(&path, b"not JSON").unwrap();
        let corrupt = default_provider.latest_at(&package, now).unwrap_err();
        assert!(corrupt.to_string().contains("cached entry is corrupt"));

        write_cache_entry(
            &cache,
            "registry",
            &key,
            &CacheEntry {
                stored_at: now + Duration::seconds(1),
                etag: None,
                value,
            },
        );
        let future = default_provider.latest_at(&package, now).unwrap_err();
        assert!(future.to_string().contains("timestamp is in the future"));

        let disabled = RegistryOffline::new(Cache {
            root: cache.root.clone(),
            policy: CachePolicy {
                read: false,
                max_age: None,
            },
        })
        .latest_at(&package, now)
        .unwrap_err();
        assert!(disabled.to_string().contains("disabled by --no-cache"));
    }

    #[test]
    fn owned_cache_clear_removes_only_known_cache_contents() {
        let temp = tempfile::tempdir().unwrap();
        let requested = temp.path().join("owned-cache");
        let cache = Cache::from_root(requested, CachePolicy::default()).unwrap();
        cache
            .put("registry", "fixture", &json!({"ok": true}), None)
            .unwrap();
        cache.put("osv/query", "fixture", &json!([]), None).unwrap();
        fs::create_dir_all(cache.root().join("offline")).unwrap();
        fs::write(cache.root().join("offline/npm.zip"), b"fixture").unwrap();
        fs::write(cache.root().join("unrelated.txt"), b"preserve me").unwrap();

        cache.clear().unwrap();

        for directory in CACHE_CONTENT_DIRECTORIES {
            assert!(!cache.root().join(directory).exists());
        }
        assert!(cache.root().join(CACHE_SENTINEL_FILE).is_file());
        assert_eq!(
            fs::read(cache.root().join("unrelated.txt")).unwrap(),
            b"preserve me"
        );
        cache.clear().unwrap();
    }

    #[test]
    fn cache_initialization_rejects_empty_broad_and_nonowned_paths() {
        let empty = Cache::from_root(PathBuf::new(), CachePolicy::default()).unwrap_err();
        assert!(empty.to_string().contains("empty cache directory"));

        let current = fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        let filesystem_root = current.ancestors().last().unwrap();
        let broad =
            Cache::from_root(filesystem_root.to_path_buf(), CachePolicy::default()).unwrap_err();
        assert!(broad.to_string().contains("filesystem roots"));
        assert!(
            validate_cache_scope_with(&current, &current, None)
                .unwrap_err()
                .to_string()
                .contains("current workspace")
        );

        let temp = tempfile::tempdir().unwrap();
        let fake_home = fs::canonicalize(temp.path()).unwrap();
        assert!(
            validate_cache_scope_with(&fake_home, &current, Some(fake_home.as_path()),)
                .unwrap_err()
                .to_string()
                .contains("home directory")
        );
        let nonowned = temp.path().join("nonowned");
        fs::create_dir(&nonowned).unwrap();
        let unrelated = nonowned.join("important.txt");
        fs::write(&unrelated, b"do not delete").unwrap();

        let error = Cache::from_root(nonowned.clone(), CachePolicy::default()).unwrap_err();

        assert!(error.to_string().contains("non-empty"));
        assert_eq!(fs::read(&unrelated).unwrap(), b"do not delete");
        assert!(!nonowned.join(CACHE_SENTINEL_FILE).exists());
    }

    #[test]
    fn cache_initialization_canonicalizes_safe_path_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let alias_component = temp.path().join("alias");
        fs::create_dir(&alias_component).unwrap();
        let requested = alias_component.join("..").join("cache");

        let cache = Cache::from_root(requested, CachePolicy::default()).unwrap();

        assert_eq!(
            cache.root(),
            fs::canonicalize(temp.path().join("cache")).unwrap()
        );
        assert!(cache.root().join(CACHE_SENTINEL_FILE).is_file());
    }

    #[test]
    fn exact_default_cache_layout_can_be_migrated_to_the_ownership_sentinel() {
        let temp = tempfile::tempdir().unwrap();
        let legacy = temp.path().join("legacy-default-cache");
        fs::create_dir_all(legacy.join("osv/query")).unwrap();
        fs::create_dir(legacy.join("registry")).unwrap();
        fs::write(legacy.join("osv/query/fixture.json"), b"{}").unwrap();

        let migrated = initialize_cache_root(&legacy, true).unwrap();

        assert!(migrated.join(CACHE_SENTINEL_FILE).is_file());
        assert!(migrated.join("osv/query/fixture.json").is_file());

        let unrelated = temp.path().join("unrelated-default-cache");
        fs::create_dir(&unrelated).unwrap();
        fs::write(unrelated.join("important.txt"), b"preserve").unwrap();
        let error = initialize_cache_root(&unrelated, true).unwrap_err();
        assert!(error.to_string().contains("non-empty"));
        assert_eq!(
            fs::read(unrelated.join("important.txt")).unwrap(),
            b"preserve"
        );
        assert!(!unrelated.join(CACHE_SENTINEL_FILE).exists());
    }

    #[test]
    fn missing_or_invalid_cache_sentinel_refuses_clear_without_deleting_data() {
        let temp = tempfile::tempdir().unwrap();
        let cache =
            Cache::from_root(temp.path().join("owned-cache"), CachePolicy::default()).unwrap();
        cache
            .put("registry", "fixture", &json!({"preserve": true}), None)
            .unwrap();
        let registry = cache.root().join("registry");
        fs::remove_file(cache.root().join(CACHE_SENTINEL_FILE)).unwrap();

        let missing = cache.clear().unwrap_err();

        assert!(missing.to_string().contains("missing ownership sentinel"));
        assert!(registry.is_dir());
        fs::write(
            cache.root().join(CACHE_SENTINEL_FILE),
            br#"{"schema_version":2,"owner":"depscan"}"#,
        )
        .unwrap();
        let invalid = cache.clear().unwrap_err();
        assert!(invalid.to_string().contains("unsupported owner or schema"));
        assert!(registry.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_swaps_and_symlinked_cache_content_are_refused_without_deletion() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let requested = temp.path().join("owned-cache");
        let cache = Cache::from_root(requested.clone(), CachePolicy::default()).unwrap();
        cache
            .put("registry", "fixture", &json!({"preserve": true}), None)
            .unwrap();
        let backup = temp.path().join("owned-cache-backup");
        fs::rename(cache.root(), &backup).unwrap();
        let replacement = Cache::from_root(
            temp.path().join("replacement-cache"),
            CachePolicy::default(),
        )
        .unwrap();
        replacement
            .put("registry", "victim", &json!({"important": true}), None)
            .unwrap();
        symlink(replacement.root(), &requested).unwrap();

        let swapped = cache.clear().unwrap_err();

        assert!(swapped.to_string().contains("replaced or is not real"));
        assert!(replacement.root().join("registry").is_dir());

        let content_cache =
            Cache::from_root(temp.path().join("content-cache"), CachePolicy::default()).unwrap();
        fs::create_dir(content_cache.root().join("offline")).unwrap();
        fs::write(content_cache.root().join("offline/preserve.zip"), b"keep").unwrap();
        let external = temp.path().join("external-registry");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("important.txt"), b"keep").unwrap();
        symlink(&external, content_cache.root().join("registry")).unwrap();

        let content_swap = content_cache.clear().unwrap_err();

        assert!(content_swap.to_string().contains("not a real directory"));
        assert!(content_cache.root().join("offline/preserve.zip").is_file());
        assert!(external.join("important.txt").is_file());
    }

    #[derive(Debug, Deserialize)]
    struct OsvRangeFixture {
        name: String,
        ecosystem: String,
        package: String,
        installed: String,
        affected: bool,
        fixed_in: Vec<String>,
        document: Value,
    }

    fn osv_range_fixtures() -> Vec<OsvRangeFixture> {
        serde_json::from_str(include_str!("../../../fixtures/osv-range-cases.json")).unwrap()
    }

    fn fixture_package(fixture: &OsvRangeFixture) -> Package {
        let ecosystem = Ecosystem::from_cli(&fixture.ecosystem).unwrap();
        Package::new(
            ecosystem,
            &fixture.package,
            &fixture.installed,
            PathBuf::from("fixture.lock"),
        )
    }

    fn write_fixture_archives(root: &Path, fixtures: &[OsvRangeFixture]) {
        let offline_dir = root.join("offline");
        fs::create_dir_all(&offline_dir).unwrap();
        for ecosystem in [
            Ecosystem::Npm,
            Ecosystem::PyPI,
            Ecosystem::NuGet,
            Ecosystem::CratesIo,
        ] {
            let file = File::create(
                offline_dir.join(format!("{}.zip", ecosystem.osv_name().replace('.', "_"))),
            )
            .unwrap();
            let mut archive = zip::ZipWriter::new(file);
            for fixture in fixtures
                .iter()
                .filter(|fixture| Ecosystem::from_cli(&fixture.ecosystem) == Some(ecosystem))
            {
                let id = fixture.document.get("id").and_then(Value::as_str).unwrap();
                let mut document = fixture.document.clone();
                document
                    .as_object_mut()
                    .unwrap()
                    .insert("modified".to_owned(), json!(TEST_OSV_MODIFIED));
                archive
                    .start_file(format!("{id}.json"), SimpleFileOptions::default())
                    .unwrap();
                archive
                    .write_all(serde_json::to_string(&document).unwrap().as_bytes())
                    .unwrap();
            }
            archive.finish().unwrap();
            fs::write(
                offline_dir.join(format!(
                    "{}.synced-at",
                    ecosystem.osv_name().replace('.', "_")
                )),
                Utc::now().to_rfc3339(),
            )
            .unwrap();
        }
    }

    enum RawResponseBody {
        Fixed(Vec<u8>),
        Truncated {
            body: Vec<u8>,
            bytes_to_send: usize,
        },
        Chunked {
            body: Vec<u8>,
            chunk_size: usize,
            delay: StdDuration,
            pause_after_chunks: Option<usize>,
            paused: Option<Arc<Notify>>,
            resume: Option<Arc<Notify>>,
        },
    }

    struct RawResponse {
        status: u16,
        retry_after: Option<String>,
        body: RawResponseBody,
    }

    impl RawResponse {
        fn fixed(status: u16, body: Vec<u8>) -> Self {
            Self {
                status,
                retry_after: None,
                body: RawResponseBody::Fixed(body),
            }
        }

        fn truncated(body: Vec<u8>, bytes_to_send: usize) -> Self {
            Self {
                status: 200,
                retry_after: None,
                body: RawResponseBody::Truncated {
                    body,
                    bytes_to_send,
                },
            }
        }
    }

    async fn read_raw_request(stream: &mut TcpStream) -> std::io::Result<()> {
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.len() > 64 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "test request headers are too large",
                ));
            }
        }
        Ok(())
    }

    async fn write_raw_response(
        stream: &mut TcpStream,
        response: RawResponse,
    ) -> std::io::Result<()> {
        let reason = match response.status {
            200 => "OK",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "Test Response",
        };
        let retry_after = response
            .retry_after
            .map(|value| format!("Retry-After: {value}\r\n"))
            .unwrap_or_default();
        match response.body {
            RawResponseBody::Fixed(body) => {
                let headers = format!(
                    "HTTP/1.1 {} {}\r\nConnection: close\r\n{}Content-Length: {}\r\n\r\n",
                    response.status,
                    reason,
                    retry_after,
                    body.len()
                );
                stream.write_all(headers.as_bytes()).await?;
                stream.write_all(&body).await?;
            }
            RawResponseBody::Truncated {
                body,
                bytes_to_send,
            } => {
                let headers = format!(
                    "HTTP/1.1 {} {}\r\nConnection: close\r\n{}Content-Length: {}\r\n\r\n",
                    response.status,
                    reason,
                    retry_after,
                    body.len()
                );
                stream.write_all(headers.as_bytes()).await?;
                stream
                    .write_all(&body[..bytes_to_send.min(body.len())])
                    .await?;
            }
            RawResponseBody::Chunked {
                body,
                chunk_size,
                delay,
                pause_after_chunks,
                paused,
                resume,
            } => {
                let headers = format!(
                    "HTTP/1.1 {} {}\r\nConnection: close\r\n{}Transfer-Encoding: chunked\r\n\r\n",
                    response.status, reason, retry_after
                );
                stream.write_all(headers.as_bytes()).await?;
                for (index, chunk) in body.chunks(chunk_size).enumerate() {
                    stream
                        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                        .await?;
                    stream.write_all(chunk).await?;
                    stream.write_all(b"\r\n").await?;
                    stream.flush().await?;
                    if pause_after_chunks == Some(index + 1) {
                        if let Some(paused) = &paused {
                            paused.notify_one();
                        }
                        if let Some(resume) = &resume {
                            resume.notified().await;
                        }
                    }
                    sleep(delay).await;
                }
                stream.write_all(b"0\r\n\r\n").await?;
            }
        }
        stream.flush().await
    }

    async fn spawn_raw_server(
        responses: Vec<RawResponse>,
    ) -> (String, Arc<AtomicUsize>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let server_requests = requests.clone();
        let handle = tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                server_requests.fetch_add(1, Ordering::SeqCst);
                if read_raw_request(&mut stream).await.is_ok() {
                    let _ = write_raw_response(&mut stream, response).await;
                }
            }
        });
        (format!("http://{address}"), requests, handle)
    }

    struct RecordingRetryRuntime {
        now: SystemTime,
        sleeps: Mutex<Vec<StdDuration>>,
        jitter_bounds: Mutex<Vec<StdDuration>>,
    }

    impl RecordingRetryRuntime {
        fn new(now: SystemTime) -> Self {
            Self {
                now,
                sleeps: Mutex::new(Vec::new()),
                jitter_bounds: Mutex::new(Vec::new()),
            }
        }

        fn sleeps(&self) -> Vec<StdDuration> {
            self.sleeps.lock().unwrap().clone()
        }

        fn jitter_bounds(&self) -> Vec<StdDuration> {
            self.jitter_bounds.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl RetryRuntime for RecordingRetryRuntime {
        fn now(&self) -> SystemTime {
            self.now
        }

        fn jitter(&self, upper_bound: StdDuration) -> StdDuration {
            self.jitter_bounds.lock().unwrap().push(upper_bound);
            StdDuration::ZERO
        }

        async fn sleep(&self, duration: StdDuration) {
            self.sleeps.lock().unwrap().push(duration);
        }
    }

    fn test_http_client(
        runtime: Arc<RecordingRetryRuntime>,
        request_timeout: StdDuration,
    ) -> HttpClient {
        HttpClient::with_retry_runtime(
            request_timeout,
            request_timeout,
            RetrySettings::default(),
            runtime,
        )
        .unwrap()
    }

    #[test]
    fn retry_status_classification_is_exact() {
        for code in 100..=599 {
            let status = StatusCode::from_u16(code).unwrap();
            assert_eq!(
                retryable_status(status),
                code == 429 || (500..=599).contains(&code),
                "unexpected retry classification for HTTP {code}"
            );
        }
    }

    #[test]
    fn production_network_budgets_match_the_documented_contract() {
        let http = HttpClient::new().unwrap();
        assert_eq!(http.request_timeout, StdDuration::from_secs(10));
        assert_eq!(http.retry_settings.attempts, 4);
        assert_eq!(
            http.retry_settings.backoff_base,
            StdDuration::from_millis(200)
        );
        assert_eq!(http.retry_settings.max_delay, StdDuration::from_secs(30));

        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let osv = OsvClient::new(http.clone(), cache.clone());
        assert_eq!(osv.concurrency.available_permits(), 16);
        let registries = RegistryClient::new(http, cache);
        assert_eq!(registries.limits[&Ecosystem::Npm].available_permits(), 16);
        assert_eq!(registries.limits[&Ecosystem::PyPI].available_permits(), 16);
        assert_eq!(registries.limits[&Ecosystem::NuGet].available_permits(), 16);
        assert_eq!(
            registries.limits[&Ecosystem::CratesIo].available_permits(),
            8
        );
    }

    #[test]
    fn retry_after_supports_delta_seconds_and_all_http_date_forms() {
        let now = SystemTime::UNIX_EPOCH + StdDuration::from_secs(1_800_000_000);
        let cap = StdDuration::from_secs(30);

        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("999999"));
        assert_eq!(retry_after_delay(&headers, now, cap), Some(cap));

        for date in [
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "Sun, 06 Nov 1994 08:49:37 GMT",
        ] {
            let parsed = httpdate::parse_http_date(date).unwrap();
            headers.insert(RETRY_AFTER, HeaderValue::from_str(date).unwrap());
            assert_eq!(
                retry_after_delay(&headers, parsed - StdDuration::from_secs(7), cap),
                Some(StdDuration::from_secs(7))
            );
        }

        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_str(&httpdate::fmt_http_date(now - StdDuration::from_secs(1)))
                .unwrap(),
        );
        assert_eq!(
            retry_after_delay(&headers, now, cap),
            Some(StdDuration::ZERO)
        );
        headers.insert(RETRY_AFTER, HeaderValue::from_static("not-a-date"));
        assert_eq!(retry_after_delay(&headers, now, cap), None);
    }

    #[tokio::test]
    async fn json_uses_one_attempt_plus_three_retries_without_a_final_sleep() {
        let responses = (0..HTTP_ATTEMPTS)
            .map(|_| RawResponse::fixed(500, Vec::new()))
            .collect();
        let (base_url, requests, server) = spawn_raw_server(responses).await;
        let runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
        let client = test_http_client(runtime.clone(), StdDuration::from_secs(1));

        let error = client
            .get_json(&format!("{base_url}/metadata"), HeaderMap::new())
            .await
            .unwrap_err();
        server.await.unwrap();

        assert_eq!(requests.load(Ordering::SeqCst), HTTP_ATTEMPTS);
        assert_eq!(
            runtime.sleeps(),
            vec![
                StdDuration::from_millis(200),
                StdDuration::from_millis(400),
                StdDuration::from_millis(800),
            ]
        );
        assert_eq!(
            runtime.jitter_bounds(),
            vec![
                StdDuration::from_millis(50),
                StdDuration::from_millis(100),
                StdDuration::from_millis(200),
            ]
        );
        assert!(error.to_string().contains("HTTP 500"));
        assert!(error.to_string().contains("attempt 4/4"));
    }

    #[tokio::test]
    async fn bounded_byte_stream_uses_one_attempt_plus_three_retries() {
        let responses = (0..HTTP_ATTEMPTS)
            .map(|_| RawResponse {
                status: 429,
                retry_after: Some("0".to_owned()),
                body: RawResponseBody::Fixed(Vec::new()),
            })
            .collect();
        let (base_url, requests, server) = spawn_raw_server(responses).await;
        let runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
        let client = test_http_client(runtime.clone(), StdDuration::from_secs(1));

        let error = client
            .get_bytes_limited_revalidated(&format!("{base_url}/bytes"), 1024, HeaderMap::new())
            .await
            .unwrap_err();
        server.await.unwrap();

        assert_eq!(requests.load(Ordering::SeqCst), HTTP_ATTEMPTS);
        assert_eq!(runtime.sleeps(), vec![StdDuration::ZERO; HTTP_MAX_RETRIES]);
        assert!(runtime.jitter_bounds().is_empty());
        assert!(error.to_string().contains("HTTP 429"));
        assert!(error.to_string().contains("attempt 4/4"));
    }

    #[tokio::test]
    async fn bounded_json_rejects_a_body_larger_than_its_decompressed_limit() {
        let body = serde_json::to_vec(&json!({"padding": "x".repeat(128)})).unwrap();
        let (base_url, requests, server) =
            spawn_raw_server(vec![RawResponse::fixed(200, body)]).await;
        let runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
        let client = test_http_client(runtime, StdDuration::from_secs(1));

        let error = client
            .get_json_limited_revalidated(&format!("{base_url}/metadata"), 64, HeaderMap::new())
            .await
            .unwrap_err();
        server.await.unwrap();

        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert!(
            error
                .to_string()
                .contains("response exceeds the 64-byte limit")
        );
    }

    #[tokio::test]
    async fn retry_after_delta_and_http_date_use_the_injected_clock_and_sleeper() {
        let now = SystemTime::UNIX_EPOCH + StdDuration::from_secs(1_800_000_000);
        let responses = vec![
            RawResponse {
                status: 429,
                retry_after: Some("999999".to_owned()),
                body: RawResponseBody::Fixed(Vec::new()),
            },
            RawResponse {
                status: 503,
                retry_after: Some(httpdate::fmt_http_date(now + StdDuration::from_secs(7))),
                body: RawResponseBody::Fixed(Vec::new()),
            },
            RawResponse::fixed(200, br#"{"ok":true}"#.to_vec()),
        ];
        let (base_url, requests, server) = spawn_raw_server(responses).await;
        let runtime = Arc::new(RecordingRetryRuntime::new(now));
        let client = test_http_client(runtime.clone(), StdDuration::from_secs(1));

        let (value, _) = client
            .get_json(&format!("{base_url}/metadata"), HeaderMap::new())
            .await
            .unwrap();
        server.await.unwrap();

        assert_eq!(value, json!({"ok": true}));
        assert_eq!(requests.load(Ordering::SeqCst), 3);
        assert_eq!(
            runtime.sleeps(),
            vec![StdDuration::from_secs(30), StdDuration::from_secs(7)]
        );
        assert!(runtime.jitter_bounds().is_empty());
    }

    #[tokio::test]
    async fn non_retryable_status_is_immediate_and_redacts_request_secrets() {
        let secret_body = b"super-secret-response".to_vec();
        let (base_url, requests, server) =
            spawn_raw_server(vec![RawResponse::fixed(400, secret_body)]).await;
        let authenticated_url = base_url.replacen("http://", "http://alice:password@", 1);
        let runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
        let client = test_http_client(runtime.clone(), StdDuration::from_secs(1));

        let error = client
            .get_json(
                &format!("{authenticated_url}/metadata?token=query-secret"),
                HeaderMap::new(),
            )
            .await
            .unwrap_err();
        server.await.unwrap();

        let message = error.to_string();
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert!(runtime.sleeps().is_empty());
        assert!(message.contains("HTTP 400"));
        for secret in ["alice", "password", "query-secret", "super-secret-response"] {
            assert!(
                !message.contains(secret),
                "error leaked {secret:?}: {message}"
            );
        }
    }

    #[tokio::test]
    async fn unavailable_endpoint_retries_with_platform_semantic_transport_detail() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unavailable = listener.local_addr().unwrap();
        drop(listener);
        let connect_runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
        let connect_client =
            test_http_client(connect_runtime.clone(), StdDuration::from_millis(50));
        let url = format!("http://alice:connect-secret@{unavailable}/metadata?token=query-secret");

        let connect_error = connect_client
            .get_json(&url, HeaderMap::new())
            .await
            .unwrap_err();
        let ProviderError::Network(message) = connect_error else {
            panic!("retryable transport failure did not return a network error")
        };
        assert_eq!(
            connect_runtime.sleeps(),
            vec![
                StdDuration::from_millis(200),
                StdDuration::from_millis(400),
                StdDuration::from_millis(800),
            ]
        );
        assert!(
            message.contains("connection failed") || message.contains("request timed out"),
            "retryable transport detail was not normalized: {message}"
        );
        assert!(message.contains("attempt 4/4"));
        assert!(message.starts_with(&request_context(&reqwest::Method::GET, &url)));
        for secret in ["alice", "connect-secret", "query-secret"] {
            assert!(
                !message.contains(secret),
                "error leaked {secret:?}: {message}"
            );
        }
    }

    #[tokio::test]
    async fn request_timeout_retries_every_attempt() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/slow"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(StdDuration::from_millis(100))
                    .set_body_json(json!({"ok": true})),
            )
            .expect(HTTP_ATTEMPTS as u64)
            .mount(&server)
            .await;
        let timeout_runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
        let timeout_client =
            test_http_client(timeout_runtime.clone(), StdDuration::from_millis(10));
        let timeout_error = timeout_client
            .get_json(&format!("{}/slow", server.uri()), HeaderMap::new())
            .await
            .unwrap_err();
        assert_eq!(
            timeout_runtime.sleeps(),
            vec![
                StdDuration::from_millis(200),
                StdDuration::from_millis(400),
                StdDuration::from_millis(800),
            ]
        );
        assert!(timeout_error.to_string().contains("timed out"));
        assert!(timeout_error.to_string().contains("attempt 4/4"));
        server.verify().await;
    }

    #[tokio::test]
    async fn request_builder_failure_is_immediate_and_redacted() {
        let builder_runtime = Arc::new(RecordingRetryRuntime::new(SystemTime::UNIX_EPOCH));
        let builder_client = test_http_client(builder_runtime.clone(), StdDuration::from_secs(1));
        let builder_error = builder_client
            .get_json("://builder-secret", HeaderMap::new())
            .await
            .unwrap_err();
        assert!(builder_runtime.sleeps().is_empty());
        assert!(builder_error.to_string().contains("attempt 1/4"));
        assert!(!builder_error.to_string().contains("builder-secret"));
    }

    fn dump_archive_bytes(payload_bytes: usize) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut archive = zip::ZipWriter::new(cursor);
        archive
            .start_file(
                "TEST-1.json",
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
            )
            .unwrap();
        archive
            .write_all(
                br#"{"id":"TEST-1","modified":"2026-08-19T00:00:00Z","affected":[],"details":""#,
            )
            .unwrap();
        archive.write_all(&vec![b'x'; payload_bytes]).unwrap();
        archive.write_all(br#""}"#).unwrap();
        archive.finish().unwrap().into_inner()
    }

    fn archive_with_entry(name: &str, contents: &[u8]) -> Vec<u8> {
        archive_with_entries(&[(name, contents)], zip::CompressionMethod::Stored)
    }

    fn archive_with_entries(
        entries: &[(&str, &[u8])],
        compression: zip::CompressionMethod,
    ) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut archive = zip::ZipWriter::new(cursor);
        for (name, contents) in entries {
            archive
                .start_file(
                    *name,
                    SimpleFileOptions::default().compression_method(compression),
                )
                .unwrap();
            archive.write_all(contents).unwrap();
        }
        archive.finish().unwrap().into_inner()
    }

    fn cache_for_sync(root: &Path) -> Cache {
        Cache::from_root(root.to_path_buf(), CachePolicy::default()).unwrap()
    }

    fn sync_paths(cache: &Cache) -> (PathBuf, PathBuf) {
        let archive = cache.root().join("offline/npm.zip");
        let marker = archive.with_extension("synced-at");
        (archive, marker)
    }

    fn seed_sync_files(cache: &Cache, archive_bytes: &[u8], marker: &str) {
        let (archive, synced_at) = sync_paths(cache);
        fs::create_dir_all(archive.parent().unwrap()).unwrap();
        fs::write(archive, archive_bytes).unwrap();
        fs::write(synced_at, marker).unwrap();
    }

    fn assert_no_sync_temps(cache: &Cache) {
        let offline = cache.root().join("offline");
        let temporary = fs::read_dir(offline)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        assert!(
            temporary.is_empty(),
            "temporary files remain: {temporary:?}"
        );
    }

    #[cfg(any(unix, windows))]
    #[derive(Debug)]
    enum NamespaceSwap {
        NotAttempted,
        Denied(NamespaceSwapDenial),
        Swapped { original: PathBuf, moved: PathBuf },
    }

    #[cfg(any(unix, windows))]
    #[derive(Debug)]
    enum FileNamespaceSwap {
        Denied(NamespaceSwapDenial),
        Swapped { original: PathBuf, moved: PathBuf },
    }

    #[cfg(any(unix, windows))]
    #[derive(Debug)]
    enum RegularNamespaceSwap {
        Denied(NamespaceSwapDenial),
        Swapped {
            original: PathBuf,
            moved: PathBuf,
            replacement: PathBuf,
        },
    }

    #[cfg(any(unix, windows))]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum NamespaceSwapStage {
        RenameOriginal,
        CreateSymlink,
        InstallReplacement,
    }

    #[cfg(any(unix, windows))]
    #[derive(Debug)]
    struct NamespaceSwapDenial {
        stage: NamespaceSwapStage,
        error: std::io::Error,
    }

    #[cfg(any(unix, windows))]
    fn expected_windows_namespace_swap_denial(
        stage: NamespaceSwapStage,
        raw_os_error: Option<i32>,
    ) -> bool {
        // Win32 errors returned by MoveFileExW/CreateSymbolicLinkW at the exact stages above.
        // Keep this phase-specific: an unexpected path/setup error must not masquerade as a
        // successful capability-lock test.
        const ERROR_ACCESS_DENIED: i32 = 5;
        const ERROR_SHARING_VIOLATION: i32 = 32;
        const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;

        matches!(
            (stage, raw_os_error),
            (
                NamespaceSwapStage::RenameOriginal,
                Some(ERROR_ACCESS_DENIED) | Some(ERROR_SHARING_VIOLATION)
            ) | (
                NamespaceSwapStage::CreateSymlink,
                Some(ERROR_ACCESS_DENIED) | Some(ERROR_PRIVILEGE_NOT_HELD)
            )
        )
    }

    #[cfg(windows)]
    fn restore_expected_windows_denial(denial: NamespaceSwapDenial, operation: &str) -> bool {
        assert!(
            expected_windows_namespace_swap_denial(denial.stage, denial.error.raw_os_error()),
            "unexpected Windows {operation} denial at {:?}: kind={:?}, raw_os_error={:?}, error={}",
            denial.stage,
            denial.error.kind(),
            denial.error.raw_os_error(),
            denial.error
        );
        false
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn windows_namespace_swap_denials_are_stage_and_code_specific() {
        for (stage, raw_os_error) in [
            (NamespaceSwapStage::RenameOriginal, 5),
            (NamespaceSwapStage::RenameOriginal, 32),
            (NamespaceSwapStage::CreateSymlink, 5),
            (NamespaceSwapStage::CreateSymlink, 1314),
        ] {
            assert!(expected_windows_namespace_swap_denial(
                stage,
                Some(raw_os_error)
            ));
        }

        for (stage, raw_os_error) in [
            (NamespaceSwapStage::RenameOriginal, 3),
            (NamespaceSwapStage::RenameOriginal, 33),
            (NamespaceSwapStage::RenameOriginal, 12345),
            (NamespaceSwapStage::CreateSymlink, 32),
            (NamespaceSwapStage::InstallReplacement, 5),
            (NamespaceSwapStage::InstallReplacement, 32),
            (NamespaceSwapStage::InstallReplacement, 1314),
        ] {
            assert!(!expected_windows_namespace_swap_denial(
                stage,
                Some(raw_os_error)
            ));
        }
        assert!(!expected_windows_namespace_swap_denial(
            NamespaceSwapStage::RenameOriginal,
            None
        ));
    }

    #[cfg(any(unix, windows))]
    #[derive(Debug)]
    enum OfflineReadSwap {
        Directory(NamespaceSwap),
        File(FileNamespaceSwap),
        Regular(RegularNamespaceSwap),
    }

    #[cfg(any(unix, windows))]
    #[derive(Debug, Clone, Copy)]
    enum OfflineReadSwapKind {
        Symlink,
        Regular,
    }

    #[cfg(any(unix, windows))]
    #[derive(Debug, Clone, Copy)]
    enum OfflineReadSwapTarget {
        Root,
        OfflineDirectory,
        Archive,
        Marker,
    }

    #[cfg(any(unix, windows))]
    fn create_directory_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(target, link)
        }
    }

    #[cfg(any(unix, windows))]
    fn remove_directory_symlink(path: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            fs::remove_file(path)
        }
        #[cfg(windows)]
        {
            fs::remove_dir(path)
        }
    }

    #[cfg(any(unix, windows))]
    fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link)
        }
    }

    #[cfg(any(unix, windows))]
    fn attempt_namespace_swap(original: &Path, moved: &Path, external: &Path) -> NamespaceSwap {
        match fs::rename(original, moved) {
            Ok(()) => match create_directory_symlink(external, original) {
                Ok(()) => NamespaceSwap::Swapped {
                    original: original.to_path_buf(),
                    moved: moved.to_path_buf(),
                },
                Err(error) => {
                    fs::rename(moved, original).expect("restore namespace after symlink denial");
                    NamespaceSwap::Denied(NamespaceSwapDenial {
                        stage: NamespaceSwapStage::CreateSymlink,
                        error,
                    })
                }
            },
            Err(error) => NamespaceSwap::Denied(NamespaceSwapDenial {
                stage: NamespaceSwapStage::RenameOriginal,
                error,
            }),
        }
    }

    #[cfg(any(unix, windows))]
    fn restore_namespace_swap(outcome: NamespaceSwap) -> bool {
        match outcome {
            NamespaceSwap::Swapped { original, moved } => {
                remove_directory_symlink(&original).expect("remove replacement directory link");
                fs::rename(moved, original).expect("restore original namespace");
                true
            }
            #[cfg(unix)]
            NamespaceSwap::Denied(denial) => {
                panic!(
                    "directory swap unexpectedly failed on Unix at {:?}: kind={:?}, raw_os_error={:?}, error={}",
                    denial.stage,
                    denial.error.kind(),
                    denial.error.raw_os_error(),
                    denial.error
                )
            }
            #[cfg(windows)]
            NamespaceSwap::Denied(denial) => {
                restore_expected_windows_denial(denial, "directory-swap")
            }
            NamespaceSwap::NotAttempted => panic!("the requested sync boundary was not reached"),
        }
    }

    #[cfg(any(unix, windows))]
    fn attempt_file_namespace_swap(
        original: &Path,
        moved: &Path,
        external: &Path,
    ) -> FileNamespaceSwap {
        match fs::rename(original, moved) {
            Ok(()) => match create_file_symlink(external, original) {
                Ok(()) => FileNamespaceSwap::Swapped {
                    original: original.to_path_buf(),
                    moved: moved.to_path_buf(),
                },
                Err(error) => {
                    fs::rename(moved, original).expect("restore file after symlink denial");
                    FileNamespaceSwap::Denied(NamespaceSwapDenial {
                        stage: NamespaceSwapStage::CreateSymlink,
                        error,
                    })
                }
            },
            Err(error) => FileNamespaceSwap::Denied(NamespaceSwapDenial {
                stage: NamespaceSwapStage::RenameOriginal,
                error,
            }),
        }
    }

    #[cfg(any(unix, windows))]
    fn attempt_regular_file_swap(
        original: &Path,
        moved: &Path,
        replacement: &Path,
    ) -> FileNamespaceSwap {
        match fs::rename(original, moved) {
            Ok(()) => match fs::rename(replacement, original) {
                Ok(()) => FileNamespaceSwap::Swapped {
                    original: original.to_path_buf(),
                    moved: moved.to_path_buf(),
                },
                Err(error) => {
                    fs::rename(moved, original).expect("restore file after replacement denial");
                    FileNamespaceSwap::Denied(NamespaceSwapDenial {
                        stage: NamespaceSwapStage::InstallReplacement,
                        error,
                    })
                }
            },
            Err(error) => FileNamespaceSwap::Denied(NamespaceSwapDenial {
                stage: NamespaceSwapStage::RenameOriginal,
                error,
            }),
        }
    }

    #[cfg(any(unix, windows))]
    fn restore_file_namespace_swap(outcome: FileNamespaceSwap) -> bool {
        match outcome {
            FileNamespaceSwap::Swapped { original, moved } => {
                fs::remove_file(&original).expect("remove replacement file link");
                fs::rename(moved, original).expect("restore original file");
                true
            }
            #[cfg(unix)]
            FileNamespaceSwap::Denied(denial) => {
                panic!(
                    "file swap unexpectedly failed on Unix at {:?}: kind={:?}, raw_os_error={:?}, error={}",
                    denial.stage,
                    denial.error.kind(),
                    denial.error.raw_os_error(),
                    denial.error
                )
            }
            #[cfg(windows)]
            FileNamespaceSwap::Denied(denial) => {
                restore_expected_windows_denial(denial, "file-swap")
            }
        }
    }

    #[cfg(any(unix, windows))]
    fn attempt_regular_namespace_swap(
        original: &Path,
        moved: &Path,
        replacement: &Path,
    ) -> RegularNamespaceSwap {
        match fs::rename(original, moved) {
            Ok(()) => match fs::rename(replacement, original) {
                Ok(()) => RegularNamespaceSwap::Swapped {
                    original: original.to_path_buf(),
                    moved: moved.to_path_buf(),
                    replacement: replacement.to_path_buf(),
                },
                Err(error) => {
                    fs::rename(moved, original).expect("restore object after replacement denial");
                    RegularNamespaceSwap::Denied(NamespaceSwapDenial {
                        stage: NamespaceSwapStage::InstallReplacement,
                        error,
                    })
                }
            },
            Err(error) => RegularNamespaceSwap::Denied(NamespaceSwapDenial {
                stage: NamespaceSwapStage::RenameOriginal,
                error,
            }),
        }
    }

    #[cfg(any(unix, windows))]
    fn restore_regular_namespace_swap(outcome: RegularNamespaceSwap) -> bool {
        match outcome {
            RegularNamespaceSwap::Swapped {
                original,
                moved,
                replacement,
            } => {
                fs::rename(&original, replacement).expect("restore replacement object");
                fs::rename(moved, original).expect("restore original object");
                true
            }
            #[cfg(unix)]
            RegularNamespaceSwap::Denied(denial) => {
                panic!(
                    "regular namespace swap unexpectedly failed on Unix at {:?}: kind={:?}, raw_os_error={:?}, error={}",
                    denial.stage,
                    denial.error.kind(),
                    denial.error.raw_os_error(),
                    denial.error
                )
            }
            #[cfg(windows)]
            RegularNamespaceSwap::Denied(denial) => {
                restore_expected_windows_denial(denial, "regular namespace-swap")
            }
        }
    }

    #[cfg(any(unix, windows))]
    fn seed_external_offline_read_cache(root: &Path, archive: &[u8], marker: &str) {
        fs::write(
            root.join(CACHE_SENTINEL_FILE),
            serde_json::to_vec(&expected_cache_sentinel()).unwrap(),
        )
        .unwrap();
        let offline = root.join("offline");
        fs::create_dir(&offline).unwrap();
        fs::write(offline.join("npm.zip"), archive).unwrap();
        fs::write(offline.join("npm.synced-at"), marker).unwrap();
    }

    #[cfg(any(unix, windows))]
    fn attempt_offline_read_swap(
        kind: OfflineReadSwapKind,
        target: OfflineReadSwapTarget,
        cache: &Cache,
        external_root: &Path,
    ) -> OfflineReadSwap {
        let offline = cache.root().join("offline");
        let external_offline = external_root.join("offline");
        if matches!(kind, OfflineReadSwapKind::Regular) {
            let (original, moved, replacement) = match target {
                OfflineReadSwapTarget::Root => {
                    let original = cache.root().to_path_buf();
                    let moved = original.parent().unwrap().join(format!(
                        "{}.ds064-read-held",
                        original.file_name().unwrap().to_string_lossy()
                    ));
                    (original, moved, external_root.to_path_buf())
                }
                OfflineReadSwapTarget::OfflineDirectory => (
                    offline.clone(),
                    cache.root().join("offline.ds064-read-held"),
                    external_offline.clone(),
                ),
                OfflineReadSwapTarget::Archive => (
                    offline.join("npm.zip"),
                    offline.join("npm.zip.ds064-read-held"),
                    external_offline.join("npm.zip"),
                ),
                OfflineReadSwapTarget::Marker => (
                    offline.join("npm.synced-at"),
                    offline.join("npm.synced-at.ds064-read-held"),
                    external_offline.join("npm.synced-at"),
                ),
            };
            return OfflineReadSwap::Regular(attempt_regular_namespace_swap(
                &original,
                &moved,
                &replacement,
            ));
        }

        match target {
            OfflineReadSwapTarget::Root => {
                let original = cache.root();
                let moved = original.parent().unwrap().join(format!(
                    "{}.ds047-read-held",
                    original.file_name().unwrap().to_string_lossy()
                ));
                OfflineReadSwap::Directory(attempt_namespace_swap(original, &moved, external_root))
            }
            OfflineReadSwapTarget::OfflineDirectory => {
                let moved = cache.root().join("offline.ds047-read-held");
                OfflineReadSwap::Directory(attempt_namespace_swap(
                    &offline,
                    &moved,
                    &external_offline,
                ))
            }
            OfflineReadSwapTarget::Archive => {
                let original = offline.join("npm.zip");
                let moved = offline.join("npm.zip.ds047-read-held");
                OfflineReadSwap::File(attempt_file_namespace_swap(
                    &original,
                    &moved,
                    &external_offline.join("npm.zip"),
                ))
            }
            OfflineReadSwapTarget::Marker => {
                let original = offline.join("npm.synced-at");
                let moved = offline.join("npm.synced-at.ds047-read-held");
                OfflineReadSwap::File(attempt_file_namespace_swap(
                    &original,
                    &moved,
                    &external_offline.join("npm.synced-at"),
                ))
            }
        }
    }

    #[cfg(any(unix, windows))]
    fn restore_offline_read_swap(outcome: OfflineReadSwap) -> bool {
        match outcome {
            OfflineReadSwap::Directory(outcome) => restore_namespace_swap(outcome),
            OfflineReadSwap::File(outcome) => restore_file_namespace_swap(outcome),
            OfflineReadSwap::Regular(outcome) => restore_regular_namespace_swap(outcome),
        }
    }

    #[cfg(any(unix, windows))]
    fn seed_external_sync_namespace(directory: &Path) {
        fs::create_dir_all(directory).unwrap();
        for (name, contents) in [
            ("npm.zip", b"external archive".as_slice()),
            ("npm.synced-at", b"external marker".as_slice()),
            (".npm.sync.lock", b"external lock".as_slice()),
            (".npm-victim.zip.tmp", b"external temp".as_slice()),
            (
                ".npm-victim.zip.rollback.tmp",
                b"external rollback".as_slice(),
            ),
        ] {
            fs::write(directory.join(name), contents).unwrap();
        }
    }

    #[cfg(any(unix, windows))]
    fn assert_external_sync_namespace_unchanged(directory: &Path) {
        let expected = BTreeMap::from([
            (
                ".npm-victim.zip.rollback.tmp",
                b"external rollback".as_slice(),
            ),
            (".npm-victim.zip.tmp", b"external temp".as_slice()),
            (".npm.sync.lock", b"external lock".as_slice()),
            ("npm.synced-at", b"external marker".as_slice()),
            ("npm.zip", b"external archive".as_slice()),
        ]);
        let actual = fs::read_dir(directory)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let name = entry.file_name().into_string().unwrap();
                let bytes = fs::read(entry.path()).unwrap();
                (name, bytes)
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(actual.len(), expected.len(), "external namespace changed");
        for (name, contents) in expected {
            assert_eq!(
                actual.get(name).map(Vec::as_slice),
                Some(contents),
                "external file {name:?} changed"
            );
        }
    }

    #[cfg(any(unix, windows))]
    async fn assert_sync_boundary_is_capability_confined(
        boundary: OsvSyncBoundary,
        response: Vec<u8>,
    ) {
        let expected_response = response.clone();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/npm/all.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(response))
            .mount(&server)
            .await;
        let cache_root = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_root.path());
        let previous = dump_archive_bytes(32);
        let previous_marker = "2000-01-01T00:00:00Z";
        seed_sync_files(&cache, &previous, previous_marker);
        let external = tempfile::tempdir().unwrap();
        seed_external_sync_namespace(external.path());
        let offline = cache.root().join("offline");
        let moved = cache.root().join("offline.ds047-held");
        let swap = Arc::new(Mutex::new(NamespaceSwap::NotAttempted));
        let hook_swap = swap.clone();
        let external_path = external.path().to_path_buf();
        let mut config = test_sync_config(server.uri());
        config.boundary_hook = Some(Arc::new(move |observed| {
            if observed == boundary {
                let mut outcome = hook_swap.lock().unwrap();
                if matches!(*outcome, NamespaceSwap::NotAttempted) {
                    *outcome = attempt_namespace_swap(&offline, &moved, &external_path);
                }
            }
        }));
        let client =
            HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1))
                .unwrap();

        let result = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config).await;
        let outcome = std::mem::replace(&mut *swap.lock().unwrap(), NamespaceSwap::NotAttempted);
        let swapped = restore_namespace_swap(outcome);

        if swapped || boundary == OsvSyncBoundary::BeforeHandledErrorCleanup {
            assert!(matches!(result, Err(ProviderError::Cache(_))));
            assert_eq!(fs::read(sync_paths(&cache).0).unwrap(), previous);
            assert_eq!(
                fs::read_to_string(sync_paths(&cache).1).unwrap(),
                previous_marker
            );
            assert_no_sync_temps(&cache);
        } else {
            result.expect("a denied Windows swap must preserve a valid sync");
            assert_eq!(fs::read(sync_paths(&cache).0).unwrap(), expected_response);
            assert_ne!(
                fs::read_to_string(sync_paths(&cache).1).unwrap(),
                previous_marker
            );
            assert_no_sync_temps(&cache);
        }
        assert_external_sync_namespace_unchanged(external.path());
    }

    fn test_sync_config(base_url: String) -> OsvSyncConfig {
        let mut config = OsvSyncConfig::new(OsvSyncOptions {
            transfer_timeout: StdDuration::from_secs(5),
        })
        .unwrap();
        config.base_url = base_url;
        config.max_download_bytes = 32 * 1024 * 1024;
        config.max_entry_bytes = 16 * 1024 * 1024;
        config.max_uncompressed_bytes = 64 * 1024 * 1024;
        config.max_entries = 100;
        config.backoff_base = StdDuration::from_millis(1);
        config.max_retry_delay = StdDuration::from_millis(5);
        config
    }

    struct TrackedChunk {
        bytes: Vec<u8>,
        live_bytes: Arc<AtomicUsize>,
    }

    impl TrackedChunk {
        fn new(size: usize, live_bytes: Arc<AtomicUsize>, peak_bytes: &AtomicUsize) -> Self {
            let live = live_bytes.fetch_add(size, Ordering::SeqCst) + size;
            peak_bytes.fetch_max(live, Ordering::SeqCst);
            Self {
                bytes: vec![b'x'; size],
                live_bytes,
            }
        }
    }

    impl AsRef<[u8]> for TrackedChunk {
        fn as_ref(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for TrackedChunk {
        fn drop(&mut self) {
            self.live_bytes
                .fetch_sub(self.bytes.len(), Ordering::SeqCst);
        }
    }

    async fn peak_live_stream_bytes(total_bytes: usize, chunk_bytes: usize) -> usize {
        assert_eq!(total_bytes % chunk_bytes, 0);
        let live_bytes = Arc::new(AtomicUsize::new(0));
        let peak_bytes = Arc::new(AtomicUsize::new(0));
        let chunks = stream::iter((0..total_bytes / chunk_bytes).map({
            let live_bytes = live_bytes.clone();
            let peak_bytes = peak_bytes.clone();
            move |_| {
                Ok::<_, std::io::Error>(TrackedChunk::new(
                    chunk_bytes,
                    live_bytes.clone(),
                    &peak_bytes,
                ))
            }
        }));
        let mut destination = tokio::io::sink();
        let mut config = test_sync_config("http://unused.test".to_owned());
        config.max_download_bytes = total_bytes as u64;
        let downloaded = stream_osv_dump_body(
            chunks,
            &mut destination,
            "http://unused.test/dump.zip",
            &config,
        )
        .await
        .unwrap();
        assert_eq!(downloaded, total_bytes as u64);
        assert_eq!(live_bytes.load(Ordering::SeqCst), 0);
        peak_bytes.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn streamed_dump_memory_is_bounded_by_chunk_size_not_archive_size() {
        let chunk_bytes = 64 * 1024;
        let small_peak = peak_live_stream_bytes(4 * 1024 * 1024, chunk_bytes).await;
        let large_peak = peak_live_stream_bytes(128 * 1024 * 1024, chunk_bytes).await;

        assert_eq!(small_peak, chunk_bytes);
        assert_eq!(large_peak, chunk_bytes);
    }

    #[tokio::test]
    async fn ecosystem_sync_lock_serializes_competing_writers() {
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_dir.path());
        let (_, first_lock) = acquire_osv_sync_lock(cache.root(), "npm").unwrap();
        let started = Arc::new(Notify::new());
        let waiter_started = started.clone();
        let root = cache.root().to_path_buf();
        let mut waiter = tokio::task::spawn_blocking(move || {
            waiter_started.notify_one();
            acquire_osv_sync_lock(&root, "npm")
        });

        started.notified().await;
        assert!(
            tokio::time::timeout(StdDuration::from_millis(50), &mut waiter)
                .await
                .is_err(),
            "a competing same-ecosystem sync acquired the lock early"
        );
        fs2::FileExt::unlock(&first_lock).unwrap();
        let (_, second_lock) = waiter.await.unwrap().unwrap();
        fs2::FileExt::unlock(&second_lock).unwrap();
    }

    #[tokio::test]
    async fn sync_removes_only_owned_abandoned_temporary_files() {
        let replacement = dump_archive_bytes(1024);
        let (base_url, requests, server) =
            spawn_raw_server(vec![RawResponse::fixed(200, replacement)]).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_dir.path());
        let offline = cache.root().join("offline");
        fs::create_dir(&offline).unwrap();
        for name in [
            ".npm-old.zip.tmp",
            ".npm-old.synced-at.tmp",
            ".npm-old.zip.rollback.tmp",
            ".npm-old.zip.tmp.keep",
            ".npmx-old.zip.tmp",
            ".pypi-old.zip.tmp",
            "unrelated.tmp",
        ] {
            fs::write(offline.join(name), b"stale fixture").unwrap();
        }
        let client =
            HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1))
                .unwrap();
        let config = test_sync_config(base_url);

        sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
            .await
            .unwrap();
        server.await.unwrap();

        assert_eq!(requests.load(Ordering::SeqCst), 1);
        for name in [
            ".npm-old.zip.tmp",
            ".npm-old.synced-at.tmp",
            ".npm-old.zip.rollback.tmp",
        ] {
            assert!(!offline.join(name).exists(), "{name} was not reclaimed");
        }
        for name in [
            ".npm-old.zip.tmp.keep",
            ".npmx-old.zip.tmp",
            ".pypi-old.zip.tmp",
            "unrelated.tmp",
        ] {
            assert!(offline.join(name).is_file(), "{name} was removed");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sync_refuses_a_symlinked_offline_namespace_without_external_writes() {
        use std::os::unix::fs::symlink;

        let cache_dir = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_dir.path());
        let external = tempfile::tempdir().unwrap();
        let important = external.path().join("important.txt");
        fs::write(&important, b"preserve").unwrap();
        symlink(external.path(), cache.root().join("offline")).unwrap();
        let client = HttpClient::new().unwrap();
        let config = test_sync_config("http://127.0.0.1:9".to_owned());

        let error = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
            .await
            .unwrap_err();

        assert!(matches!(error, ProviderError::Cache(_)));
        assert_eq!(fs::read(important).unwrap(), b"preserve");
        assert!(!external.path().join("npm.zip").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sync_refuses_a_cache_root_swapped_to_a_symlink() {
        use std::os::unix::fs::symlink;

        let cache_dir = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_dir.path());
        let original = cache.root().to_path_buf();
        let moved = original.with_extension("owned-before-swap");
        let external = tempfile::tempdir().unwrap();
        let important = external.path().join("important.txt");
        fs::write(&important, b"preserve").unwrap();
        fs::rename(&original, &moved).unwrap();
        symlink(external.path(), &original).unwrap();
        let client = HttpClient::new().unwrap();
        let config = test_sync_config("http://127.0.0.1:9".to_owned());

        let result = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config).await;
        fs::remove_file(&original).unwrap();
        fs::rename(&moved, &original).unwrap();

        assert!(matches!(result, Err(ProviderError::Cache(_))));
        assert_eq!(fs::read(important).unwrap(), b"preserve");
        assert!(!external.path().join("npm.zip").exists());
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn capability_relative_sync_confines_every_publication_and_cleanup_boundary() {
        let valid = dump_archive_bytes(1024);
        for boundary in [
            OsvSyncBoundary::AfterTemporaryCreation,
            OsvSyncBoundary::BeforeValidation,
            OsvSyncBoundary::BeforeRollbackStaging,
            OsvSyncBoundary::BeforeArchivePublication,
            OsvSyncBoundary::BeforeMarkerPublication,
        ] {
            assert_sync_boundary_is_capability_confined(boundary, valid.clone()).await;
        }
        assert_sync_boundary_is_capability_confined(
            OsvSyncBoundary::BeforeHandledErrorCleanup,
            b"not a zip archive".to_vec(),
        )
        .await;
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn capability_relative_sync_confines_a_cache_root_swap() {
        let replacement = dump_archive_bytes(1024);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/npm/all.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(replacement.clone()))
            .mount(&server)
            .await;
        let cache_root = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_root.path());
        let previous = dump_archive_bytes(32);
        seed_sync_files(&cache, &previous, "2000-01-01T00:00:00Z");
        let external = tempfile::tempdir().unwrap();
        seed_external_sync_namespace(external.path());
        let original = cache.root().to_path_buf();
        let moved = original.parent().unwrap().join(format!(
            "{}.ds047-held",
            original.file_name().unwrap().to_string_lossy()
        ));
        let swap = Arc::new(Mutex::new(NamespaceSwap::NotAttempted));
        let hook_swap = swap.clone();
        let external_path = external.path().to_path_buf();
        let mut config = test_sync_config(server.uri());
        config.boundary_hook = Some(Arc::new(move |boundary| {
            if boundary == OsvSyncBoundary::AfterTemporaryCreation {
                let mut outcome = hook_swap.lock().unwrap();
                if matches!(*outcome, NamespaceSwap::NotAttempted) {
                    *outcome = attempt_namespace_swap(&original, &moved, &external_path);
                }
            }
        }));
        let client =
            HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1))
                .unwrap();

        let result = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config).await;
        let outcome = std::mem::replace(&mut *swap.lock().unwrap(), NamespaceSwap::NotAttempted);
        let swapped = restore_namespace_swap(outcome);

        if swapped {
            assert!(matches!(result, Err(ProviderError::Cache(_))));
            assert_eq!(fs::read(sync_paths(&cache).0).unwrap(), previous);
            assert_no_sync_temps(&cache);
        } else {
            result.expect("a denied Windows root swap must preserve a valid sync");
            assert_eq!(fs::read(sync_paths(&cache).0).unwrap(), replacement);
            assert_no_sync_temps(&cache);
        }
        assert_external_sync_namespace_unchanged(external.path());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn capability_relative_lock_and_abandoned_cleanup_ignore_replacement_namespace() {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Boundary {
            Lock,
            Cleanup,
        }

        for boundary in [Boundary::Lock, Boundary::Cleanup] {
            let cache_root = tempfile::tempdir().unwrap();
            let cache = cache_for_sync(cache_root.path());
            let offline = cache.root().join("offline");
            fs::create_dir(&offline).unwrap();
            fs::write(offline.join(".npm-victim.zip.tmp"), b"owned stale temp").unwrap();
            let moved = cache.root().join("offline.ds047-held");
            let external = tempfile::tempdir().unwrap();
            seed_external_sync_namespace(external.path());
            let swap = Arc::new(Mutex::new(NamespaceSwap::NotAttempted));
            let attempt = {
                let swap = swap.clone();
                let offline = offline.clone();
                let moved = moved.clone();
                let external = external.path().to_path_buf();
                Arc::new(move || {
                    let mut outcome = swap.lock().unwrap();
                    if matches!(*outcome, NamespaceSwap::NotAttempted) {
                        *outcome = attempt_namespace_swap(&offline, &moved, &external);
                    }
                })
            };
            let before_lock = attempt.clone();
            let before_cleanup = attempt.clone();

            let result = acquire_osv_sync_lock_with(
                cache.root(),
                "npm",
                move || {
                    if boundary == Boundary::Lock {
                        before_lock();
                    }
                },
                move || {
                    if boundary == Boundary::Cleanup {
                        before_cleanup();
                    }
                },
            );
            let outcome =
                std::mem::replace(&mut *swap.lock().unwrap(), NamespaceSwap::NotAttempted);
            let swapped = restore_namespace_swap(outcome);

            if swapped {
                assert!(matches!(result, Err(ProviderError::Cache(_))));
            } else {
                let (_, lock) =
                    result.expect("a denied Windows namespace swap must preserve lock acquisition");
                fs2::FileExt::unlock(&lock).unwrap();
            }
            if boundary == Boundary::Cleanup {
                assert!(
                    !offline.join(".npm-victim.zip.tmp").exists(),
                    "cleanup did not act through the held directory capability"
                );
            }
            assert_external_sync_namespace_unchanged(external.path());
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn capability_acquisition_revalidates_before_creating_the_offline_child() {
        let cache_root = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_root.path());
        let original = cache.root().to_path_buf();
        let moved = original.parent().unwrap().join(format!(
            "{}.ds047-acquire-held",
            original.file_name().unwrap().to_string_lossy()
        ));
        let external = tempfile::tempdir().unwrap();
        let swap = Arc::new(Mutex::new(NamespaceSwap::NotAttempted));
        let hook_swap = swap.clone();
        let hook_original = original.clone();
        let external_path = external.path().to_path_buf();

        let result = OfflineDirectory::open_with(&original, move || {
            *hook_swap.lock().unwrap() =
                attempt_namespace_swap(&hook_original, &moved, &external_path);
        });
        let outcome = std::mem::replace(&mut *swap.lock().unwrap(), NamespaceSwap::NotAttempted);
        let swapped = restore_namespace_swap(outcome);

        if swapped {
            assert!(matches!(result, Err(ProviderError::Cache(_))));
        } else {
            result.expect("a denied Windows root swap must preserve capability acquisition");
            assert!(original.join("offline").is_dir());
        }
        assert!(
            fs::read_dir(external.path()).unwrap().next().is_none(),
            "capability acquisition wrote into the replacement cache root"
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn cache_sentinel_regular_replacement_is_denied_or_detected() {
        let cache_root = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_root.path());
        let sentinel = cache.root().join(CACHE_SENTINEL_FILE);
        let moved = cache.root().join(".depscan-cache.original.json");
        let replacement = cache.root().join(".depscan-cache.replacement.json");
        let original_bytes = fs::read(&sentinel).unwrap();
        fs::write(&replacement, &original_bytes).unwrap();
        let root = CapDir::open_ambient_dir(cache.root(), ambient_authority()).unwrap();
        let mut outcome = None;

        let result = validate_capability_sentinel_with(&root, cache.root(), || {
            outcome = Some(attempt_regular_file_swap(&sentinel, &moved, &replacement));
        });
        let swapped = restore_file_namespace_swap(outcome.expect("replacement was attempted"));

        if swapped {
            assert!(matches!(result, Err(ProviderError::Cache(_))));
        } else {
            result.expect("denied replacement keeps the owned cache usable");
        }
        assert_eq!(fs::read(sentinel).unwrap(), original_bytes);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn capability_relative_offline_reads_reject_root_child_and_final_name_swaps() {
        let package = Package::new(
            Ecosystem::Npm,
            "read-capability",
            "1.0.0",
            PathBuf::from("package-lock.json"),
        );
        let document = serde_json::to_vec(&json!({
            "id": "TEST-READ-CAPABILITY",
            "modified": TEST_OSV_MODIFIED,
            "summary": "the original held archive contains this advisory",
            "affected": [{
                "package": {
                    "ecosystem": "npm",
                    "name": "read-capability"
                },
                "versions": ["1.0.0"]
            }]
        }))
        .unwrap();
        let vulnerable_archive = archive_with_entry("TEST-READ-CAPABILITY.json", &document);
        let empty_archive = archive_with_entries(&[], zip::CompressionMethod::Stored);
        let now = test_timestamp("2026-08-19T12:00:00Z");

        for (kind, target) in [OfflineReadSwapKind::Symlink, OfflineReadSwapKind::Regular]
            .into_iter()
            .flat_map(|kind| {
                [
                    OfflineReadSwapTarget::Root,
                    OfflineReadSwapTarget::OfflineDirectory,
                    OfflineReadSwapTarget::Archive,
                    OfflineReadSwapTarget::Marker,
                ]
                .into_iter()
                .map(move |target| (kind, target))
            })
        {
            let cache_root = tempfile::tempdir().unwrap();
            let cache = cache_for_sync(cache_root.path());
            seed_sync_files(&cache, &vulnerable_archive, TEST_OSV_MODIFIED);
            let provider = OsvOffline::new(cache.clone());
            let baseline = provider
                .query_blocking_at(std::slice::from_ref(&package), now)
                .unwrap();
            assert_eq!(
                baseline[&package.key()].len(),
                1,
                "original archive was not a vulnerable baseline for {target:?}"
            );

            let external = tempfile::tempdir().unwrap();
            seed_external_offline_read_cache(external.path(), &empty_archive, TEST_OSV_MODIFIED);
            let boundary = match target {
                OfflineReadSwapTarget::Archive => OsvOfflineReadBoundary::BeforeArchive,
                OfflineReadSwapTarget::Root
                | OfflineReadSwapTarget::OfflineDirectory
                | OfflineReadSwapTarget::Marker => OsvOfflineReadBoundary::BeforeMarker,
            };
            let swap = Arc::new(Mutex::new(None));
            let hook_swap = swap.clone();
            let hook_cache = cache.clone();
            let external_root = external.path().to_path_buf();

            let result = provider.query_blocking_at_with_hook(
                std::slice::from_ref(&package),
                now,
                move |observed| {
                    if observed == boundary {
                        let mut outcome = hook_swap.lock().unwrap();
                        if outcome.is_none() {
                            *outcome = Some(attempt_offline_read_swap(
                                kind,
                                target,
                                &hook_cache,
                                &external_root,
                            ));
                        }
                    }
                },
            );
            let outcome = swap
                .lock()
                .unwrap()
                .take()
                .expect("offline read did not reach the requested swap boundary");
            let swapped = restore_offline_read_swap(outcome);

            if swapped {
                assert!(
                    matches!(result, Err(ProviderError::Offline(_))),
                    "successful {kind:?} {target:?} swap did not fail the offline scan closed: {result:?}"
                );
            } else {
                let output = result.expect("a denied Windows swap must leave the scan usable");
                assert_eq!(
                    output[&package.key()].len(),
                    1,
                    "denied {kind:?} {target:?} swap produced a false-clean result"
                );
            }
            let (archive_path, marker_path) = sync_paths(&cache);
            assert_eq!(fs::read(archive_path).unwrap(), vulnerable_archive);
            assert_eq!(fs::read(marker_path).unwrap(), TEST_OSV_MODIFIED.as_bytes());
            assert_eq!(
                fs::read(external.path().join("offline/npm.zip")).unwrap(),
                empty_archive,
                "external empty archive changed during {kind:?} {target:?} swap"
            );
            assert_eq!(
                fs::read(external.path().join("offline/npm.synced-at")).unwrap(),
                TEST_OSV_MODIFIED.as_bytes(),
                "external marker changed during {kind:?} {target:?} swap"
            );
        }
    }

    #[tokio::test]
    async fn sync_streams_a_slow_large_dump_before_atomic_replacement() {
        let previous = dump_archive_bytes(32);
        let replacement = dump_archive_bytes(4 * 1024 * 1024);
        let paused = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        let response = RawResponse {
            status: 200,
            retry_after: None,
            body: RawResponseBody::Chunked {
                body: replacement.clone(),
                chunk_size: 64 * 1024,
                delay: StdDuration::from_millis(3),
                pause_after_chunks: Some(8),
                paused: Some(paused.clone()),
                resume: Some(resume.clone()),
            },
        };
        let (base_url, requests, server) = spawn_raw_server(vec![response]).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_dir.path());
        let previous_marker = "2000-01-01T00:00:00Z";
        seed_sync_files(&cache, &previous, previous_marker);
        let client =
            HttpClient::with_timeouts(StdDuration::from_secs(30), StdDuration::from_secs(30))
                .unwrap();
        let observed_chunk_bytes = Arc::new(AtomicUsize::new(0));
        let (stream_progress, mut streamed_bytes) = tokio::sync::watch::channel(0u64);
        let mut config = test_sync_config(base_url);
        config.transfer_timeout = StdDuration::from_secs(30);
        config.observed_max_chunk_bytes = Some(observed_chunk_bytes.clone());
        config.stream_progress = Some(stream_progress);
        let sync_cache = cache.clone();
        let sync = tokio::spawn(async move {
            sync_osv_dumps_with_config(&client, &sync_cache, &[Ecosystem::Npm], &config).await
        });

        tokio::time::timeout(StdDuration::from_secs(10), async {
            paused.notified().await;
            streamed_bytes
                .wait_for(|bytes| *bytes > 0)
                .await
                .expect("stream progress sender closed before the first write");
            let (archive_path, marker_path) = sync_paths(&cache);
            assert_eq!(fs::read(&archive_path).unwrap(), previous);
            assert_eq!(fs::read_to_string(&marker_path).unwrap(), previous_marker);
            let partial_size = *streamed_bytes.borrow_and_update();
            assert!(partial_size > 0);
            assert!(partial_size < replacement.len() as u64);
            assert!(
                fs::read_dir(cache.root().join("offline"))
                    .unwrap()
                    .filter_map(Result::ok)
                    .any(|entry| entry.file_name().to_string_lossy().ends_with(".zip.tmp")),
                "the client write did not target the held temporary file"
            );

            resume.notify_one();
            let paths = sync.await.unwrap().unwrap();
            server.await.unwrap();
            assert_eq!(paths, vec![archive_path.clone()]);
            assert_eq!(requests.load(Ordering::SeqCst), 1);
            assert!(observed_chunk_bytes.load(Ordering::SeqCst) > 0);
            assert!(observed_chunk_bytes.load(Ordering::SeqCst) < replacement.len());
            assert_eq!(fs::read(&archive_path).unwrap(), replacement);
            assert_ne!(fs::read_to_string(marker_path).unwrap(), previous_marker);
            assert_no_sync_temps(&cache);
        })
        .await
        .expect("slow stream did not complete the server/client/write/publication sequence");
    }

    #[tokio::test]
    async fn sync_retries_an_interrupted_body_from_an_empty_temp_file() {
        let previous = dump_archive_bytes(32);
        let replacement = dump_archive_bytes(256 * 1024);
        let responses = vec![
            RawResponse::truncated(replacement.clone(), replacement.len() / 2),
            RawResponse::fixed(200, replacement.clone()),
        ];
        let (base_url, requests, server) = spawn_raw_server(responses).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_dir.path());
        seed_sync_files(&cache, &previous, "2000-01-01T00:00:00Z");
        let client =
            HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1))
                .unwrap();
        let config = test_sync_config(base_url);

        sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
            .await
            .unwrap();
        server.await.unwrap();

        let (archive_path, _) = sync_paths(&cache);
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        assert_eq!(fs::read(archive_path).unwrap(), replacement);
        assert_no_sync_temps(&cache);
    }

    #[tokio::test]
    async fn sync_retries_429_and_5xx_with_both_retry_after_forms() {
        let replacement = dump_archive_bytes(1024);
        let now = SystemTime::UNIX_EPOCH + StdDuration::from_secs(1_800_000_000);
        let responses = vec![
            RawResponse {
                status: 429,
                retry_after: Some("999999".to_owned()),
                body: RawResponseBody::Fixed(Vec::new()),
            },
            RawResponse::fixed(500, Vec::new()),
            RawResponse {
                status: 503,
                retry_after: Some(httpdate::fmt_http_date(now + StdDuration::from_secs(20))),
                body: RawResponseBody::Fixed(Vec::new()),
            },
            RawResponse::fixed(200, replacement.clone()),
        ];
        let (base_url, requests, server) = spawn_raw_server(responses).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_dir.path());
        let runtime = Arc::new(RecordingRetryRuntime::new(now));
        let client = test_http_client(runtime.clone(), StdDuration::from_secs(1));
        let config = test_sync_config(base_url);

        sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
            .await
            .unwrap();
        server.await.unwrap();

        assert_eq!(requests.load(Ordering::SeqCst), HTTP_ATTEMPTS);
        assert_eq!(
            runtime.sleeps(),
            vec![
                StdDuration::from_millis(5),
                StdDuration::from_millis(2),
                StdDuration::from_millis(5),
            ]
        );
        assert_eq!(fs::read(sync_paths(&cache).0).unwrap(), replacement);
        assert_no_sync_temps(&cache);
    }

    #[tokio::test]
    async fn failed_interrupted_transfers_preserve_known_good_files_and_clean_temps() {
        let previous = dump_archive_bytes(32);
        let replacement = dump_archive_bytes(64 * 1024);
        let responses = (0..OSV_DUMP_ATTEMPTS)
            .map(|_| RawResponse::truncated(replacement.clone(), replacement.len() / 3))
            .collect();
        let (base_url, requests, server) = spawn_raw_server(responses).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_dir.path());
        let previous_marker = "2000-01-01T00:00:00Z";
        seed_sync_files(&cache, &previous, previous_marker);
        let client =
            HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1))
                .unwrap();
        let config = test_sync_config(base_url);

        let error = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
            .await
            .unwrap_err();
        server.await.unwrap();

        assert!(matches!(error, ProviderError::Network(_)));
        assert_eq!(requests.load(Ordering::SeqCst), OSV_DUMP_ATTEMPTS);
        let (archive_path, marker_path) = sync_paths(&cache);
        assert_eq!(fs::read(archive_path).unwrap(), previous);
        assert_eq!(fs::read_to_string(marker_path).unwrap(), previous_marker);
        assert_no_sync_temps(&cache);
    }

    #[tokio::test]
    async fn corrupt_zip_preserves_known_good_files_and_is_not_retried() {
        let previous = dump_archive_bytes(32);
        let corrupt = b"this is not a zip archive".to_vec();
        let (base_url, requests, server) =
            spawn_raw_server(vec![RawResponse::fixed(200, corrupt)]).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_dir.path());
        let previous_marker = "2000-01-01T00:00:00Z";
        seed_sync_files(&cache, &previous, previous_marker);
        let client =
            HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1))
                .unwrap();
        let config = test_sync_config(base_url);

        let error = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
            .await
            .unwrap_err();
        server.await.unwrap();

        assert!(matches!(error, ProviderError::InvalidResponse(_)));
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        let (archive_path, marker_path) = sync_paths(&cache);
        assert_eq!(fs::read(archive_path).unwrap(), previous);
        assert_eq!(fs::read_to_string(marker_path).unwrap(), previous_marker);
        assert_no_sync_temps(&cache);
    }

    #[tokio::test]
    async fn syntactically_valid_non_osv_json_preserves_known_good_files() {
        let previous = dump_archive_bytes(32);
        let invalid = archive_with_entry("TEST-1.json", b"{}");
        let (base_url, requests, server) =
            spawn_raw_server(vec![RawResponse::fixed(200, invalid)]).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_dir.path());
        let previous_marker = "2000-01-01T00:00:00Z";
        seed_sync_files(&cache, &previous, previous_marker);
        let client =
            HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1))
                .unwrap();
        let config = test_sync_config(base_url);

        let error = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
            .await
            .unwrap_err();
        server.await.unwrap();

        assert!(matches!(error, ProviderError::InvalidResponse(_)));
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        let (archive_path, marker_path) = sync_paths(&cache);
        assert_eq!(fs::read(archive_path).unwrap(), previous);
        assert_eq!(fs::read_to_string(marker_path).unwrap(), previous_marker);
        assert_no_sync_temps(&cache);
    }

    #[tokio::test]
    async fn rollback_staging_failure_leaves_the_previous_pair_untouched() {
        let previous = dump_archive_bytes(32);
        let replacement = dump_archive_bytes(1024);
        let (base_url, requests, server) =
            spawn_raw_server(vec![RawResponse::fixed(200, replacement)]).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_dir.path());
        let previous_marker = "2000-01-01T00:00:00Z";
        seed_sync_files(&cache, &previous, previous_marker);
        let client =
            HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1))
                .unwrap();
        let mut config = test_sync_config(base_url);
        config.force_rollback_staging_error = true;

        let error = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
            .await
            .unwrap_err();
        server.await.unwrap();

        assert!(matches!(error, ProviderError::Cache(_)));
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        let (archive_path, marker_path) = sync_paths(&cache);
        assert_eq!(fs::read(archive_path).unwrap(), previous);
        assert_eq!(fs::read_to_string(marker_path).unwrap(), previous_marker);
        assert_no_sync_temps(&cache);
    }

    #[tokio::test]
    async fn invalid_marker_target_is_rejected_before_download_or_replacement() {
        let previous = dump_archive_bytes(32);
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_dir.path());
        seed_sync_files(&cache, &previous, "2000-01-01T00:00:00Z");
        let (archive_path, marker_path) = sync_paths(&cache);
        fs::remove_file(&marker_path).unwrap();
        fs::create_dir(&marker_path).unwrap();
        let client =
            HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1))
                .unwrap();
        let config = test_sync_config("http://127.0.0.1:9".to_owned());

        let error = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
            .await
            .unwrap_err();

        assert!(matches!(error, ProviderError::Cache(_)));
        assert_eq!(fs::read(archive_path).unwrap(), previous);
        assert!(marker_path.is_dir());
        assert_no_sync_temps(&cache);
    }

    #[test]
    fn staged_backup_restores_a_replaced_archive_without_copying_after_failure() {
        let cache_root = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_root.path());
        let directory = OfflineDirectory::open(cache.root()).unwrap();
        let archive_name = OsStr::new("npm.zip");
        let archive = directory.display_path(archive_name);
        let previous = dump_archive_bytes(32);
        fs::write(&archive, &previous).unwrap();
        let backup = stage_previous_archive(&directory, archive_name, ".npm-")
            .unwrap()
            .unwrap();

        let mut replacement = CapabilityTempFile::new(&directory, ".npm-", ".zip.tmp").unwrap();
        replacement.write_all(&dump_archive_bytes(1024)).unwrap();
        replacement.as_file().sync_all().unwrap();
        replacement
            .persist(archive_name)
            .map_err(|error| error.source)
            .unwrap();
        restore_previous_archive(&directory, Some(backup), archive_name).unwrap();

        assert_eq!(fs::read(archive).unwrap(), previous);
    }

    #[test]
    fn failed_restore_retains_the_last_recovery_copy() {
        let cache_root = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_root.path());
        let directory = OfflineDirectory::open(cache.root()).unwrap();
        let archive_name = OsStr::new("npm.zip");
        let archive = directory.display_path(archive_name);
        let previous = dump_archive_bytes(32);
        fs::write(&archive, &previous).unwrap();
        let backup = stage_previous_archive(&directory, archive_name, ".npm-")
            .unwrap()
            .unwrap();
        fs::remove_file(&archive).unwrap();
        fs::create_dir(&archive).unwrap();

        let error = restore_previous_archive(&directory, Some(backup), archive_name).unwrap_err();
        let recovery_files = fs::read_dir(&directory.path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".zip.rollback.tmp")
            })
            .map(|entry| entry.path())
            .collect::<Vec<_>>();

        assert!(error.to_string().contains("rollback copy retained at"));
        assert_eq!(recovery_files.len(), 1);
        assert_eq!(fs::read(&recovery_files[0]).unwrap(), previous);
        assert!(archive.is_dir());
    }

    #[test]
    fn marker_publication_failure_exercises_pair_rollback() {
        let cache_root = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_root.path());
        let directory = OfflineDirectory::open(cache.root()).unwrap();
        let archive_name = OsStr::new("npm.zip");
        let marker_name = OsStr::new("npm.synced-at");
        let archive = directory.display_path(archive_name);
        let marker = directory.display_path(marker_name);
        let previous_archive = dump_archive_bytes(32);
        let previous_marker = b"2000-01-01T00:00:00Z";
        fs::write(&archive, &previous_archive).unwrap();
        fs::write(&marker, previous_marker).unwrap();
        let backup = stage_previous_archive(&directory, archive_name, ".npm-").unwrap();

        let mut archive_temp = CapabilityTempFile::new(&directory, ".npm-", ".zip.tmp").unwrap();
        archive_temp.write_all(&dump_archive_bytes(1024)).unwrap();
        archive_temp.as_file().sync_all().unwrap();
        let mut marker_temp =
            CapabilityTempFile::new(&directory, ".npm-", ".synced-at.tmp").unwrap();
        marker_temp.write_all(b"2026-08-19T00:00:00Z").unwrap();
        marker_temp.as_file().sync_all().unwrap();
        let marker_blocker = directory.path.join("marker-blocker");
        fs::create_dir(&marker_blocker).unwrap();

        let error = publish_osv_pair_with(
            &directory,
            archive_temp,
            marker_temp,
            OsvPairNames {
                archive: archive_name,
                marker: marker_name,
            },
            backup,
            || Ok(()),
            |temporary, _| persist_capability_temp(temporary, OsStr::new("marker-blocker")),
        )
        .unwrap_err();

        assert!(error.to_string().contains("restored previous archive"));
        assert_eq!(fs::read(&archive).unwrap(), previous_archive);
        assert_eq!(fs::read(&marker).unwrap(), previous_marker);
        let temporary = fs::read_dir(&directory.path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        assert!(
            temporary.is_empty(),
            "temporary files remain: {temporary:?}"
        );
    }

    #[tokio::test]
    async fn configurable_transfer_deadline_preserves_known_good_files() {
        let previous = dump_archive_bytes(32);
        let replacement = dump_archive_bytes(512 * 1024);
        let responses = (0..2)
            .map(|_| RawResponse {
                status: 200,
                retry_after: None,
                body: RawResponseBody::Chunked {
                    body: replacement.clone(),
                    chunk_size: 32 * 1024,
                    delay: StdDuration::from_millis(20),
                    pause_after_chunks: None,
                    paused: None,
                    resume: None,
                },
            })
            .collect();
        let (base_url, requests, server) = spawn_raw_server(responses).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = cache_for_sync(cache_dir.path());
        let previous_marker = "2000-01-01T00:00:00Z";
        seed_sync_files(&cache, &previous, previous_marker);
        let client =
            HttpClient::with_timeouts(StdDuration::from_secs(1), StdDuration::from_secs(1))
                .unwrap();
        let mut config = test_sync_config(base_url);
        config.transfer_timeout = StdDuration::from_millis(45);
        config.attempts = 2;

        let error = sync_osv_dumps_with_config(&client, &cache, &[Ecosystem::Npm], &config)
            .await
            .unwrap_err();
        server.await.unwrap();

        assert!(matches!(error, ProviderError::Network(_)));
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        let (archive_path, marker_path) = sync_paths(&cache);
        assert_eq!(fs::read(archive_path).unwrap(), previous);
        assert_eq!(fs::read_to_string(marker_path).unwrap(), previous_marker);
        assert_no_sync_temps(&cache);
    }

    #[test]
    fn dump_validation_requires_complete_bounded_osv_documents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dump.zip");
        let config = test_sync_config("http://unused.test".to_owned());
        let valid = br#"{"id":"TEST-1","modified":"2026-08-19T00:00:00Z","details":"forward-compatible","affected":[]}"#;

        fs::write(&path, archive_with_entry("TEST-1.json", valid)).unwrap();
        validate_osv_dump(&path, Ecosystem::Npm, &config).unwrap();

        for (name, contents) in [
            ("README.txt", b"not JSON".as_slice()),
            ("TEST-1.json", b"{}".as_slice()),
            ("TEST-1.json", b"null".as_slice()),
            ("TEST-1.json", b"[]".as_slice()),
            (
                "TEST-1.json",
                br#"{"id":"TEST-1","modified":"not-a-timestamp"}"#.as_slice(),
            ),
            (
                "TEST-1.json",
                br#"{"id":"UNKNOWN","modified":"2026-08-19T00:00:00Z"}"#.as_slice(),
            ),
            ("TEST-1.json", br#"{"id":"TEST-1""#.as_slice()),
        ] {
            fs::write(&path, archive_with_entry(name, contents)).unwrap();
            assert!(
                matches!(
                    validate_osv_dump(&path, Ecosystem::Npm, &config),
                    Err(ProviderError::InvalidResponse(_))
                ),
                "accepted invalid entry {name:?}: {}",
                String::from_utf8_lossy(contents)
            );
        }

        fs::write(&path, archive_with_entry("OTHER-1.json", valid)).unwrap();
        assert!(matches!(
            validate_osv_dump(&path, Ecosystem::Npm, &config),
            Err(ProviderError::InvalidResponse(_))
        ));

        let mut limited = config;
        limited.max_entry_bytes = valid.len() as u64 - 1;
        fs::write(&path, archive_with_entry("TEST-1.json", valid)).unwrap();
        assert!(matches!(
            validate_osv_dump(&path, Ecosystem::Npm, &limited),
            Err(ProviderError::InvalidResponse(_))
        ));

        let mut forged = archive_with_entry("TEST-1.json", valid);
        let central_header = forged
            .windows(4)
            .rposition(|window| window == b"PK\x01\x02")
            .unwrap();
        let forged_declared_size = u32::try_from(valid.len() - 2).unwrap();
        forged[central_header + 24..central_header + 28]
            .copy_from_slice(&forged_declared_size.to_le_bytes());
        fs::write(&path, forged).unwrap();
        limited.max_entry_bytes = valid.len() as u64 - 1;
        let error = validate_osv_dump(&path, Ecosystem::Npm, &limited).unwrap_err();
        assert!(
            error.to_string().contains("actual uncompressed"),
            "unexpected forged-size error: {error}"
        );
    }

    fn nuget_package(name: &str) -> Package {
        Package::new(
            Ecosystem::NuGet,
            name,
            "12.0.1",
            PathBuf::from("packages.lock.json"),
        )
    }

    fn nuget_registration_index(id: &str, versions: &[&str]) -> Value {
        let lower = versions.first().expect("registration fixture version");
        let upper = versions.last().expect("registration fixture version");
        json!({
            "count": 1,
            "items": [{
                "@id": format!("https://example.invalid/{}/index.json#page/{lower}/{upper}", id.to_ascii_lowercase()),
                "count": versions.len(),
                "items": versions
                    .iter()
                    .map(|version| json!({
                        "catalogEntry": {"id": id, "version": version}
                    }))
                    .collect::<Vec<_>>(),
                "lower": lower,
                "upper": upper
            }]
        })
    }

    fn nuget_registry_client(server: &MockServer, cache: Cache) -> RegistryClient {
        RegistryClient::with_registry_base_urls(
            HttpClient::new().unwrap(),
            cache,
            format!("{}/npm", server.uri()),
            format!("{}/pypi", server.uri()),
            format!("{}/nuget", server.uri()),
            format!("{}/registration", server.uri()),
            format!("{}/crates", server.uri()),
        )
    }

    fn npm_package(name: &str) -> Package {
        Package::new(
            Ecosystem::Npm,
            name,
            "1.0.0",
            PathBuf::from("package-lock.json"),
        )
    }

    fn pypi_package(name: &str) -> Package {
        Package::new(Ecosystem::PyPI, name, "1.0.0", PathBuf::from("uv.lock"))
    }

    fn cache_osv_document(cache: &Cache, package: &Package, id: &str) {
        let revision = OsvVulnerabilityRevision {
            id: id.to_owned(),
            modified: DateTime::parse_from_rfc3339(TEST_OSV_MODIFIED)
                .unwrap()
                .with_timezone(&Utc),
        };
        cache
            .put(
                "osv/vuln",
                &revision.cache_key(),
                &json!({
                    "id": id,
                    "modified": TEST_OSV_MODIFIED,
                    "summary": "pagination fixture",
                    "affected": [{
                        "package": {
                            "ecosystem": package.ecosystem.osv_name(),
                            "name": osv_query_name(package)
                        },
                        "versions": [package.version]
                    }]
                }),
                None,
            )
            .unwrap();
    }

    fn crates_package(name: &str) -> Package {
        Package::new(
            Ecosystem::CratesIo,
            name,
            "1.0.0",
            PathBuf::from("Cargo.lock"),
        )
    }

    #[derive(Debug, Deserialize)]
    struct RegistryRangeFixture {
        ecosystem: String,
        package: String,
        constraint: String,
        cache_key: String,
        registry: Value,
        latest_stable: String,
        latest_matching: String,
    }

    fn registry_range_fixtures() -> Vec<RegistryRangeFixture> {
        serde_json::from_str(include_str!("../tests/fixtures/registry-ranges.json")).unwrap()
    }

    #[test]
    fn registry_path_segment_encoding_preserves_only_rfc3986_unreserved_bytes() {
        let cases = [
            ("AZaz09-._~", "AZaz09-._~"),
            ("@scope/package", "%40scope%2Fpackage"),
            ("% /?#", "%25%20%2F%3F%23"),
            ("café/λ", "caf%C3%A9%2F%CE%BB"),
            ("\0\n\u{7f}", "%00%0A%7F"),
        ];

        for (input, expected) in cases {
            assert_eq!(
                encode_path_segment(input).to_string(),
                expected,
                "{input:?}"
            );
        }
    }

    #[tokio::test]
    async fn registry_request_paths_encode_scoped_npm_and_pypi_names_exactly() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/npm/%40scope%2Fpackage"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"dist-tags": {"latest": "2.0.0"}})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/pypi/caf%C3%A9%20%2F%25/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "releases": {
                    "1.0.0": [{"yanked": false}],
                    "2.0.0": [{"yanked": false}]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client = nuget_registry_client(&server, cache);

        for package in [npm_package("@scope/package"), pypi_package("Café /%")] {
            assert_eq!(
                client.latest(&package).await.unwrap().latest.latest_stable,
                "2.0.0"
            );
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn nuget_flat_and_registration_request_paths_encode_package_names_exactly() {
        let server = MockServer::start().await;
        let package = nuget_package("Contoso.Tools/@Edge %");
        let encoded_name = "contoso.tools%2F%40edge%20%25";
        let flat_path = format!("/nuget/{encoded_name}/index.json");
        let registration_path = format!("/registration/{encoded_name}/index.json");
        Mock::given(method("GET"))
            .and(path(flat_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "versions": ["12.0.1", "13.0.3"]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(registration_path))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(nuget_registration_index(
                    "Contoso.Tools/@Edge %",
                    &["12.0.1", "13.0.3"],
                )),
            )
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            nuget_registry_url_with_base("https://api.nuget.test/v3-flatcontainer", &package),
            format!("https://api.nuget.test/v3-flatcontainer/{encoded_name}/index.json")
        );
        assert_eq!(
            nuget_registration_url_with_base("https://api.nuget.test/v3/registration", &package),
            format!("https://api.nuget.test/v3/registration/{encoded_name}/index.json")
        );

        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let enrichment = nuget_registry_client(&server, cache)
            .latest(&package)
            .await
            .unwrap();

        assert_eq!(
            enrichment.canonical_name.as_deref(),
            Some("Contoso.Tools/@Edge %")
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn native_registry_http_mocks_cover_every_endpoint_and_header_contract() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/npm/npm-demo"))
            .and(header("accept", "application/vnd.npm.install-v1+json"))
            .and(header("user-agent", USER_AGENT_VALUE))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"dist-tags": {"latest": "2.0.0"}})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/pypi/pypi-demo/json"))
            .and(header("user-agent", USER_AGENT_VALUE))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "releases": {
                    "1.0.0": [{"yanked": false}],
                    "2.0.0": [{"yanked": false}]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/nuget/nuget.demo/index.json"))
            .and(header("user-agent", USER_AGENT_VALUE))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"versions": ["1.0.0", "2.0.0"]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/registration/nuget.demo/index.json"))
            .and(header("user-agent", USER_AGENT_VALUE))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(nuget_registration_index("NuGet.Demo", &["1.0.0", "2.0.0"])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/crates/cr/at/crate-demo"))
            .and(header("user-agent", USER_AGENT_VALUE))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                concat!(
                    "{\"name\":\"crate-demo\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
                    "{\"name\":\"crate-demo\",\"vers\":\"2.0.0\",\"yanked\":false}\n"
                ),
                "text/plain",
            ))
            .expect(1)
            .mount(&server)
            .await;

        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client = RegistryClient::with_registry_base_urls(
            HttpClient::new().unwrap(),
            cache,
            format!("{}/npm", server.uri()),
            format!("{}/pypi", server.uri()),
            format!("{}/nuget", server.uri()),
            format!("{}/registration", server.uri()),
            format!("{}/crates", server.uri()),
        );
        let packages = [
            npm_package("npm-demo"),
            pypi_package("pypi-demo"),
            Package::new(
                Ecosystem::NuGet,
                "NuGet.Demo",
                "1.0.0",
                PathBuf::from("packages.lock.json"),
            ),
            crates_package("crate-demo"),
        ];

        for package in packages {
            let latest = client.latest(&package).await.unwrap();
            assert_eq!(latest.latest.latest_stable, "2.0.0", "{}", package.name);
            assert_eq!(latest.latest.staleness, depscan_core::Staleness::Major);
            if package.ecosystem == Ecosystem::NuGet {
                assert_eq!(latest.canonical_name.as_deref(), Some("NuGet.Demo"));
            }
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn nuget_registration_follows_the_target_page_and_returns_canonical_identity() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/nuget/newtonsoft.json/index.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "versions": ["12.0.1", "13.0.3"]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let page_url = format!(
            "{}/registration/newtonsoft.json/page/12.0.1/13.0.3.json",
            server.uri()
        );
        Mock::given(method("GET"))
            .and(path("/registration/newtonsoft.json/index.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "count": 1,
                "items": [{
                    "@id": page_url,
                    "count": 2,
                    "lower": "12.0.1",
                    "upper": "13.0.3"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/registration/newtonsoft.json/page/12.0.1/13.0.3.json",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "count": 2,
                "items": [
                    {"catalogEntry": {"id": "Newtonsoft.Json", "version": "12.0.1"}},
                    {"catalogEntry": {"id": "Newtonsoft.Json", "version": "13.0.3"}}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let package = nuget_package("newtonsoft.json");

        let enrichment = nuget_registry_client(&server, cache)
            .latest(&package)
            .await
            .unwrap();

        assert_eq!(
            enrichment.canonical_name.as_deref(),
            Some("Newtonsoft.Json")
        );
        assert_eq!(enrichment.latest.latest_stable, "13.0.3");
        assert_eq!(package.display_name, "newtonsoft.json");
        assert_eq!(package.key(), "NuGet:newtonsoft.json:12.0.1");
        server.verify().await;
    }

    #[test]
    fn nuget_registration_rejects_malformed_and_mismatched_catalog_identities() {
        let package = nuget_package("newtonsoft.json");
        let mismatched = nuget_registration_index("Other.Package", &["12.0.1"]);
        let NugetRegistrationPageSource::Inline(page) =
            nuget_registration_page_for_version(&mismatched, "12.0.1").unwrap()
        else {
            panic!("fixture page must be inline");
        };
        let mismatch =
            canonical_nuget_name_from_registration_page(&package, "12.0.1", &page).unwrap_err();
        assert!(
            mismatch
                .to_string()
                .contains("does not match requested package")
        );

        let malformed = json!({
            "count": 1,
            "items": [{
                "count": 1,
                "items": [{"catalogEntry": {"version": "12.0.1"}}],
                "lower": "12.0.1",
                "upper": "12.0.1"
            }]
        });
        let NugetRegistrationPageSource::Inline(page) =
            nuget_registration_page_for_version(&malformed, "12.0.1").unwrap()
        else {
            panic!("fixture page must be inline");
        };
        let missing =
            canonical_nuget_name_from_registration_page(&package, "12.0.1", &page).unwrap_err();
        assert!(missing.to_string().contains("has no catalogEntry.id"));
    }

    #[tokio::test]
    async fn nuget_registry_enrichment_fails_when_registration_identity_is_unavailable() {
        let package = nuget_package("newtonsoft.json");
        let cases = [
            (
                "absent target version",
                json!({"count": 0, "items": []}),
                "no index page contains version",
            ),
            (
                "missing catalog ID",
                json!({
                    "count": 1,
                    "items": [{
                        "count": 1,
                        "items": [{"catalogEntry": {"version": "12.0.1"}}],
                        "lower": "12.0.1",
                        "upper": "12.0.1"
                    }]
                }),
                "has no catalogEntry.id",
            ),
            (
                "mismatched catalog ID",
                nuget_registration_index("Other.Package", &["12.0.1"]),
                "does not match requested package",
            ),
        ];

        for (case, registration, expected) in cases {
            let cache_dir = tempfile::tempdir().unwrap();
            let cache = Cache {
                root: cache_dir.path().to_path_buf(),
                policy: CachePolicy::default(),
            };
            cache
                .put(
                    "registry",
                    &nuget_registry_cache_key(&package),
                    &json!({"versions": ["12.0.1", "13.0.3"]}),
                    None,
                )
                .unwrap();
            cache
                .put(
                    "registry",
                    &nuget_registration_cache_key(&package),
                    &registration,
                    None,
                )
                .unwrap();

            let error = RegistryClient::new(HttpClient::new().unwrap(), cache)
                .latest(&package)
                .await
                .unwrap_err();

            assert!(
                error.to_string().contains(expected),
                "{case}: expected {expected:?}, got {error}"
            );
        }
    }

    #[test]
    fn nuget_registration_page_links_are_origin_and_package_prefix_confined() {
        let package = nuget_package("newtonsoft.json");
        let base = "https://api.nuget.test/v3/registration";
        let valid = "https://api.nuget.test/v3/registration/newtonsoft.json/page/1/2.json";
        assert_eq!(
            validated_nuget_registration_page_url(base, &package, valid).unwrap(),
            valid
        );

        for invalid in [
            "https://attacker.invalid/v3/registration/newtonsoft.json/page/1/2.json",
            "https://api.nuget.test/v3/registration/other.package/page/1/2.json",
            "https://user:secret@api.nuget.test/v3/registration/newtonsoft.json/page/1/2.json",
        ] {
            assert!(
                validated_nuget_registration_page_url(base, &package, invalid).is_err(),
                "accepted unconfined registration page {invalid:?}"
            );
        }
    }

    #[test]
    fn nuget_registration_page_prefix_encodes_the_package_segment_exactly() {
        let package = nuget_package("Contoso.Tools/@Edge %");
        let base = "https://api.nuget.test/v3/registration";
        let valid = concat!(
            "https://api.nuget.test/v3/registration/",
            "contoso.tools%2F%40edge%20%25/page/1/2.json"
        );

        assert_eq!(
            validated_nuget_registration_page_url(base, &package, valid).unwrap(),
            valid
        );
        for invalid in [
            "https://api.nuget.test/v3/registration/contoso.tools/@edge%20%25/page/1/2.json",
            "https://api.nuget.test/v3/registration/contoso.tools%2F%40other%20%25/page/1/2.json",
        ] {
            assert!(
                validated_nuget_registration_page_url(base, &package, invalid).is_err(),
                "accepted mismatched encoded prefix {invalid:?}"
            );
        }
    }

    #[tokio::test]
    async fn native_registry_http_mocks_reject_malformed_documents_for_every_ecosystem() {
        let server = MockServer::start().await;
        let cases = [
            ("/npm/npm-bad", json!({"dist-tags": {}})),
            ("/pypi/pypi-bad/json", json!({"releases": false})),
            ("/nuget/nuget.bad/index.json", json!({"versions": {}})),
        ];
        for (request_path, response) in cases {
            Mock::given(method("GET"))
                .and(path(request_path))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/crates/cr/at/crate-bad"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                "{\"name\":\"crate-bad\",\"vers\":false,\"yanked\":false}\n",
                "text/plain",
            ))
            .expect(1)
            .mount(&server)
            .await;

        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client = RegistryClient::with_registry_base_urls(
            HttpClient::new().unwrap(),
            cache,
            format!("{}/npm", server.uri()),
            format!("{}/pypi", server.uri()),
            format!("{}/nuget", server.uri()),
            format!("{}/registration", server.uri()),
            format!("{}/crates", server.uri()),
        );
        let cases = [
            (npm_package("npm-bad"), "npm response lacked latest"),
            (pypi_package("pypi-bad"), "PyPI response lacked releases"),
            (nuget_package("NuGet.Bad"), "NuGet response lacked versions"),
            (crates_package("crate-bad"), "sparse-index line 1"),
        ];

        for (package, expected) in cases {
            let error = client.latest(&package).await.unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "{}: expected {expected:?}, got {error}",
                package.name
            );
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn registry_fixtures_keep_unconstrained_and_matching_latest_distinct() {
        for fixture in registry_range_fixtures() {
            let ecosystem = Ecosystem::from_cli(&fixture.ecosystem).unwrap();
            let cache_dir = tempfile::tempdir().unwrap();
            let cache = Cache {
                root: cache_dir.path().to_path_buf(),
                policy: CachePolicy::default(),
            };
            cache
                .put("registry", &fixture.cache_key, &fixture.registry, None)
                .unwrap();
            let mut package = Package::new(
                ecosystem,
                &fixture.package,
                &fixture.constraint,
                PathBuf::from("manifest.fixture"),
            );
            package.set_manifest_constraint(&fixture.constraint);
            if ecosystem == Ecosystem::NuGet {
                cache
                    .put(
                        "registry",
                        &nuget_registration_cache_key(&package),
                        &nuget_registration_index(
                            &fixture.package,
                            &[
                                fixture.latest_matching.as_str(),
                                fixture.latest_stable.as_str(),
                            ],
                        ),
                        None,
                    )
                    .unwrap();
            }
            let client = RegistryClient::new(HttpClient::new().unwrap(), cache);

            let latest = client.latest(&package).await.unwrap();

            assert_eq!(
                latest.latest.latest_stable, fixture.latest_stable,
                "wrong stable release for {}",
                fixture.package
            );
            assert_eq!(
                latest.latest.latest_matching.as_deref(),
                Some(fixture.latest_matching.as_str()),
                "wrong constrained release for {}",
                fixture.package
            );
            assert_ne!(latest.latest.latest_stable, fixture.latest_matching);
            assert_eq!(latest.latest.staleness, depscan_core::Staleness::Unknown);
        }
    }

    #[tokio::test]
    async fn invalid_manifest_constraint_is_a_visible_provider_error() {
        let fixture = registry_range_fixtures()
            .into_iter()
            .find(|fixture| fixture.ecosystem == "npm")
            .unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        cache
            .put("registry", &fixture.cache_key, &fixture.registry, None)
            .unwrap();
        let client = RegistryClient::new(HttpClient::new().unwrap(), cache);
        let mut package = Package::new(
            Ecosystem::Npm,
            &fixture.package,
            "workspace:*",
            PathBuf::from("package.json"),
        );
        package.set_manifest_constraint("workspace:*");

        let error = client.latest(&package).await.unwrap_err();

        assert!(error.to_string().contains("workspace:*"));
        assert!(
            error
                .to_string()
                .contains("invalid npm manifest constraint")
        );
    }

    fn assert_invalid_crates_name(name: &str) {
        let result = std::panic::catch_unwind(|| crates_io_sparse_path(name));
        let error = result
            .unwrap_or_else(|_| panic!("sparse path construction panicked for {name:?}"))
            .unwrap_err();

        match error {
            ProviderError::InvalidPackageName {
                ecosystem,
                name: rejected,
                reason,
            } => {
                assert_eq!(ecosystem, Ecosystem::CratesIo);
                assert_eq!(rejected, name);
                assert!(!reason.is_empty());
            }
            other => panic!("expected a typed package-name error for {name:?}, got {other:?}"),
        }
    }

    async fn assert_invalid_sparse_response(body: Vec<u8>, expected_fragments: &[&str]) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/fi/xt/fixture"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let cache_file = cache.filename("registry", "crates:fixture");
        let cache_temp_file = cache_file.with_extension("json.tmp");
        let client = RegistryClient::with_crates_index_base_url(
            HttpClient::new().unwrap(),
            cache,
            server.uri(),
        );

        let error = client.latest(&crates_package("fixture")).await.unwrap_err();
        let message = match error {
            ProviderError::InvalidResponse(message) => message,
            other => panic!("expected invalid-response error, got {other:?}"),
        };
        for fragment in expected_fragments {
            assert!(
                message.contains(fragment),
                "expected {message:?} to contain {fragment:?}"
            );
        }
        assert!(!cache_file.exists(), "invalid response was cached");
        assert!(
            !cache_temp_file.exists(),
            "invalid response left a partial cache file"
        );
        server.verify().await;
    }

    #[test]
    fn scores_supported_cvss_versions_with_standard_formulas() {
        let cases = [
            (
                "CVSS_V3",
                "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                9.8,
                Severity::Critical,
            ),
            (
                "CVSS_V3",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                7.5,
                Severity::High,
            ),
            (
                "CVSS_V4",
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/V:C",
                8.7,
                Severity::High,
            ),
        ];

        for (severity_type, vector, expected_score, expected_severity) in cases {
            let document = json!({
                "id": "TEST-1",
                "modified": TEST_OSV_MODIFIED,
                "affected": [],
                "severity": [{"type": severity_type, "score": vector}]
            });
            let vulnerability = vulnerability_from_osv(&document, None).unwrap().unwrap();

            assert_eq!(vulnerability.cvss_score, Some(expected_score), "{vector}");
            assert_eq!(vulnerability.severity, Some(expected_severity), "{vector}");
        }
    }

    #[test]
    fn prefers_cvss_v4_and_falls_back_to_valid_cvss_v3() {
        let v3_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H";
        let v4_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/V:C";
        let document = json!({
            "severity": [
                {"type": "CVSS_V3", "score": v3_vector},
                {"type": "CVSS_V4", "score": v4_vector}
            ]
        });
        assert_eq!(osv_cvss_score(&document, None), Some(8.7));

        let document = json!({
            "severity": [
                {"type": "CVSS_V4", "score": "CVSS:4.0/not-a-vector"},
                {"type": "CVSS_V3", "score": v3_vector}
            ]
        });
        assert_eq!(osv_cvss_score(&document, None), Some(7.5));
    }

    #[test]
    fn selects_the_highest_score_independent_of_source_order() {
        let high = json!({
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        });
        let critical = json!({
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        });

        for severity in [vec![high.clone(), critical.clone()], vec![critical, high]] {
            let document = json!({"severity": severity});
            assert_eq!(osv_cvss_score(&document, None), Some(9.8));
        }
    }

    #[test]
    fn top_level_severity_precedes_matching_affected_severity() {
        let package = Package::new(
            Ecosystem::CratesIo,
            "quick-xml",
            "0.36.2",
            PathBuf::from("Cargo.lock"),
        );
        let document = json!({
            "severity": [{
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
            }],
            "affected": [{
                "package": {"ecosystem": "crates.io", "name": "quick-xml"},
                "severity": [{
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/V:C"
                }]
            }]
        });

        assert_eq!(osv_cvss_score(&document, Some(&package)), Some(7.5));
    }

    #[test]
    fn affected_severity_is_restricted_to_the_matching_package() {
        let package = Package::new(
            Ecosystem::CratesIo,
            "quick-xml",
            "0.36.2",
            PathBuf::from("Cargo.lock"),
        );
        let document = json!({
            "id": "TEST-AFFECTED-SEVERITY",
            "modified": TEST_OSV_MODIFIED,
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "quick-xml"},
                    "severity": [{
                        "type": "CVSS_V4",
                        "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
                    }]
                },
                {
                    "package": {"ecosystem": "crates.io", "name": "another-crate"},
                    "severity": [{
                        "type": "CVSS_V4",
                        "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
                    }]
                },
                {
                    "package": {"ecosystem": "crates.io", "name": "quick-xml"},
                    "versions": ["0.36.2"],
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                        },
                        {
                            "type": "CVSS_V4",
                            "score": "CVSS:4.0/not-a-vector"
                        }
                    ]
                }
            ]
        });

        let vulnerability = vulnerability_from_osv(&document, Some(&package))
            .unwrap()
            .unwrap();
        assert_eq!(vulnerability.cvss_score, Some(7.5));
        assert_eq!(vulnerability.severity, Some(Severity::High));
        assert_eq!(osv_cvss_score(&document, None), None);
    }

    #[test]
    fn rejects_malformed_mismatched_and_unscoped_scores() {
        let cases = [
            json!({"severity": [{"type": "CVSS_V3", "score": "6.5"}]}),
            json!({"severity": [{
                "type": "CVSS_V4",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
            }]}),
            json!({"severity": [{"type": "CVSS_V3", "score": "not-a-vector"}]}),
            json!({"severity": [{
                "type": "CVSS_V2",
                "score": "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"
            }]}),
        ];

        for document in cases {
            let document = json!({
                "id": "TEST-MALFORMED-SCORE",
                "modified": TEST_OSV_MODIFIED,
                "affected": [],
                "severity": document["severity"].clone()
            });
            let vulnerability = vulnerability_from_osv(&document, None).unwrap().unwrap();
            assert_eq!(vulnerability.cvss_score, None);
            assert_eq!(vulnerability.severity, None);
        }
    }

    #[test]
    fn builds_lowercase_sparse_paths_at_every_length_boundary() {
        let max_name = format!("A{}", "z".repeat(CRATES_IO_MAX_NAME_LEN - 1));
        let max_path = format!("az/zz/{}", max_name.to_ascii_lowercase());
        let cases = [
            ("a".to_owned(), "1/a".to_owned()),
            ("Z".to_owned(), "1/z".to_owned()),
            ("a1".to_owned(), "2/a1".to_owned()),
            ("AB".to_owned(), "2/ab".to_owned()),
            ("a-b".to_owned(), "3/a/a-b".to_owned()),
            ("A_B".to_owned(), "3/a/a_b".to_owned()),
            ("abcd".to_owned(), "ab/cd/abcd".to_owned()),
            ("Serde_JSON".to_owned(), "se/rd/serde_json".to_owned()),
            (max_name, max_path),
        ];

        for (name, expected) in cases {
            assert_eq!(crates_io_sparse_path(&name).unwrap(), expected, "{name}");
        }
    }

    #[test]
    fn accepts_all_structural_name_characters_through_the_length_limit() {
        const FIRST_CHARACTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const REMAINING_CHARACTERS: &[u8] =
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

        for len in 1..=CRATES_IO_MAX_NAME_LEN {
            for &first in FIRST_CHARACTERS {
                for &remaining in REMAINING_CHARACTERS {
                    let mut bytes = vec![remaining; len];
                    bytes[0] = first;
                    let name = String::from_utf8(bytes).unwrap();
                    let result = std::panic::catch_unwind(|| crates_io_sparse_path(&name));
                    let path = result
                        .unwrap_or_else(|_| {
                            panic!("sparse path construction panicked for {name:?}")
                        })
                        .unwrap_or_else(|error| panic!("valid name {name:?} failed: {error}"));

                    assert!(path.is_ascii());
                    assert_eq!(path, path.to_ascii_lowercase());
                    assert!(path.ends_with(&name.to_ascii_lowercase()));
                }
            }
        }
    }

    #[test]
    fn rejects_every_disallowed_ascii_character_without_panicking() {
        for byte in 0_u8..=127 {
            if !byte.is_ascii_alphabetic() {
                assert_invalid_crates_name(&char::from(byte).to_string());
            }

            if !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')) {
                assert_invalid_crates_name(&format!("a{}", char::from(byte)));
            }
        }
    }

    #[test]
    fn rejects_empty_unicode_separators_controls_overlong_and_punctuation() {
        let overlong = "a".repeat(CRATES_IO_MAX_NAME_LEN + 1);
        let very_long = "a".repeat(4_096);
        let invalid = [
            "",
            "é",
            "a🦀",
            "a/b",
            "a\\b",
            "../serde",
            "a\0b",
            "a\nb",
            "a\tb",
            "1crate",
            "-crate",
            "_crate",
            "crate.name",
            "crate@name",
            "crate name",
            overlong.as_str(),
            very_long.as_str(),
        ];

        for name in invalid {
            assert_invalid_crates_name(name);
        }
    }

    #[tokio::test]
    async fn valid_crates_names_request_the_expected_sparse_index_paths() {
        let server = MockServer::start().await;
        let cases = [
            ("A", "/1/a"),
            ("aB", "/2/ab"),
            ("A-B", "/3/a/a-b"),
            ("Serde_JSON", "/se/rd/serde_json"),
        ];
        for (name, expected_path) in cases {
            let body = format!("{{\"name\":\"{name}\",\"vers\":\"1.0.0\",\"yanked\":false}}\n");
            Mock::given(method("GET"))
                .and(path(expected_path))
                .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/plain"))
                .expect(1)
                .mount(&server)
                .await;
        }
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client = RegistryClient::with_crates_index_base_url(
            HttpClient::new().unwrap(),
            cache,
            server.uri(),
        );

        for (name, _) in cases {
            let latest = client.latest(&crates_package(name)).await.unwrap();
            assert_eq!(latest.latest.latest_stable, "1.0.0");
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn invalid_crates_names_return_typed_errors_without_http_requests() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client = RegistryClient::with_crates_index_base_url(
            HttpClient::new().unwrap(),
            cache,
            server.uri(),
        );
        let invalid = ["", "é", "a/b", "a\0b", "1crate", "crate.name"];

        for name in invalid {
            let error = client.latest(&crates_package(name)).await.unwrap_err();
            match error {
                ProviderError::InvalidPackageName {
                    ecosystem,
                    name: rejected,
                    reason,
                } => {
                    assert_eq!(ecosystem, Ecosystem::CratesIo);
                    assert_eq!(rejected, name);
                    assert!(!reason.is_empty());
                }
                other => panic!("expected a typed package-name error, got {other:?}"),
            }
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn accepts_complete_sparse_ndjson_and_reuses_the_validated_cache() {
        let server = MockServer::start().await;
        let body = concat!(
            "\n",
            "{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":true}\r\n",
            "\n",
            "{\"name\":\"fixture\",\"vers\":\"2.0.0\",\"yanked\":false}\n",
        );
        Mock::given(method("GET"))
            .and(path("/fi/xt/fixture"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/plain"))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let cache_file = cache.filename("registry", "crates:fixture");
        let client = RegistryClient::with_crates_index_base_url(
            HttpClient::new().unwrap(),
            cache,
            server.uri(),
        );
        let package = crates_package("fixture");

        for _ in 0..2 {
            let latest = client.latest(&package).await.unwrap();
            assert_eq!(latest.latest.latest_stable, "2.0.0");
            assert!(latest.latest.yanked);
        }

        let stored: Value =
            serde_json::from_str(&fs::read_to_string(&cache_file).unwrap()).unwrap();
        assert_eq!(
            stored
                .pointer("/value/schema_version")
                .and_then(Value::as_u64),
            Some(u64::from(CRATES_IO_INDEX_CACHE_SCHEMA_VERSION))
        );
        assert_eq!(
            stored
                .pointer("/value/entries")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn stale_sparse_index_revalidates_with_etag_and_refreshes_on_304() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/fi/xt/fixture"))
            .and(header("if-none-match", "\"sparse-1\""))
            .respond_with(ResponseTemplate::new(304))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        cache
            .put(
                "registry",
                "crates:fixture",
                &json!({
                    "schema_version": CRATES_IO_INDEX_CACHE_SCHEMA_VERSION,
                    "entries": [
                        {"name": "fixture", "vers": "1.0.0", "yanked": true},
                        {"name": "fixture", "vers": "2.0.0", "yanked": false}
                    ]
                }),
                Some("\"sparse-1\"".to_owned()),
            )
            .unwrap();
        age_cache_entry(&cache, "registry", "crates:fixture", Duration::hours(7));
        let before = read_cache_entry(&cache, "registry", "crates:fixture").stored_at;
        let client = RegistryClient::with_crates_index_base_url(
            HttpClient::new().unwrap(),
            cache.clone(),
            server.uri(),
        );

        let latest = client.latest(&crates_package("fixture")).await.unwrap();

        assert_eq!(latest.latest.latest_stable, "2.0.0");
        assert!(latest.latest.yanked);
        let refreshed = read_cache_entry(&cache, "registry", "crates:fixture");
        assert!(refreshed.stored_at > before);
        assert_eq!(refreshed.etag.as_deref(), Some("\"sparse-1\""));
        assert_eq!(
            refreshed
                .value
                .pointer("/entries/1/vers")
                .and_then(Value::as_str),
            Some("2.0.0")
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn future_sparse_index_revalidates_before_reuse() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/fi/xt/fixture"))
            .and(header("if-none-match", "\"sparse-future\""))
            .respond_with(ResponseTemplate::new(304))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        cache
            .put(
                "registry",
                "crates:fixture",
                &json!({
                    "schema_version": CRATES_IO_INDEX_CACHE_SCHEMA_VERSION,
                    "entries": [
                        {"name": "fixture", "vers": "1.0.0", "yanked": false},
                        {"name": "fixture", "vers": "2.0.0", "yanked": false}
                    ]
                }),
                Some("\"sparse-future\"".to_owned()),
            )
            .unwrap();
        let future = Utc::now() + Duration::days(1);
        set_cache_entry_timestamp(&cache, "registry", "crates:fixture", future);
        let client = RegistryClient::with_crates_index_base_url(
            HttpClient::new().unwrap(),
            cache.clone(),
            server.uri(),
        );

        let latest = client.latest(&crates_package("fixture")).await.unwrap();

        assert_eq!(latest.latest.latest_stable, "2.0.0");
        let refreshed = read_cache_entry(&cache, "registry", "crates:fixture");
        assert!(refreshed.stored_at < future);
        assert!(refreshed.stored_at <= Utc::now());
        assert_eq!(refreshed.etag.as_deref(), Some("\"sparse-future\""));
        server.verify().await;
    }

    #[tokio::test]
    async fn late_sparse_304_cannot_overwrite_a_concurrent_changed_index() {
        let server = MockServer::start().await;
        let slow_received = Arc::new(tokio::sync::Notify::new());
        let slow_responder_received = slow_received.clone();
        Mock::given(method("GET"))
            .and(path("/slow/fi/xt/fixture"))
            .and(header("if-none-match", "\"sparse-1\""))
            .respond_with(move |_: &wiremock::Request| {
                slow_responder_received.notify_one();
                ResponseTemplate::new(304).set_delay(std::time::Duration::from_millis(200))
            })
            .expect(1)
            .mount(&server)
            .await;
        let changed_body = concat!(
            "{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
            "{\"name\":\"fixture\",\"vers\":\"2.0.0\",\"yanked\":false}\n",
        );
        Mock::given(method("GET"))
            .and(path("/fast/fi/xt/fixture"))
            .and(header("if-none-match", "\"sparse-1\""))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"sparse-2\"")
                    .set_body_raw(changed_body, "text/plain"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        cache
            .put(
                "registry",
                "crates:fixture",
                &json!({
                    "schema_version": CRATES_IO_INDEX_CACHE_SCHEMA_VERSION,
                    "entries": [
                        {"name": "fixture", "vers": "1.0.0", "yanked": false}
                    ]
                }),
                Some("\"sparse-1\"".to_owned()),
            )
            .unwrap();
        age_cache_entry(&cache, "registry", "crates:fixture", Duration::hours(7));
        let slow_client = RegistryClient::with_crates_index_base_url(
            HttpClient::new().unwrap(),
            cache.clone(),
            format!("{}/slow", server.uri()),
        );
        let fast_client = RegistryClient::with_crates_index_base_url(
            HttpClient::new().unwrap(),
            cache.clone(),
            format!("{}/fast", server.uri()),
        );
        let package = crates_package("fixture");
        let slow_package = package.clone();
        let slow_started = slow_received.notified();
        let slow = tokio::spawn(async move { slow_client.latest(&slow_package).await });
        tokio::time::timeout(std::time::Duration::from_secs(2), slow_started)
            .await
            .expect("slow sparse-index request was not received");

        let fast = fast_client.latest(&package).await.unwrap();
        let slow = slow.await.unwrap().unwrap();

        assert_eq!(fast.latest.latest_stable, "2.0.0");
        assert_eq!(slow.latest.latest_stable, "2.0.0");
        let cached = read_cache_entry(&cache, "registry", "crates:fixture");
        assert_eq!(cached.etag.as_deref(), Some("\"sparse-2\""));
        assert_eq!(
            cached
                .value
                .pointer("/entries/1/vers")
                .and_then(Value::as_str),
            Some("2.0.0")
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn stale_registry_metadata_revalidates_with_etag_and_refreshes_on_304() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/metadata"))
            .and(header("if-none-match", "\"revision-1\""))
            .respond_with(ResponseTemplate::new(304))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        cache
            .put(
                "registry",
                "etag-304",
                &json!({"revision": 1}),
                Some("\"revision-1\"".to_owned()),
            )
            .unwrap();
        age_cache_entry(&cache, "registry", "etag-304", Duration::hours(7));
        let before = read_cache_entry(&cache, "registry", "etag-304").stored_at;
        let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());

        let value = client
            .metadata(
                "etag-304",
                &format!("{}/metadata", server.uri()),
                HeaderMap::new(),
            )
            .await
            .unwrap();

        assert_eq!(value, json!({"revision": 1}));
        let refreshed = read_cache_entry(&cache, "registry", "etag-304");
        assert!(refreshed.stored_at > before);
        assert_eq!(refreshed.etag.as_deref(), Some("\"revision-1\""));
        assert_eq!(refreshed.value, value);
        server.verify().await;
    }

    #[tokio::test]
    async fn future_registry_metadata_revalidates_before_reuse() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/metadata"))
            .and(header("if-none-match", "\"revision-future\""))
            .respond_with(ResponseTemplate::new(304))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        cache
            .put(
                "registry",
                "future-etag",
                &json!({"revision": 1}),
                Some("\"revision-future\"".to_owned()),
            )
            .unwrap();
        let future = Utc::now() + Duration::days(1);
        set_cache_entry_timestamp(&cache, "registry", "future-etag", future);
        let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());

        let value = client
            .metadata(
                "future-etag",
                &format!("{}/metadata", server.uri()),
                HeaderMap::new(),
            )
            .await
            .unwrap();

        assert_eq!(value, json!({"revision": 1}));
        let refreshed = read_cache_entry(&cache, "registry", "future-etag");
        assert!(refreshed.stored_at < future);
        assert!(refreshed.stored_at <= Utc::now());
        assert_eq!(refreshed.etag.as_deref(), Some("\"revision-future\""));
        server.verify().await;
    }

    #[tokio::test]
    async fn late_registry_304_cannot_overwrite_a_concurrent_changed_response() {
        let server = MockServer::start().await;
        let slow_received = Arc::new(tokio::sync::Notify::new());
        let slow_responder_received = slow_received.clone();
        Mock::given(method("GET"))
            .and(path("/slow-not-modified"))
            .and(header("if-none-match", "\"revision-1\""))
            .respond_with(move |_: &wiremock::Request| {
                slow_responder_received.notify_one();
                ResponseTemplate::new(304).set_delay(std::time::Duration::from_millis(200))
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/fast-modified"))
            .and(header("if-none-match", "\"revision-1\""))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"revision-2\"")
                    .set_body_json(json!({"revision": 2})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        cache
            .put(
                "registry",
                "revalidation-race",
                &json!({"revision": 1}),
                Some("\"revision-1\"".to_owned()),
            )
            .unwrap();
        age_cache_entry(&cache, "registry", "revalidation-race", Duration::hours(7));
        let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());
        let slow_client = client.clone();
        let slow_url = format!("{}/slow-not-modified", server.uri());
        let slow_started = slow_received.notified();
        let slow = tokio::spawn(async move {
            slow_client
                .metadata("revalidation-race", &slow_url, HeaderMap::new())
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), slow_started)
            .await
            .expect("slow revalidation request was not received");

        let fast = client
            .metadata(
                "revalidation-race",
                &format!("{}/fast-modified", server.uri()),
                HeaderMap::new(),
            )
            .await
            .unwrap();
        let slow = slow.await.unwrap().unwrap();

        assert_eq!(fast, json!({"revision": 2}));
        assert_eq!(slow, fast);
        let cached = read_cache_entry(&cache, "registry", "revalidation-race");
        assert_eq!(cached.value, fast);
        assert_eq!(cached.etag.as_deref(), Some("\"revision-2\""));
        server.verify().await;
    }

    #[tokio::test]
    async fn cache_bypass_still_prevents_out_of_order_publication() {
        let server = MockServer::start().await;
        let slow_received = Arc::new(tokio::sync::Notify::new());
        let slow_responder_received = slow_received.clone();
        let slow_calls = Arc::new(AtomicUsize::new(0));
        let responder_calls = slow_calls.clone();
        Mock::given(method("GET"))
            .and(path("/slow-refresh"))
            .respond_with(move |_: &wiremock::Request| {
                if responder_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    slow_responder_received.notify_one();
                    ResponseTemplate::new(200)
                        .insert_header("etag", "\"revision-1\"")
                        .set_body_json(json!({"revision": 1}))
                        .set_delay(std::time::Duration::from_millis(200))
                } else {
                    ResponseTemplate::new(200)
                        .insert_header("etag", "\"revision-2\"")
                        .set_body_json(json!({"revision": 2}))
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/fast-refresh"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"revision-2\"")
                    .set_body_json(json!({"revision": 2})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy {
                read: false,
                max_age: None,
            },
        };
        cache
            .put(
                "registry",
                "bypass-race",
                &json!({"revision": 0}),
                Some("\"revision-0\"".to_owned()),
            )
            .unwrap();
        let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());
        let slow_client = client.clone();
        let slow_url = format!("{}/slow-refresh", server.uri());
        let slow_started = slow_received.notified();
        let slow = tokio::spawn(async move {
            slow_client
                .metadata("bypass-race", &slow_url, HeaderMap::new())
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), slow_started)
            .await
            .expect("slow bypass request was not received");

        let fast = client
            .metadata(
                "bypass-race",
                &format!("{}/fast-refresh", server.uri()),
                HeaderMap::new(),
            )
            .await
            .unwrap();
        let slow = slow.await.unwrap().unwrap();

        assert_eq!(fast, json!({"revision": 2}));
        assert_eq!(slow, fast);
        assert_eq!(slow_calls.load(Ordering::SeqCst), 2);
        let cached = read_cache_entry(&cache, "registry", "bypass-race");
        assert_eq!(cached.value, fast);
        assert_eq!(cached.etag.as_deref(), Some("\"revision-2\""));
        for request in server.received_requests().await.unwrap() {
            assert!(request.headers.get("if-none-match").is_none());
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn changed_registry_etag_replaces_the_cached_body_atomically() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/metadata"))
            .and(header("if-none-match", "\"revision-1\""))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"revision-2\"")
                    .set_body_json(json!({"revision": 2})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        cache
            .put(
                "registry",
                "etag-changed",
                &json!({"revision": 1}),
                Some("\"revision-1\"".to_owned()),
            )
            .unwrap();
        age_cache_entry(&cache, "registry", "etag-changed", Duration::hours(7));
        let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());

        let value = client
            .metadata(
                "etag-changed",
                &format!("{}/metadata", server.uri()),
                HeaderMap::new(),
            )
            .await
            .unwrap();

        assert_eq!(value, json!({"revision": 2}));
        let cached = read_cache_entry(&cache, "registry", "etag-changed");
        assert_eq!(cached.value, value);
        assert_eq!(cached.etag.as_deref(), Some("\"revision-2\""));
        server.verify().await;
    }

    #[tokio::test]
    async fn missing_registry_etag_forces_an_unconditional_refresh() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"revision": 2})))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        cache
            .put("registry", "missing-etag", &json!({"revision": 1}), None)
            .unwrap();
        age_cache_entry(&cache, "registry", "missing-etag", Duration::hours(7));
        let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());

        let value = client
            .metadata(
                "missing-etag",
                &format!("{}/metadata", server.uri()),
                HeaderMap::new(),
            )
            .await
            .unwrap();

        assert_eq!(value, json!({"revision": 2}));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].headers.get("if-none-match").is_none());
        let cached = read_cache_entry(&cache, "registry", "missing-etag");
        assert_eq!(cached.value, value);
        assert!(cached.etag.is_none());
        server.verify().await;
    }

    #[tokio::test]
    async fn failed_registry_revalidation_preserves_the_stale_cache_entry() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/metadata"))
            .and(header("if-none-match", "\"revision-1\""))
            .respond_with(ResponseTemplate::new(400))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        cache
            .put(
                "registry",
                "failed-revalidation",
                &json!({"revision": 1}),
                Some("\"revision-1\"".to_owned()),
            )
            .unwrap();
        age_cache_entry(
            &cache,
            "registry",
            "failed-revalidation",
            Duration::hours(7),
        );
        let before = read_cache_entry(&cache, "registry", "failed-revalidation");
        let client = RegistryClient::new(HttpClient::new().unwrap(), cache.clone());

        let error = client
            .metadata(
                "failed-revalidation",
                &format!("{}/metadata", server.uri()),
                HeaderMap::new(),
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("HTTP 400"));
        let after = read_cache_entry(&cache, "registry", "failed-revalidation");
        assert_eq!(after.stored_at, before.stored_at);
        assert_eq!(after.etag, before.etag);
        assert_eq!(after.value, before.value);
        server.verify().await;
    }

    #[tokio::test]
    async fn rejects_invalid_utf8_with_the_source_line_number() {
        let mut body = b"{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":false}\n".to_vec();
        body.extend_from_slice(&[0xff, b'\n']);

        assert_invalid_sparse_response(body, &["sparse-index line 2", "not valid UTF-8"]).await;
    }

    #[tokio::test]
    async fn rejects_a_malformed_line_between_valid_entries() {
        let body = concat!(
            "{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
            "{\"name\":\"fixture\",\"vers\":\"1.1.0\"\n",
            "{\"name\":\"fixture\",\"vers\":\"2.0.0\",\"yanked\":false}\n",
        );

        assert_invalid_sparse_response(
            body.as_bytes().to_vec(),
            &["sparse-index line 2", "invalid JSON"],
        )
        .await;
    }

    #[tokio::test]
    async fn rejects_a_truncated_final_sparse_index_line() {
        let body = concat!(
            "{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
            "{\"name\":\"fixture\",\"vers\":\"2.0.0\"",
        );

        assert_invalid_sparse_response(
            body.as_bytes().to_vec(),
            &["sparse-index line 2", "invalid JSON"],
        )
        .await;
    }

    #[tokio::test]
    async fn rejects_missing_wrong_or_invalid_selection_fields() {
        let cases = [
            (
                "{\"vers\":\"1.0.0\",\"yanked\":false}\n",
                vec!["sparse-index line 1", "missing field `name`"],
            ),
            (
                "{\"name\":7,\"vers\":\"1.0.0\",\"yanked\":false}\n",
                vec!["sparse-index line 1", "invalid type"],
            ),
            (
                "{\"name\":\"fixture\",\"yanked\":false}\n",
                vec!["sparse-index line 1", "missing field `vers`"],
            ),
            (
                "{\"name\":\"fixture\",\"vers\":false,\"yanked\":false}\n",
                vec!["sparse-index line 1", "invalid type"],
            ),
            (
                "{\"name\":\"fixture\",\"vers\":\"not-semver\",\"yanked\":false}\n",
                vec!["sparse-index line 1", "field `vers` is not valid SemVer"],
            ),
            (
                "{\"name\":\"fixture\",\"vers\":\"1.0.0\"}\n",
                vec!["sparse-index line 1", "missing field `yanked`"],
            ),
            (
                "{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":\"no\"}\n",
                vec!["sparse-index line 1", "invalid type"],
            ),
            (
                "{\"name\":\"different\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
                vec!["sparse-index line 1", "does not match requested crate"],
            ),
            ("", vec!["contains no version entries"]),
        ];

        for (body, expected_fragments) in cases {
            assert_invalid_sparse_response(body.as_bytes().to_vec(), &expected_fragments).await;
        }
    }

    #[tokio::test]
    async fn rejects_duplicate_or_conflicting_version_records() {
        let body = concat!(
            "{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
            "{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":true}\n",
        );

        assert_invalid_sparse_response(
            body.as_bytes().to_vec(),
            &["sparse-index line 2", "duplicate version", "line 1"],
        )
        .await;
    }

    #[tokio::test]
    async fn rejects_oversized_sparse_index_lines() {
        let padding = "x".repeat(CRATES_IO_MAX_INDEX_LINE_BYTES);
        let body = format!(
            "{{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":false,\"padding\":\"{padding}\"}}\n"
        );

        assert_invalid_sparse_response(body.into_bytes(), &["sparse-index line 1", "line exceeds"])
            .await;
    }

    #[test]
    fn osv_query_preserves_nuget_display_case() {
        let package = nuget_package("Newtonsoft.Json");

        let body = osv_query_body(&[package]);

        assert_eq!(
            body.pointer("/queries/0/package/name")
                .and_then(Value::as_str),
            Some("Newtonsoft.Json")
        );
        assert_eq!(
            body.pointer("/queries/0/package/ecosystem")
                .and_then(Value::as_str),
            Some("NuGet")
        );
    }

    #[test]
    fn validates_osv_database_scoped_ids() {
        for id in [
            "OSV-2020-111",
            "GHSA-vp9c-fpxx-744v",
            "DEBIAN-CVE-2000-0001",
            "x_CUSTOM-0001",
        ] {
            assert!(valid_osv_id(id), "expected {id:?} to be valid");
        }
        for id in [
            "",
            "unscoped",
            "-missing-db",
            "GHSA-",
            "GHSA---",
            "GHSA-not valid",
        ] {
            assert!(!valid_osv_id(id), "expected {id:?} to be invalid");
        }
    }

    #[tokio::test]
    async fn online_osv_query_uses_canonical_nuget_case() {
        let server = MockServer::start().await;
        let package = nuget_package("Newtonsoft.Json");
        let expected_body = json!({
            "queries": [{
                "package": {
                    "name": "Newtonsoft.Json",
                    "ecosystem": "NuGet"
                },
                "version": "12.0.1"
            }]
        });
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(&expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "vulns": [osv_query_vulnerability("GHSA-5crp-9r3c-p9vr")]
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache, server.uri());

        let results = client.query_batch(&[package]).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].len(), 1);
        assert_eq!(results[0][0].id, "GHSA-5crp-9r3c-p9vr");
    }

    #[tokio::test]
    async fn paginates_queries_independently_and_caches_complete_deduplicated_ids() {
        let server = MockServer::start().await;
        let packages = vec![npm_package("alpha"), npm_package("beta")];
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(&packages)))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {
                        "vulns": [
                            osv_query_vulnerability("TEST-ALPHA-1"),
                            osv_query_vulnerability("TEST-ALPHA-DUP")
                        ],
                        "next_page_token": "alpha-page-2"
                    },
                    {
                        "vulns": [osv_query_vulnerability("TEST-BETA-1")],
                        "next_page_token": "beta-page-2"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body_with_tokens(&[
                (&packages[0], Some("alpha-page-2")),
                (&packages[1], Some("beta-page-2")),
            ])))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {
                        "vulns": [
                            osv_query_vulnerability("TEST-ALPHA-DUP"),
                            osv_query_vulnerability("TEST-ALPHA-2")
                        ]
                    },
                    {
                        "vulns": [
                            osv_query_vulnerability("TEST-BETA-1"),
                            osv_query_vulnerability("TEST-BETA-2")
                        ],
                        "next_page_token": "beta-page-3"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body_with_tokens(&[(
                &packages[1],
                Some("beta-page-3"),
            )])))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "vulns": [osv_query_vulnerability("TEST-BETA-3")]
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        for id in ["TEST-ALPHA-1", "TEST-ALPHA-2", "TEST-ALPHA-DUP"] {
            cache_osv_document(&cache, &packages[0], id);
        }
        for id in ["TEST-BETA-1", "TEST-BETA-2", "TEST-BETA-3"] {
            cache_osv_document(&cache, &packages[1], id);
        }
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let results = client.query(&packages).await.unwrap();

        assert_eq!(
            results.vulnerabilities[&packages[0].key()]
                .iter()
                .map(|vulnerability| vulnerability.id.as_str())
                .collect::<Vec<_>>(),
            ["TEST-ALPHA-1", "TEST-ALPHA-2", "TEST-ALPHA-DUP"]
        );
        assert_eq!(
            results.vulnerabilities[&packages[1].key()]
                .iter()
                .map(|vulnerability| vulnerability.id.as_str())
                .collect::<Vec<_>>(),
            ["TEST-BETA-1", "TEST-BETA-2", "TEST-BETA-3"]
        );
        for (package, expected) in [
            (
                &packages[0],
                json!([
                    osv_query_vulnerability("TEST-ALPHA-1"),
                    osv_query_vulnerability("TEST-ALPHA-2"),
                    osv_query_vulnerability("TEST-ALPHA-DUP")
                ]),
            ),
            (
                &packages[1],
                json!([
                    osv_query_vulnerability("TEST-BETA-1"),
                    osv_query_vulnerability("TEST-BETA-2"),
                    osv_query_vulnerability("TEST-BETA-3")
                ]),
            ),
        ] {
            let (cached, _) = cache
                .get(
                    "osv/query",
                    &osv_query_cache_key(package),
                    Duration::seconds(OSV_QUERY_TTL_SECS),
                )
                .expect("complete paginated query cache entry");
            assert_eq!(cached, expected);
        }
        server.verify().await;
    }

    #[tokio::test]
    async fn rejects_a_regressing_osv_query_revision_without_downgrading_cache() {
        let server = MockServer::start().await;
        let package = npm_package("regressing-revision");
        let id = "TEST-REGRESSION-1";
        let older = "2026-08-18T00:00:00Z";
        let newer = "2026-08-19T00:00:00Z";
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(std::slice::from_ref(&package))))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [osv_query_vulnerability_at(id, older)]}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let query_key = osv_query_cache_key(&package);
        cache
            .put(
                "osv/query",
                &query_key,
                &json!([osv_query_vulnerability_at(id, newer)]),
                None,
            )
            .unwrap();
        age_cache_entry(&cache, "osv/query", &query_key, Duration::hours(2));
        let before = read_cache_entry(&cache, "osv/query", &query_key);
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let error = client
            .query(std::slice::from_ref(&package))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("regressed below"));
        let after = read_cache_entry(&cache, "osv/query", &query_key);
        assert_eq!(after.stored_at, before.stored_at);
        assert_eq!(after.value, before.value);
        server.verify().await;
    }

    #[test]
    fn hydration_cache_keys_never_downgrade_newer_alias_documents() {
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client = OsvClient::with_base_url(
            HttpClient::new().unwrap(),
            cache.clone(),
            "https://unused.invalid",
        );
        let id = "TEST-HYDRATION-MONOTONIC-1";
        let requested = OsvVulnerabilityRevision {
            id: id.to_owned(),
            modified: DateTime::parse_from_rfc3339("2026-08-18T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        let newer_document = json!({
            "id": id,
            "modified": "2026-08-20T00:00:00Z",
            "summary": "newer alias document",
            "affected": []
        });
        let older_document = json!({
            "id": id,
            "modified": "2026-08-19T00:00:00Z",
            "summary": "late older document",
            "affected": []
        });
        cache
            .put("osv/vuln", &requested.cache_key(), &newer_document, None)
            .unwrap();

        let winner = client
            .publish_hydrated_document(&requested.cache_key(), id, &older_document, None, true)
            .unwrap();

        assert_eq!(winner.value, newer_document);
        assert_eq!(
            read_cache_entry(&cache, "osv/vuln", &requested.cache_key()).value,
            newer_document
        );
    }

    #[test]
    fn cache_bypass_publication_preserves_the_newer_disk_winner() {
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy {
                read: false,
                max_age: None,
            },
        };
        let client = OsvClient::with_base_url(
            HttpClient::new().unwrap(),
            cache.clone(),
            "https://unused.invalid",
        );
        let id = "TEST-HYDRATION-BYPASS-1";
        let revision = OsvVulnerabilityRevision {
            id: id.to_owned(),
            modified: DateTime::parse_from_rfc3339("2026-08-18T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        let cached_newer = json!({
            "id": id,
            "modified": "2026-08-20T00:00:00Z",
            "summary": "cached representation",
            "affected": []
        });
        let network_candidate = json!({
            "id": id,
            "modified": "2026-08-19T00:00:00Z",
            "summary": "network representation",
            "affected": []
        });
        cache
            .put("osv/vuln", &revision.cache_key(), &cached_newer, None)
            .unwrap();

        let reported = client
            .publish_hydrated_document(&revision.cache_key(), id, &network_candidate, None, true)
            .unwrap();

        assert_eq!(reported.value, cached_newer);
        assert_eq!(
            read_cache_entry(&cache, "osv/vuln", &revision.cache_key()).value,
            cached_newer
        );
    }

    #[tokio::test]
    async fn newer_hydration_is_reused_under_the_requested_revision_without_etag_aliasing() {
        let server = MockServer::start().await;
        let id = "TEST-HYDRATION-ALIAS-1";
        let requested = OsvVulnerabilityRevision {
            id: id.to_owned(),
            modified: DateTime::parse_from_rfc3339("2026-08-18T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        let actual = OsvVulnerabilityRevision {
            id: id.to_owned(),
            modified: DateTime::parse_from_rfc3339("2026-08-19T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        let document = json!({
            "id": id,
            "modified": "2026-08-19T00:00:00Z",
            "summary": "newer than querybatch",
            "affected": []
        });
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{id}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"hydration-2\"")
                    .set_body_json(&document),
            )
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let first = client.hydrate(&requested).await.unwrap();
        assert_eq!(first.value, document);
        assert!(first.cache_warning.is_none());
        let second = client.hydrate(&requested).await.unwrap();
        assert_eq!(second.value, document);
        assert!(second.cache_warning.is_none());

        let actual_entry = read_cache_entry(&cache, "osv/vuln", &actual.cache_key());
        assert_eq!(actual_entry.value, document);
        assert_eq!(actual_entry.etag.as_deref(), Some("\"hydration-2\""));
        let alias_entry = read_cache_entry(&cache, "osv/vuln", &requested.cache_key());
        assert_eq!(alias_entry.value, document);
        assert!(alias_entry.etag.is_none());
        server.verify().await;
    }

    #[tokio::test]
    async fn future_hydration_entry_is_not_reused_without_network_validation() {
        let server = MockServer::start().await;
        let id = "TEST-HYDRATION-FUTURE-1";
        let revision = OsvVulnerabilityRevision {
            id: id.to_owned(),
            modified: test_timestamp(TEST_OSV_MODIFIED),
        };
        let cached_document = json!({
            "id": id,
            "modified": TEST_OSV_MODIFIED,
            "summary": "future-dated cached representation",
            "affected": []
        });
        let network_document = json!({
            "id": id,
            "modified": TEST_OSV_MODIFIED,
            "summary": "network-validated representation",
            "affected": []
        });
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&network_document))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        cache
            .put("osv/vuln", &revision.cache_key(), &cached_document, None)
            .unwrap();
        set_cache_entry_timestamp(
            &cache,
            "osv/vuln",
            &revision.cache_key(),
            Utc::now() + Duration::days(1),
        );
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let reported = client.hydrate(&revision).await.unwrap();

        assert_eq!(reported.value, network_document);
        assert!(reported.cache_warning.is_none());
        assert_eq!(
            read_cache_entry(&cache, "osv/vuln", &revision.cache_key()).value,
            cached_document,
            "the future entry remains only as a raw CAS generation, not a reusable result"
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn cache_bypass_returns_network_hydration_but_aliases_the_newer_disk_winner() {
        let server = MockServer::start().await;
        let id = "TEST-HYDRATION-BYPASS-ALIAS-1";
        let requested = OsvVulnerabilityRevision {
            id: id.to_owned(),
            modified: DateTime::parse_from_rfc3339("2026-08-18T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        let actual = OsvVulnerabilityRevision {
            id: id.to_owned(),
            modified: DateTime::parse_from_rfc3339("2026-08-19T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        let network_document = json!({
            "id": id,
            "modified": "2026-08-19T00:00:00Z",
            "summary": "fresh network representation",
            "affected": []
        });
        let cached_newer = json!({
            "id": id,
            "modified": "2026-08-20T00:00:00Z",
            "summary": "newer cached representation",
            "affected": []
        });
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&network_document))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy {
                read: false,
                max_age: None,
            },
        };
        cache
            .put(
                "osv/vuln",
                &actual.cache_key(),
                &cached_newer,
                Some("\"hydration-3\"".to_owned()),
            )
            .unwrap();
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let reported = client.hydrate(&requested).await.unwrap();

        assert_eq!(reported.value, network_document);
        assert!(reported.cache_warning.is_none());
        assert_eq!(
            read_cache_entry(&cache, "osv/vuln", &actual.cache_key()).value,
            cached_newer
        );
        let alias = read_cache_entry(&cache, "osv/vuln", &requested.cache_key());
        assert_eq!(alias.value, cached_newer);
        assert!(alias.etag.is_none());
        server.verify().await;
    }

    #[tokio::test]
    async fn cache_bypass_ignores_a_future_dated_stale_osv_revision() {
        let server = MockServer::start().await;
        let package = npm_package("bypass-future-revision");
        let id = "TEST-BYPASS-FUTURE-1";
        let origin_modified = "2026-08-19T00:00:00Z";
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(std::slice::from_ref(&package))))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "vulns": [osv_query_vulnerability_at(id, origin_modified)]
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": id,
                "modified": origin_modified,
                "summary": "fresh bypass response",
                "affected": [{
                    "package": {"ecosystem": "npm", "name": "bypass-future-revision"},
                    "versions": ["1.0.0"]
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy {
                read: false,
                max_age: None,
            },
        };
        let query_key = osv_query_cache_key(&package);
        cache
            .put(
                "osv/query",
                &query_key,
                &json!([osv_query_vulnerability_at(id, "2026-08-21T00:00:00Z")]),
                None,
            )
            .unwrap();
        set_cache_entry_timestamp(
            &cache,
            "osv/query",
            &query_key,
            Utc::now() + Duration::days(1),
        );
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let result = client.query(std::slice::from_ref(&package)).await.unwrap();

        assert_eq!(
            result.vulnerabilities[&package.key()][0].summary,
            "fresh bypass response"
        );
        assert_eq!(
            read_cache_entry(&cache, "osv/query", &query_key).value,
            json!([osv_query_vulnerability_at(id, origin_modified)])
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn concurrent_osv_query_refresh_retries_instead_of_publishing_stale_results() {
        let server = MockServer::start().await;
        let package = npm_package("query-race");
        let id = "TEST-QUERY-RACE-1";
        let initial = "2026-08-17T00:00:00Z";
        let older = "2026-08-18T00:00:00Z";
        let newer = "2026-08-19T00:00:00Z";
        let slow_received = Arc::new(tokio::sync::Notify::new());
        let slow_responder_received = slow_received.clone();
        let slow_calls = Arc::new(AtomicUsize::new(0));
        let responder_calls = slow_calls.clone();
        Mock::given(method("POST"))
            .and(path("/slow/v1/querybatch"))
            .and(body_json(osv_query_body(std::slice::from_ref(&package))))
            .respond_with(move |_: &wiremock::Request| {
                if responder_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    slow_responder_received.notify_one();
                    ResponseTemplate::new(200)
                        .set_body_json(json!({
                            "results": [{
                                "vulns": [osv_query_vulnerability_at(id, older)]
                            }]
                        }))
                        .set_delay(std::time::Duration::from_secs(1))
                } else {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "results": [{
                            "vulns": [osv_query_vulnerability_at(id, newer)]
                        }]
                    }))
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/fast/v1/querybatch"))
            .and(body_json(osv_query_body(std::slice::from_ref(&package))))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [osv_query_vulnerability_at(id, newer)]}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let newer_document = json!({
            "id": id,
            "modified": newer,
            "summary": "newest concurrent revision",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "query-race"},
                "versions": ["1.0.0"]
            }]
        });
        Mock::given(method("GET"))
            .and(path(format!("/fast/v1/vulns/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&newer_document))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/slow/v1/vulns/{id}")))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let query_key = osv_query_cache_key(&package);
        cache
            .put(
                "osv/query",
                &query_key,
                &json!([osv_query_vulnerability_at(id, initial)]),
                None,
            )
            .unwrap();
        age_cache_entry(&cache, "osv/query", &query_key, Duration::hours(2));
        let slow_client = OsvClient::with_base_url(
            HttpClient::new().unwrap(),
            cache.clone(),
            format!("{}/slow", server.uri()),
        );
        let fast_client = OsvClient::with_base_url(
            HttpClient::new().unwrap(),
            cache.clone(),
            format!("{}/fast", server.uri()),
        );
        let slow_package = package.clone();
        let slow_started = slow_received.notified();
        let slow =
            tokio::spawn(
                async move { slow_client.query(std::slice::from_ref(&slow_package)).await },
            );
        tokio::time::timeout(std::time::Duration::from_secs(2), slow_started)
            .await
            .expect("slow OSV query request was not received");

        let fast = fast_client
            .query(std::slice::from_ref(&package))
            .await
            .unwrap();
        let slow = slow.await.unwrap().unwrap();

        assert_eq!(
            fast.vulnerabilities[&package.key()][0].summary,
            "newest concurrent revision"
        );
        assert_eq!(
            slow.vulnerabilities[&package.key()][0].summary,
            "newest concurrent revision"
        );
        assert_eq!(slow_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            read_cache_entry(&cache, "osv/query", &query_key).value,
            json!([osv_query_vulnerability_at(id, newer)])
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn query_revisions_invalidate_legacy_and_changed_hydrated_advisories() {
        let package = npm_package("revisioned");
        let id = "TEST-REVISION-1";
        let first_modified = "2026-08-18T00:00:00Z";
        let second_modified = "2026-08-19T00:00:00Z";
        let first_document = json!({
            "id": id,
            "modified": first_modified,
            "summary": "first revision",
            "severity": [{
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
            }],
            "affected": [{
                "package": {"ecosystem": "npm", "name": "revisioned"},
                "ranges": [{
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]
                }]
            }]
        });
        let second_document = json!({
            "id": id,
            "modified": second_modified,
            "withdrawn": "2026-08-19T00:00:00Z",
            "summary": "updated revision",
            "severity": [{
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }],
            "affected": [{
                "package": {"ecosystem": "npm", "name": "revisioned"},
                "ranges": [{
                    "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]
                }]
            }]
        });
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        // These are the two legacy ID-only cache shapes. Neither may be treated as revisioned.
        cache
            .put(
                "osv/query",
                &osv_query_cache_key(&package),
                &json!([id]),
                None,
            )
            .unwrap();
        cache.put("osv/vuln", id, &first_document, None).unwrap();

        let first_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(std::slice::from_ref(&package))))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "vulns": [osv_query_vulnerability_at(id, first_modified)]
                }]
            })))
            .expect(1)
            .mount(&first_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&first_document))
            .expect(1)
            .mount(&first_server)
            .await;
        let first_client = OsvClient::with_base_url(
            HttpClient::new().unwrap(),
            cache.clone(),
            first_server.uri(),
        );

        let first = first_client
            .query(std::slice::from_ref(&package))
            .await
            .unwrap();
        let first = &first.vulnerabilities[&package.key()][0];
        assert_eq!(first.summary, "first revision");
        assert_eq!(first.fixed_in, ["2.0.0"]);
        assert!(!first.withdrawn);
        let first_score = first.cvss_score.unwrap();
        first_server.verify().await;

        age_cache_entry(
            &cache,
            "osv/query",
            &osv_query_cache_key(&package),
            Duration::hours(2),
        );
        let second_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(std::slice::from_ref(&package))))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "vulns": [osv_query_vulnerability_at(id, second_modified)]
                }]
            })))
            .expect(1)
            .mount(&second_server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&second_document))
            .expect(1)
            .mount(&second_server)
            .await;
        let second_client = OsvClient::with_base_url(
            HttpClient::new().unwrap(),
            cache.clone(),
            second_server.uri(),
        );

        let second = second_client
            .query(std::slice::from_ref(&package))
            .await
            .unwrap();
        let second = &second.vulnerabilities[&package.key()][0];
        assert_eq!(second.summary, "updated revision");
        assert_eq!(second.fixed_in, ["3.0.0"]);
        assert!(second.withdrawn);
        assert!(second.cvss_score.unwrap() > first_score);
        second_server.verify().await;

        // Refreshing the query with an unchanged revision must reuse the hydrated revision cache.
        age_cache_entry(
            &cache,
            "osv/query",
            &osv_query_cache_key(&package),
            Duration::hours(2),
        );
        let unchanged_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(std::slice::from_ref(&package))))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "vulns": [osv_query_vulnerability_at(id, second_modified)]
                }]
            })))
            .expect(1)
            .mount(&unchanged_server)
            .await;
        let unchanged_client = OsvClient::with_base_url(
            HttpClient::new().unwrap(),
            cache.clone(),
            unchanged_server.uri(),
        );

        let unchanged = unchanged_client
            .query(std::slice::from_ref(&package))
            .await
            .unwrap();

        assert_eq!(
            unchanged.vulnerabilities[&package.key()][0].summary,
            "updated revision"
        );
        unchanged_server.verify().await;
        let cached_query = read_cache_entry(&cache, "osv/query", &osv_query_cache_key(&package));
        assert_eq!(
            cached_query.value,
            json!([osv_query_vulnerability_at(id, second_modified)])
        );
    }

    #[tokio::test]
    async fn rejects_repeated_page_tokens_without_caching_partial_ids() {
        let server = MockServer::start().await;
        let package = npm_package("repeated-token");
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(std::slice::from_ref(&package))))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "vulns": [osv_query_vulnerability("TEST-PARTIAL-1")],
                    "next_page_token": "repeat-me"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body_with_tokens(&[(
                &package,
                Some("repeat-me"),
            )])))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "vulns": [osv_query_vulnerability("TEST-PARTIAL-2")],
                    "next_page_token": "repeat-me"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let error = client
            .query(std::slice::from_ref(&package))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("repeated a next_page_token"));
        assert!(
            !cache
                .filename("osv/query", &osv_query_cache_key(&package))
                .exists()
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn later_page_failure_does_not_cache_the_partial_query() {
        let server = MockServer::start().await;
        let package = npm_package("page-failure");
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(std::slice::from_ref(&package))))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "vulns": [osv_query_vulnerability("TEST-PARTIAL-1")],
                    "next_page_token": "broken-page"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body_with_tokens(&[(
                &package,
                Some("broken-page"),
            )])))
            .respond_with(ResponseTemplate::new(400))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let error = client
            .query(std::slice::from_ref(&package))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("HTTP 400"));
        assert!(
            !cache
                .filename("osv/query", &osv_query_cache_key(&package))
                .exists()
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn later_page_failure_is_soft_for_only_the_still_pending_package() {
        let server = MockServer::start().await;
        let packages = vec![npm_package("page-complete"), npm_package("page-incomplete")];
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(&packages)))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {},
                    {
                        "vulns": [osv_query_vulnerability("TEST-PARTIAL-PAGE")],
                        "next_page_token": "broken-page"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body_with_tokens(&[(
                &packages[1],
                Some("broken-page"),
            )])))
            .respond_with(ResponseTemplate::new(400))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let outcome = client.query(&packages).await.unwrap();

        assert!(outcome.vulnerabilities[&packages[0].key()].is_empty());
        assert!(!outcome.vulnerabilities.contains_key(&packages[1].key()));
        assert!(!outcome.errors.contains_key(&packages[0].key()));
        assert!(
            outcome.errors[&packages[1].key()][0]
                .message
                .contains("HTTP 400")
        );
        assert!(
            cache
                .filename("osv/query", &osv_query_cache_key(&packages[0]))
                .exists()
        );
        assert!(
            !cache
                .filename("osv/query", &osv_query_cache_key(&packages[1]))
                .exists()
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn failed_query_chunk_is_soft_when_another_chunk_completes() {
        let server = MockServer::start().await;
        let packages = (0..1001)
            .map(|index| npm_package(&format!("chunk-{index}")))
            .collect::<Vec<_>>();
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(&packages[..1000])))
            .respond_with(ResponseTemplate::new(400))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(&packages[1000..])))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": [{}]})))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let outcome = client.query(&packages).await.unwrap();

        assert_eq!(outcome.errors.len(), 1000);
        assert!(outcome.vulnerabilities[&packages[1000].key()].is_empty());
        assert!(!outcome.errors.contains_key(&packages[1000].key()));
        assert!(
            !cache
                .filename("osv/query", &osv_query_cache_key(&packages[0]))
                .exists()
        );
        assert!(
            cache
                .filename("osv/query", &osv_query_cache_key(&packages[1000]))
                .exists()
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn query_cache_failure_does_not_discard_a_valid_network_result() {
        let server = MockServer::start().await;
        let package = npm_package("query-cache-unwritable");
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(std::slice::from_ref(&package))))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": [{}]})))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        fs::write(cache_dir.path().join("osv"), b"not a directory").unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache, server.uri());

        let outcome = client.query(std::slice::from_ref(&package)).await.unwrap();

        assert!(outcome.vulnerabilities[&package.key()].is_empty());
        assert!(
            outcome.errors[&package.key()]
                .iter()
                .any(|error| error.message.contains("query cache publication failed"))
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn hydration_cache_failure_does_not_discard_a_valid_advisory() {
        let server = MockServer::start().await;
        let package = npm_package("hydration-cache-unwritable");
        let advisory = "TEST-CACHE-WARNING";
        let revision = OsvVulnerabilityRevision {
            id: advisory.to_owned(),
            modified: test_timestamp(TEST_OSV_MODIFIED),
        };
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{advisory}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": advisory,
                "modified": TEST_OSV_MODIFIED,
                "summary": "valid advisory despite an unwritable cache",
                "affected": [{
                    "package": {"ecosystem": "npm", "name": package.name},
                    "versions": [package.version]
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        cache
            .put(
                "osv/query",
                &osv_query_cache_key(&package),
                &serde_json::to_value(vec![revision]).unwrap(),
                None,
            )
            .unwrap();
        fs::write(cache.root().join("osv/vuln"), b"not a directory").unwrap();
        let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache, server.uri());

        let outcome = client.query(std::slice::from_ref(&package)).await.unwrap();

        assert_eq!(outcome.vulnerabilities[&package.key()].len(), 1);
        assert_eq!(outcome.vulnerabilities[&package.key()][0].id, advisory);
        assert!(
            outcome.errors[&package.key()]
                .iter()
                .any(|error| error.message.contains("cache publication failed"))
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn malformed_affected_hydration_fails_hard_without_entering_the_cache() {
        let server = MockServer::start().await;
        let package = npm_package("malformed-affected");
        let advisory = "TEST-MALFORMED-AFFECTED";
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(std::slice::from_ref(&package))))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [osv_query_vulnerability(advisory)]}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{advisory}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": advisory,
                "modified": TEST_OSV_MODIFIED,
                "affected": {"package": "not-an-array"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let error = client
            .query(std::slice::from_ref(&package))
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("affected must be a present array")
        );
        let revision = OsvVulnerabilityRevision {
            id: advisory.to_owned(),
            modified: test_timestamp(TEST_OSV_MODIFIED),
        };
        assert!(!cache.filename("osv/vuln", &revision.cache_key()).exists());
        server.verify().await;
    }

    #[tokio::test]
    async fn malformed_security_fields_fail_hydration_without_entering_the_cache() {
        let package = npm_package("malformed-security-fields");
        let mut cases = Vec::new();

        let mut document = valid_osv_document_value("TEST-MISSING-AFFECTED", &package);
        document.as_object_mut().unwrap().remove("affected");
        cases.push((
            "TEST-MISSING-AFFECTED",
            document,
            "affected must be a present array",
        ));

        let mut document = valid_osv_document_value("TEST-MALFORMED-IDENTITY", &package);
        document["affected"][0]["package"]["name"] = Value::Null;
        cases.push((
            "TEST-MALFORMED-IDENTITY",
            document,
            "package.name must be a string",
        ));

        for (id, value, expected) in [
            ("TEST-NULL-WITHDRAWN", Value::Null, "RFC 3339 string"),
            ("TEST-BOOL-WITHDRAWN", json!(false), "RFC 3339 string"),
            (
                "TEST-BAD-WITHDRAWN",
                json!("not-a-timestamp"),
                "valid RFC 3339 timestamp",
            ),
        ] {
            let mut document = valid_osv_document_value(id, &package);
            document["withdrawn"] = value;
            cases.push((id, document, expected));
        }

        for (advisory, document, expected) in cases {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .and(body_json(osv_query_body(std::slice::from_ref(&package))))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "results": [{"vulns": [osv_query_vulnerability(advisory)]}]
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{advisory}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(document))
                .expect(1)
                .mount(&server)
                .await;
            let cache_dir = tempfile::tempdir().unwrap();
            let cache = Cache {
                root: cache_dir.path().to_path_buf(),
                policy: CachePolicy::default(),
            };
            let client =
                OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

            let error = client
                .query(std::slice::from_ref(&package))
                .await
                .unwrap_err();

            assert!(
                error.to_string().contains(expected),
                "{advisory}: expected {expected:?}, got {error}"
            );
            let revision = OsvVulnerabilityRevision {
                id: advisory.to_owned(),
                modified: test_timestamp(TEST_OSV_MODIFIED),
            };
            assert!(
                !cache.filename("osv/vuln", &revision.cache_key()).exists(),
                "{advisory}: malformed hydration entered the cache"
            );
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn malformed_hydration_cache_is_bypassed_and_replaced() {
        let server = MockServer::start().await;
        let package = npm_package("malformed-cached-advisory");
        let advisory = "TEST-MALFORMED-CACHED-ADVISORY";
        let revision = OsvVulnerabilityRevision {
            id: advisory.to_owned(),
            modified: test_timestamp(TEST_OSV_MODIFIED),
        };
        let mut malformed = valid_osv_document_value(advisory, &package);
        malformed["withdrawn"] = Value::Null;
        let valid = valid_osv_document_value(advisory, &package);

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{advisory}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(&valid))
            .expect(1)
            .mount(&server)
            .await;

        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        cache
            .put(
                "osv/query",
                &osv_query_cache_key(&package),
                &serde_json::to_value(std::slice::from_ref(&revision)).unwrap(),
                None,
            )
            .unwrap();
        cache
            .put("osv/vuln", &revision.cache_key(), &malformed, None)
            .unwrap();
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let outcome = client.query(std::slice::from_ref(&package)).await.unwrap();

        assert_eq!(outcome.vulnerabilities[&package.key()].len(), 1);
        assert_eq!(outcome.vulnerabilities[&package.key()][0].id, advisory);
        let cached = read_cache_entry(&cache, "osv/vuln", &revision.cache_key());
        assert_eq!(cached.value, valid);
        server.verify().await;
    }

    #[tokio::test]
    async fn query_hits_require_a_matching_evaluable_affected_entry() {
        let package = npm_package("query-hit-shape");
        let cases = [
            ("TEST-EMPTY-AFFECTED", json!([])),
            (
                "TEST-WRONG-AFFECTED-IDENTITY",
                json!([{
                    "package": {"ecosystem": "npm", "name": "another-package"},
                    "versions": ["1.0.0"]
                }]),
            ),
            (
                "TEST-NON-EVALUABLE-AFFECTED",
                json!([{
                    "package": {"ecosystem": "npm", "name": "query-hit-shape"},
                    "versions": [],
                    "ranges": []
                }]),
            ),
        ];

        for (advisory, affected) in cases {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .and(body_json(osv_query_body(std::slice::from_ref(&package))))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "results": [{"vulns": [osv_query_vulnerability(advisory)]}]
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{advisory}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "id": advisory,
                    "modified": TEST_OSV_MODIFIED,
                    "affected": affected
                })))
                .expect(1)
                .mount(&server)
                .await;
            let cache_dir = tempfile::tempdir().unwrap();
            let cache = Cache {
                root: cache_dir.path().to_path_buf(),
                policy: CachePolicy::default(),
            };
            let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache, server.uri());

            let error = client
                .query(std::slice::from_ref(&package))
                .await
                .unwrap_err();

            assert!(
                error
                    .to_string()
                    .contains("no matching evaluable affected entry"),
                "{advisory}: unexpected error {error}"
            );
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn hydration_and_evaluation_failures_preserve_other_advisories() {
        let server = MockServer::start().await;
        let package = npm_package("partial-advisories");
        let hydration_failure = "TEST-HYDRATION-FAILURE";
        let evaluation_failure = "TEST-EVALUATION-FAILURE";
        let malformed_affected = "TEST-MALFORMED-AFFECTED-SOFT";
        let mismatched_identity = "TEST-MISMATCHED-IDENTITY-SOFT";
        let invalid_withdrawn = "TEST-INVALID-WITHDRAWN-SOFT";
        let valid = "TEST-VALID-ADVISORY";
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(std::slice::from_ref(&package))))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [
                    osv_query_vulnerability(hydration_failure),
                    osv_query_vulnerability(evaluation_failure),
                    osv_query_vulnerability(malformed_affected),
                    osv_query_vulnerability(mismatched_identity),
                    osv_query_vulnerability(invalid_withdrawn),
                    osv_query_vulnerability(valid)
                ]}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{mismatched_identity}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": mismatched_identity,
                "modified": TEST_OSV_MODIFIED,
                "affected": [{
                    "package": {"ecosystem": "npm", "name": "another-package"},
                    "versions": ["1.0.0"]
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{invalid_withdrawn}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": invalid_withdrawn,
                "modified": TEST_OSV_MODIFIED,
                "withdrawn": null,
                "affected": [{
                    "package": {"ecosystem": "npm", "name": "partial-advisories"},
                    "versions": ["1.0.0"]
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{malformed_affected}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": malformed_affected,
                "modified": TEST_OSV_MODIFIED,
                "affected": "not-an-array"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{hydration_failure}")))
            .respond_with(ResponseTemplate::new(400))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{evaluation_failure}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": evaluation_failure,
                "modified": TEST_OSV_MODIFIED,
                "summary": "cannot evaluate a commit graph",
                "affected": [{
                    "package": {"ecosystem": "npm", "name": "partial-advisories"},
                    "ranges": [{
                        "type": "GIT",
                        "repo": "https://example.invalid/partial-advisories.git",
                        "events": [{"introduced": "0"}]
                    }]
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{valid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": valid,
                "modified": TEST_OSV_MODIFIED,
                "summary": "valid advisory",
                "affected": [{
                    "package": {"ecosystem": "npm", "name": "partial-advisories"},
                    "versions": ["1.0.0"]
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let outcome = client.query(std::slice::from_ref(&package)).await.unwrap();

        assert_eq!(outcome.vulnerabilities[&package.key()].len(), 1);
        assert_eq!(outcome.vulnerabilities[&package.key()][0].id, valid);
        let messages = outcome.errors[&package.key()]
            .iter()
            .map(|error| error.message.as_str())
            .collect::<Vec<_>>();
        assert!(messages.iter().any(|message| {
            message.contains(hydration_failure) && message.contains("hydration failed")
        }));
        assert!(messages.iter().any(|message| {
            message.contains(evaluation_failure) && message.contains("evaluation failed")
        }));
        assert!(messages.iter().any(|message| {
            message.contains(malformed_affected) && message.contains("hydration failed")
        }));
        assert!(messages.iter().any(|message| {
            message.contains(mismatched_identity) && message.contains("evaluation failed")
        }));
        assert!(messages.iter().any(|message| {
            message.contains(invalid_withdrawn) && message.contains("hydration failed")
        }));
        let failed_revision = OsvVulnerabilityRevision {
            id: hydration_failure.to_owned(),
            modified: DateTime::parse_from_rfc3339(TEST_OSV_MODIFIED)
                .unwrap()
                .with_timezone(&Utc),
        };
        assert!(
            !cache
                .filename("osv/vuln", &failed_revision.cache_key())
                .exists()
        );
        let malformed_revision = OsvVulnerabilityRevision {
            id: malformed_affected.to_owned(),
            modified: test_timestamp(TEST_OSV_MODIFIED),
        };
        assert!(
            !cache
                .filename("osv/vuln", &malformed_revision.cache_key())
                .exists()
        );
        let invalid_withdrawn_revision = OsvVulnerabilityRevision {
            id: invalid_withdrawn.to_owned(),
            modified: test_timestamp(TEST_OSV_MODIFIED),
        };
        assert!(
            !cache
                .filename("osv/vuln", &invalid_withdrawn_revision.cache_key())
                .exists()
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn malformed_osv_batch_responses_fail_closed_without_query_cache_entries() {
        let cases = [
            (
                "non-object response",
                json!([]),
                1,
                "top-level value is not an object",
            ),
            (
                "missing results",
                json!({}),
                1,
                "required results field is missing",
            ),
            (
                "non-array results",
                json!({"results": {}}),
                1,
                "results field is not an array",
            ),
            (
                "too few results",
                json!({"results": [{}]}),
                2,
                "returned 1 results for 2 queries",
            ),
            (
                "too many results",
                json!({"results": [{}, {}, {}]}),
                2,
                "returned 3 results for 2 queries",
            ),
            (
                "non-object result",
                json!({"results": [null]}),
                1,
                "result 0 is not an object",
            ),
            (
                "non-empty result without vulns",
                json!({"results": [{"unexpected": true}]}),
                1,
                "result 0 is non-empty but has no vulns field",
            ),
            (
                "non-array vulns",
                json!({"results": [{"vulns": {}}]}),
                1,
                "result 0 has a non-array vulns field",
            ),
            (
                "non-string next page token",
                json!({"results": [{"vulns": [], "next_page_token": 42}]}),
                1,
                "result 0 has a non-string next_page_token field",
            ),
            (
                "empty next page token",
                json!({"results": [{"vulns": [], "next_page_token": ""}]}),
                1,
                "result 0 has an empty next_page_token field",
            ),
            (
                "non-object vulnerability",
                json!({"results": [{"vulns": ["GHSA-5crp-9r3c-p9vr"]}]}),
                1,
                "vulnerability 0 is not an object",
            ),
            (
                "missing vulnerability id",
                json!({"results": [{"vulns": [{"modified": "2026-08-19T00:00:00Z"}]}]}),
                1,
                "vulnerability 0 has no string id",
            ),
            (
                "non-string vulnerability id",
                json!({"results": [{"vulns": [{"id": 42}]}]}),
                1,
                "vulnerability 0 has no string id",
            ),
            (
                "missing modified timestamp",
                json!({"results": [{"vulns": [{"id": "TEST-MISSING-MODIFIED"}]}]}),
                1,
                "vulnerability 0 has no string modified timestamp",
            ),
            (
                "non-string modified timestamp",
                json!({"results": [{"vulns": [{
                    "id": "TEST-NONSTRING-MODIFIED",
                    "modified": 42
                }]}]}),
                1,
                "vulnerability 0 has no string modified timestamp",
            ),
            (
                "invalid modified timestamp",
                json!({"results": [{"vulns": [{
                    "id": "TEST-INVALID-MODIFIED",
                    "modified": "not-a-timestamp"
                }]}]}),
                1,
                "vulnerability 0 has an invalid modified timestamp",
            ),
            (
                "empty vulnerability id",
                json!({"results": [{"vulns": [{"id": ""}]}]}),
                1,
                "vulnerability 0 has an invalid id",
            ),
            (
                "unscoped vulnerability id",
                json!({"results": [{"vulns": [{"id": "invalid"}]}]}),
                1,
                "vulnerability 0 has an invalid id",
            ),
            (
                "whitespace vulnerability id",
                json!({"results": [{"vulns": [{"id": "GHSA-not valid"}]}]}),
                1,
                "vulnerability 0 has an invalid id",
            ),
        ];

        for (case, response, package_count, expected_message) in cases {
            let server = MockServer::start().await;
            let packages = (0..package_count)
                .map(|index| npm_package(&format!("fixture-{case}-{index}")))
                .collect::<Vec<_>>();
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .and(body_json(osv_query_body(&packages)))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&server)
                .await;
            let cache_dir = tempfile::tempdir().unwrap();
            let cache = Cache {
                root: cache_dir.path().to_path_buf(),
                policy: CachePolicy::default(),
            };
            let client =
                OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

            let error = client.query(&packages).await.unwrap_err();

            match error {
                ProviderError::InvalidResponse(message) => assert!(
                    message.contains(expected_message),
                    "{case}: expected {expected_message:?}, got {message:?}"
                ),
                other => panic!("{case}: expected InvalidResponse, got {other:?}"),
            }
            for package in &packages {
                assert!(
                    !cache
                        .filename("osv/query", &osv_query_cache_key(package))
                        .exists(),
                    "{case}: malformed response created a query cache entry for {}",
                    package.display_name
                );
            }
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn malformed_result_is_soft_when_an_aligned_package_result_is_complete() {
        let server = MockServer::start().await;
        let packages = vec![npm_package("valid-empty"), npm_package("malformed")];
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(&packages)))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {"vulns": []},
                    {"vulns": [{"id": null}]}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let outcome = client.query(&packages).await.unwrap();

        assert!(outcome.vulnerabilities[&packages[0].key()].is_empty());
        assert!(!outcome.vulnerabilities.contains_key(&packages[1].key()));
        assert!(
            outcome.errors[&packages[1].key()][0]
                .message
                .contains("result 1 vulnerability 0 has no string id")
        );
        assert!(
            cache
                .filename("osv/query", &osv_query_cache_key(&packages[0]))
                .exists()
        );
        assert!(
            !cache
                .filename("osv/query", &osv_query_cache_key(&packages[1]))
                .exists()
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn valid_empty_osv_batch_results_preserve_alignment_and_are_cached() {
        let server = MockServer::start().await;
        let packages = vec![npm_package("empty-object"), npm_package("empty-array")];
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(&packages)))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{}, {"vulns": []}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let results = client.query(&packages).await.unwrap();

        assert_eq!(results.vulnerabilities.len(), packages.len());
        for package in &packages {
            assert!(results.vulnerabilities[&package.key()].is_empty());
            let (cached, _) = cache
                .get(
                    "osv/query",
                    &osv_query_cache_key(package),
                    Duration::seconds(OSV_QUERY_TTL_SECS),
                )
                .unwrap();
            assert_eq!(cached, json!([]));
        }
        server.verify().await;
    }

    #[test]
    fn osv_cache_key_tracks_case_sensitive_request_not_package_identity() {
        let canonical = nuget_package("Newtonsoft.Json");
        let lowercase = nuget_package("newtonsoft.json");

        assert_eq!(canonical.key(), lowercase.key());
        assert_eq!(
            osv_query_cache_key(&canonical),
            "NuGet:Newtonsoft.Json:12.0.1"
        );
        assert_ne!(
            osv_query_cache_key(&canonical),
            osv_query_cache_key(&lowercase)
        );
    }

    #[test]
    fn nuget_registry_coordinates_stay_lowercase() {
        let canonical = nuget_package("Newtonsoft.Json");
        let uppercase = nuget_package("NEWTONSOFT.JSON");

        assert_eq!(
            nuget_registry_url(&canonical),
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json"
        );
        assert_eq!(
            nuget_registry_url(&canonical),
            nuget_registry_url(&uppercase)
        );
        assert_eq!(
            nuget_registry_cache_key(&canonical),
            "nuget:newtonsoft.json"
        );
        assert_eq!(
            nuget_registry_cache_key(&canonical),
            nuget_registry_cache_key(&uppercase)
        );
    }

    #[test]
    fn offline_nuget_matching_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::from_root(dir.path().join("cache"), CachePolicy::default()).unwrap();
        let offline_dir = cache.root().join("offline");
        fs::create_dir_all(&offline_dir).unwrap();
        let archive_path = offline_dir.join("NuGet.zip");
        let file = File::create(&archive_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file("GHSA-5crp-9r3c-p9vr.json", SimpleFileOptions::default())
            .unwrap();
        archive
            .write_all(
                serde_json::to_string(&json!({
                    "id": "GHSA-5crp-9r3c-p9vr",
                    "modified": TEST_OSV_MODIFIED,
                    "summary": "test advisory",
                    "affected": [{
                        "package": {
                            "ecosystem": "NuGet",
                            "name": "Newtonsoft.Json"
                        },
                        "ranges": [{
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "13.0.1"}
                            ]
                        }]
                    }]
                }))
                .unwrap()
                .as_bytes(),
            )
            .unwrap();
        archive.finish().unwrap();
        fs::write(
            archive_path.with_extension("synced-at"),
            Utc::now().to_rfc3339(),
        )
        .unwrap();

        let provider = OsvOffline::new(cache);
        let package = nuget_package("newtonsoft.json");

        let result = provider
            .query_blocking(std::slice::from_ref(&package))
            .unwrap();

        assert_eq!(result[&package.key()].len(), 1);
        assert_eq!(result[&package.key()][0].id, "GHSA-5crp-9r3c-p9vr");
    }

    #[tokio::test]
    async fn hydrated_and_offline_range_fixture_results_are_identical() {
        let fixtures = osv_range_fixtures();
        let packages = fixtures.iter().map(fixture_package).collect::<Vec<_>>();

        // Return each fixture ID even for intentionally unaffected cases. This makes the hydrated
        // document evaluator, rather than the mock batch response, authoritative. Fixtures are
        // queried independently so the ecosystem-wide wildcard case does not alter other cases.
        let server = MockServer::start().await;
        for (fixture, package) in fixtures.iter().zip(&packages) {
            let id = fixture.document.get("id").and_then(Value::as_str).unwrap();
            let mut hydrated_document = fixture.document.clone();
            hydrated_document
                .as_object_mut()
                .unwrap()
                .insert("modified".to_owned(), json!(TEST_OSV_MODIFIED));
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .and(body_json(osv_query_body(std::slice::from_ref(package))))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "results": [{"vulns": [osv_query_vulnerability(id)]}]
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(hydrated_document))
                .expect(1)
                .mount(&server)
                .await;
        }
        let online_cache = tempfile::tempdir().unwrap();
        let online = OsvClient::with_base_url(
            HttpClient::new().unwrap(),
            Cache {
                root: online_cache.path().to_path_buf(),
                policy: CachePolicy::default(),
            },
            server.uri(),
        );

        for (fixture, package) in fixtures.iter().zip(&packages) {
            let hydrated_result = online.query(std::slice::from_ref(package)).await;
            let hydrated = if fixture.name == "wrong package identity" {
                let error = hydrated_result.unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("no matching evaluable affected entry"),
                    "unexpected wrong-identity query error: {error}"
                );
                Vec::new()
            } else {
                let hydrated_results = hydrated_result.unwrap();
                let hydrated = hydrated_results.vulnerabilities[&package.key()]
                    .iter()
                    .map(|vulnerability| (vulnerability.id.clone(), vulnerability.fixed_in.clone()))
                    .collect::<Vec<_>>();
                assert_eq!(
                    !hydrated.is_empty(),
                    fixture.affected,
                    "fixture {:?} affected mismatch",
                    fixture.name
                );
                if let Some((_, fixed_in)) = hydrated.first() {
                    assert_eq!(
                        fixed_in, &fixture.fixed_in,
                        "fixture {:?} fixed versions mismatch",
                        fixture.name
                    );
                }
                hydrated
            };

            let dir = tempfile::tempdir().unwrap();
            let cache = Cache::from_root(dir.path().join("cache"), CachePolicy::default()).unwrap();
            write_fixture_archives(cache.root(), std::slice::from_ref(fixture));
            let offline_provider = OsvOffline::new(cache);
            let offline_results = offline_provider
                .query_blocking(std::slice::from_ref(package))
                .unwrap();
            let offline = offline_results[&package.key()]
                .iter()
                .map(|vulnerability| (vulnerability.id.clone(), vulnerability.fixed_in.clone()))
                .collect::<Vec<_>>();
            if fixture.name == "wrong package identity" {
                assert!(offline.is_empty());
                continue;
            }
            assert_eq!(
                offline, hydrated,
                "hydrated/offline mismatch for fixture {:?}",
                fixture.name
            );
        }
    }

    #[test]
    fn unsupported_ranges_fail_visibly_online_and_offline() {
        let document = json!({
            "id": "TEST-UNSUPPORTED-GIT",
            "modified": TEST_OSV_MODIFIED,
            "summary": "A package query cannot evaluate a commit graph",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "git-only"},
                "ranges": [{
                    "type": "GIT",
                    "repo": "https://example.invalid/repo.git",
                    "events": [{"introduced": "0000000000000000000000000000000000000000"}]
                }]
            }]
        });
        let package = Package::new(
            Ecosystem::Npm,
            "git-only",
            "1.0.0",
            PathBuf::from("package-lock.json"),
        );

        let online_error = vulnerability_from_osv(&document, Some(&package)).unwrap_err();
        assert!(
            online_error
                .to_string()
                .contains("unsupported OSV range type")
        );

        let dir = tempfile::tempdir().unwrap();
        let fixture = OsvRangeFixture {
            name: "unsupported GIT".to_owned(),
            ecosystem: "npm".to_owned(),
            package: "git-only".to_owned(),
            installed: "1.0.0".to_owned(),
            affected: false,
            fixed_in: vec![],
            document,
        };
        let cache = Cache::from_root(dir.path().join("cache"), CachePolicy::default()).unwrap();
        write_fixture_archives(cache.root(), std::slice::from_ref(&fixture));
        let offline = OsvOffline::new(cache);
        let offline_error = offline
            .query_blocking(std::slice::from_ref(&package))
            .unwrap_err();
        assert!(
            offline_error
                .to_string()
                .contains("unsupported OSV range type")
        );
    }

    #[test]
    fn selects_latest_pypi_release_regardless_of_response_order() {
        let data = json!({
            "2.34.2": [{"yanked": false}],
            "2.9.2": [{"yanked": false}],
            "2.32.5": [{"yanked": false}]
        });

        assert_eq!(
            select_pypi_release(data.as_object().unwrap(), "2.32.5"),
            Some("2.34.2".to_owned())
        );
    }

    #[test]
    fn excludes_fully_yanked_but_keeps_partially_yanked_pypi_releases() {
        let data = json!({
            "2.34.2": [{"yanked": true}, {"yanked": true}],
            "2.33.1": [{"yanked": true}, {"yanked": false}],
            "2.33.0": [{"yanked": false}]
        });

        assert_eq!(
            select_pypi_release(data.as_object().unwrap(), "2.32.5"),
            Some("2.33.1".to_owned())
        );
        assert!(pypi_release_is_yanked(&data["2.34.2"]));
        assert!(!pypi_release_is_yanked(&data["2.33.1"]));
        assert!(!pypi_release_is_yanked(&data["2.33.0"]));
    }

    #[test]
    fn follows_installed_pypi_prerelease_policy() {
        let data = json!({
            "3.0rc1": [{"yanked": false}],
            "2.34.2": [{"yanked": false}],
            "not a version": [{"yanked": false}]
        });
        let releases = data.as_object().unwrap();

        assert_eq!(
            select_pypi_release(releases, "2.32.5"),
            Some("2.34.2".to_owned())
        );
        assert_eq!(
            select_pypi_release(releases, "3.0b1"),
            Some("3.0rc1".to_owned())
        );
    }

    #[test]
    fn selects_latest_valid_stable_nuget_release() {
        let versions = [
            "1.9.0",
            "2.0.0-rc.10",
            "not-a-version",
            "1.10.0",
            "2.0.0+build-sha",
            "2147483648.0.0",
        ];

        assert_eq!(
            select_nuget_release(versions),
            Some("2.0.0+build-sha".to_owned())
        );
        assert_eq!(
            select_nuget_release(["1.0.0-rc.2", "1.0.0-rc.10", "bad"]),
            None
        );
    }
}
