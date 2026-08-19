//! Network providers, disk cache, and OSV offline-dump support.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use cvss::Cvss;
use depscan_core::{
    Ecosystem, LatestVersions, NuGetVersion, Package, ProviderError, Severity, VersionProvider,
    VulnMap, VulnProvider, Vulnerability, classify_staleness, compare_versions,
    evaluate_osv_affected, normalize_name, pypi_version_is_prerelease, pypi_version_is_stable,
};
use directories::ProjectDirs;
use fs2::FileExt;
use futures::{StreamExt, stream};
use rand::RngExt;
use reqwest::{
    Client, StatusCode,
    header::{ACCEPT, ETAG, HeaderMap, HeaderValue, RETRY_AFTER},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration as StdDuration,
};
use tokio::{sync::Semaphore, time::sleep};
use tracing::debug;
use urlencoding::encode;
use zip::ZipArchive;

const USER_AGENT_VALUE: &str = concat!(
    "depscan/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/gedankrayze/depscan)"
);
const OSV_QUERY_TTL_SECS: i64 = 60 * 60;
const REGISTRY_TTL_SECS: i64 = 6 * 60 * 60;
const CRATES_IO_INDEX_BASE_URL: &str = "https://index.crates.io";
const CRATES_IO_MAX_NAME_LEN: usize = 64;
const CRATES_IO_MAX_INDEX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const CRATES_IO_MAX_INDEX_LINE_BYTES: usize = 1024 * 1024;
const CRATES_IO_INDEX_CACHE_SCHEMA_VERSION: u32 = 1;

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

fn osv_query_body(packages: &[Package]) -> Value {
    json!({
        "queries": packages
            .iter()
            .map(|package| json!({
                "package": {
                    "name": osv_query_name(package),
                    "ecosystem": package.ecosystem.osv_name()
                },
                "version": package.version
            }))
            .collect::<Vec<_>>()
    })
}

fn invalid_osv_batch_response(message: impl Into<String>) -> ProviderError {
    ProviderError::InvalidResponse(format!(
        "OSV querybatch response is invalid: {}",
        message.into()
    ))
}

fn valid_osv_id(id: &str) -> bool {
    let Some((database, entry)) = id.split_once('-') else {
        return false;
    };

    let valid_component =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_');

    !database.is_empty()
        && !entry.is_empty()
        && database.bytes().any(|byte| byte.is_ascii_alphanumeric())
        && entry.bytes().any(|byte| byte.is_ascii_alphanumeric())
        && database.bytes().all(valid_component)
        && entry.bytes().all(valid_component)
}

fn parse_osv_query_batch_response(
    response: &Value,
    expected_results: usize,
) -> Result<Vec<Vec<String>>, ProviderError> {
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

    results
        .iter()
        .enumerate()
        .map(|(result_index, result)| {
            let result = result.as_object().ok_or_else(|| {
                invalid_osv_batch_response(format!("result {result_index} is not an object"))
            })?;
            let Some(vulns) = result.get("vulns") else {
                // OSV's protobuf JSON encoding represents a legitimate empty result as `{}`.
                return if result.is_empty() {
                    Ok(Vec::new())
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

            vulns
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
                    Ok(id.to_owned())
                })
                .collect()
        })
        .collect()
}

fn nuget_registry_cache_key(package: &Package) -> String {
    format!("nuget:{}", package.name)
}

fn nuget_registry_url(package: &Package) -> String {
    format!(
        "https://api.nuget.org/v3-flatcontainer/{}/index.json",
        encode(&package.name)
    )
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
pub struct Cache {
    root: PathBuf,
    policy: CachePolicy,
}
impl Cache {
    pub fn new(policy: CachePolicy) -> Result<Self, ProviderError> {
        let root = std::env::var_os("DEPSCAN_CACHE_DIR")
            .map(PathBuf::from)
            .or_else(|| {
                ProjectDirs::from("dev", "depscan", "depscan").map(|d| d.cache_dir().to_path_buf())
            })
            .ok_or_else(|| {
                ProviderError::Cache("could not determine cache directory".to_owned())
            })?;
        fs::create_dir_all(&root).map_err(|e| ProviderError::Cache(e.to_string()))?;
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
        if !self.policy.read {
            return None;
        }
        let path = self.filename(namespace, key);
        let text = fs::read_to_string(path).ok()?;
        let entry: CacheEntry = serde_json::from_str(&text).ok()?;
        let limit = self
            .policy
            .max_age
            .map_or(ttl, |max| std::cmp::min(ttl, max));
        if Utc::now() - entry.stored_at > limit {
            return None;
        }
        Some((entry.value, entry.etag))
    }
    pub fn put(
        &self,
        namespace: &str,
        key: &str,
        value: &Value,
        etag: Option<String>,
    ) -> Result<(), ProviderError> {
        let path = self.filename(namespace, key);
        let parent = path.parent().expect("cache filename has parent");
        fs::create_dir_all(parent).map_err(|e| ProviderError::Cache(e.to_string()))?;
        let lock_path = parent.join(".lock");
        let lock = File::create(lock_path).map_err(|e| ProviderError::Cache(e.to_string()))?;
        lock.lock_exclusive()
            .map_err(|e| ProviderError::Cache(e.to_string()))?;
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
        fs::rename(tmp, path).map_err(|e| ProviderError::Cache(e.to_string()))?;
        let _ = fs2::FileExt::unlock(&lock);
        Ok(())
    }
    pub fn clear(&self) -> Result<(), ProviderError> {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).map_err(|e| ProviderError::Cache(e.to_string()))?;
        }
        fs::create_dir_all(&self.root).map_err(|e| ProviderError::Cache(e.to_string()))
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

#[derive(Clone)]
pub struct HttpClient {
    inner: Client,
}
impl HttpClient {
    pub fn new() -> Result<Self, ProviderError> {
        let client = Client::builder()
            .user_agent(USER_AGENT_VALUE)
            .timeout(StdDuration::from_secs(10))
            .connect_timeout(StdDuration::from_secs(10))
            .gzip(true)
            .http2_adaptive_window(true)
            .build()
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        Ok(Self { inner: client })
    }
    async fn request_json(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<Value>,
        headers: HeaderMap,
    ) -> Result<(Value, Option<String>), ProviderError> {
        let mut last_error = String::new();
        for attempt in 0..3 {
            let mut request = self
                .inner
                .request(method.clone(), url)
                .headers(headers.clone());
            if let Some(body) = &body {
                request = request.json(body);
            }
            match request.send().await {
                Ok(response) if response.status().is_success() => {
                    let etag = response
                        .headers()
                        .get(ETAG)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    let value = response
                        .json::<Value>()
                        .await
                        .map_err(|e| ProviderError::InvalidResponse(format!("{url}: {e}")))?;
                    return Ok((value, etag));
                }
                Ok(response) => {
                    let status = response.status();
                    last_error = format!("{url}: HTTP {status}");
                    if !(status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()) {
                        return Err(ProviderError::Network(last_error));
                    }
                    let retry_after = response
                        .headers()
                        .get(RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok());
                    let delay = retry_after
                        .unwrap_or_else(|| (1u64 << attempt) + rand::rng().random_range(0..=1));
                    sleep(StdDuration::from_secs(delay)).await;
                }
                Err(error) => {
                    last_error = format!("{url}: {error}");
                    if attempt < 2 {
                        let jitter = rand::rng().random_range(0..100);
                        sleep(StdDuration::from_millis((200 * (1u64 << attempt)) + jitter)).await;
                    }
                }
            }
        }
        Err(ProviderError::Network(last_error))
    }
    pub async fn get_json(
        &self,
        url: &str,
        headers: HeaderMap,
    ) -> Result<(Value, Option<String>), ProviderError> {
        self.request_json(reqwest::Method::GET, url, None, headers)
            .await
    }
    pub async fn post_json(&self, url: &str, body: Value) -> Result<Value, ProviderError> {
        self.request_json(reqwest::Method::POST, url, Some(body), HeaderMap::new())
            .await
            .map(|x| x.0)
    }
    pub async fn get_bytes(&self, url: &str) -> Result<Vec<u8>, ProviderError> {
        let response = self
            .inner
            .get(url)
            .send()
            .await
            .map_err(|e| ProviderError::Network(format!("{url}: {e}")))?
            .error_for_status()
            .map_err(|e| ProviderError::Network(format!("{url}: {e}")))?;
        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| ProviderError::Network(format!("{url}: {e}")))
    }

    async fn get_bytes_limited(
        &self,
        url: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, ProviderError> {
        let mut response = self
            .inner
            .get(url)
            .send()
            .await
            .map_err(|e| ProviderError::Network(format!("{url}: {e}")))?
            .error_for_status()
            .map_err(|e| ProviderError::Network(format!("{url}: {e}")))?;
        let content_length = response.content_length();
        if content_length.is_some_and(|length| length > max_bytes as u64) {
            return Err(ProviderError::InvalidResponse(format!(
                "{url}: response exceeds the {max_bytes}-byte limit"
            )));
        }

        let initial_capacity = content_length
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(max_bytes);
        let mut bytes = Vec::with_capacity(initial_capacity);
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| ProviderError::Network(format!("{url}: {e}")))?
        {
            let Some(new_len) = bytes.len().checked_add(chunk.len()) else {
                return Err(ProviderError::InvalidResponse(format!(
                    "{url}: response size overflowed"
                )));
            };
            if new_len > max_bytes {
                return Err(ProviderError::InvalidResponse(format!(
                    "{url}: response exceeds the {max_bytes}-byte limit"
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
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
    async fn query_batch(&self, batch: &[Package]) -> Result<Vec<Vec<String>>, ProviderError> {
        let body = osv_query_body(batch);
        let url = format!("{}/v1/querybatch", self.base_url);
        let response = self.http.post_json(&url, body).await?;
        parse_osv_query_batch_response(&response, batch.len())
    }
    async fn hydrate(&self, id: &str) -> Result<Value, ProviderError> {
        if let Some((value, _)) = self.cache.get("osv/vuln", id, Duration::hours(24 * 3650)) {
            return Ok(value);
        }
        let _permit = self
            .concurrency
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let url = format!("{}/v1/vulns/{id}", self.base_url);
        let (value, etag) = self.http.get_json(&url, HeaderMap::new()).await?;
        self.cache.put("osv/vuln", id, &value, etag)?;
        Ok(value)
    }
}
#[async_trait]
impl VulnProvider for OsvClient {
    async fn query(&self, packages: &[Package]) -> Result<VulnMap, ProviderError> {
        let mut map = VulnMap::new();
        let mut missing = Vec::new();
        for package in packages
            .iter()
            .filter(|p| p.enrichable && !p.resolved_from_range)
        {
            let query_cache_key = osv_query_cache_key(package);
            if let Some((cached, _)) = self.cache.get(
                "osv/query",
                &query_cache_key,
                Duration::seconds(OSV_QUERY_TTL_SECS),
            ) {
                let ids: Vec<String> = cached
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                map.insert(
                    package.key(),
                    ids.into_iter()
                        .map(|id| Vulnerability {
                            id,
                            aliases: vec![],
                            summary: String::new(),
                            severity: None,
                            cvss_score: None,
                            fixed_in: vec![],
                            references: vec![],
                            withdrawn: false,
                        })
                        .collect(),
                );
            } else {
                missing.push(package.clone());
            }
        }
        for chunk in missing.chunks(1000) {
            let lists = self.query_batch(chunk).await?;
            for (package, ids) in chunk.iter().cloned().zip(lists) {
                self.cache.put(
                    "osv/query",
                    &osv_query_cache_key(&package),
                    &json!(ids),
                    None,
                )?;
                map.insert(
                    package.key(),
                    ids.into_iter()
                        .map(|id| Vulnerability {
                            id,
                            aliases: vec![],
                            summary: String::new(),
                            severity: None,
                            cvss_score: None,
                            fixed_in: vec![],
                            references: vec![],
                            withdrawn: false,
                        })
                        .collect(),
                );
            }
        }
        let ids: BTreeSet<String> = map.values().flatten().map(|v| v.id.clone()).collect();
        let hydrated = stream::iter(ids.into_iter().map(|id| {
            let client = self.clone();
            async move {
                let doc = client.hydrate(&id).await?;
                Ok::<_, ProviderError>((id, doc))
            }
        }))
        .buffer_unordered(16)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<HashMap<_, _>, _>>()?;
        for (key, vulns) in &mut map {
            let package = packages.iter().find(|p| p.key() == *key).ok_or_else(|| {
                ProviderError::InvalidResponse(format!(
                    "OSV query result has no source package for key {key:?}"
                ))
            })?;
            let mut evaluated = Vec::with_capacity(vulns.len());
            for vuln in std::mem::take(vulns) {
                let doc = hydrated.get(&vuln.id).ok_or_else(|| {
                    ProviderError::InvalidResponse(format!(
                        "OSV advisory {} was not hydrated",
                        vuln.id
                    ))
                })?;
                if let Some(vulnerability) = vulnerability_from_osv(doc, Some(package))? {
                    evaluated.push(vulnerability);
                }
            }
            *vulns = evaluated;
        }
        Ok(map)
    }
}

fn vulnerability_from_osv(
    doc: &Value,
    package: Option<&Package>,
) -> Result<Option<Vulnerability>, ProviderError> {
    let score = osv_cvss_score(doc, package);
    let evaluation = package
        .map(|package| {
            evaluate_osv_affected(
                package,
                doc.get("affected")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            )
            .map_err(|error| {
                ProviderError::InvalidResponse(format!(
                    "OSV advisory {} cannot be evaluated for {} {}: {error}",
                    doc.get("id").and_then(Value::as_str).unwrap_or("UNKNOWN"),
                    package.display_name,
                    package.version
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
        id: doc
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN")
            .to_owned(),
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
        withdrawn: doc.get("withdrawn").is_some(),
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

#[derive(Clone)]
pub struct OsvOffline {
    cache: Cache,
}
impl OsvOffline {
    pub fn new(cache: Cache) -> Self {
        Self { cache }
    }
    fn archive_path(&self, ecosystem: Ecosystem) -> PathBuf {
        self.cache
            .root()
            .join("offline")
            .join(format!("{}.zip", ecosystem.osv_name().replace('.', "_")))
    }
    fn query_blocking(&self, packages: &[Package]) -> Result<VulnMap, ProviderError> {
        let mut output = VulnMap::new();
        for package in packages {
            output.entry(package.key()).or_default();
        }
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
            let archive_path = self.archive_path(ecosystem);
            let file = File::open(&archive_path).map_err(|_| {
                ProviderError::Offline(format!(
                    "missing OSV dump {}; run `depscan sync --ecosystem {}`",
                    archive_path.display(),
                    ecosystem.display_name()
                ))
            })?;
            let mut archive =
                ZipArchive::new(file).map_err(|e| ProviderError::Offline(e.to_string()))?;
            for index in 0..archive.len() {
                let mut entry = archive
                    .by_index(index)
                    .map_err(|e| ProviderError::Offline(e.to_string()))?;
                if !entry.name().ends_with(".json") {
                    continue;
                }
                let mut text = String::new();
                entry
                    .read_to_string(&mut text)
                    .map_err(|e| ProviderError::Offline(e.to_string()))?;
                let Ok(document) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                for package in &scoped {
                    if let Some(vulnerability) = vulnerability_from_osv(&document, Some(package))? {
                        output.entry(package.key()).or_default().push(vulnerability);
                    }
                }
            }
        }
        Ok(output)
    }
}
#[async_trait]
impl VulnProvider for OsvOffline {
    async fn query(&self, packages: &[Package]) -> Result<VulnMap, ProviderError> {
        let this = self.clone();
        let owned = packages.to_vec();
        tokio::task::spawn_blocking(move || this.query_blocking(&owned))
            .await
            .map_err(|e| ProviderError::Offline(e.to_string()))?
    }
}

pub async fn sync_osv_dumps(
    http: &HttpClient,
    cache: &Cache,
    ecosystems: &[Ecosystem],
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
    let dir = cache.root().join("offline");
    fs::create_dir_all(&dir).map_err(|e| ProviderError::Cache(e.to_string()))?;
    let mut written = Vec::new();
    for eco in list {
        let url = format!(
            "https://storage.googleapis.com/osv-vulnerabilities/{}/all.zip",
            eco.osv_name()
        );
        debug!(%url, "downloading OSV dump");
        let bytes = http.get_bytes(&url).await?;
        let path = dir.join(format!("{}.zip", eco.osv_name().replace('.', "_")));
        let tmp = path.with_extension("zip.tmp");
        fs::write(&tmp, bytes).map_err(|e| ProviderError::Cache(e.to_string()))?;
        fs::rename(tmp, &path).map_err(|e| ProviderError::Cache(e.to_string()))?;
        fs::write(path.with_extension("synced-at"), Utc::now().to_rfc3339())
            .map_err(|e| ProviderError::Cache(e.to_string()))?;
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
    crates_index_base_url: String,
}
impl RegistryClient {
    pub fn new(http: HttpClient, cache: Cache) -> Self {
        Self::with_crates_index_base_url(http, cache, CRATES_IO_INDEX_BASE_URL)
    }

    fn with_crates_index_base_url(
        http: HttpClient,
        cache: Cache,
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
        if let Some((value, _)) =
            self.cache
                .get("registry", namespace, Duration::seconds(REGISTRY_TTL_SECS))
        {
            return Ok(value);
        }
        let (value, etag) = self.http.get_json(url, headers).await?;
        self.cache.put("registry", namespace, &value, etag)?;
        Ok(value)
    }
    async fn npm(&self, p: &Package) -> Result<LatestVersions, ProviderError> {
        let _permit = self.limits[&Ecosystem::Npm]
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let url = format!("https://registry.npmjs.org/{}", encode(&p.name));
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.npm.install-v1+json"),
        );
        let data = self
            .metadata(&format!("npm:{}", p.name), &url, headers)
            .await?;
        let latest = data
            .get("dist-tags")
            .and_then(|x| x.get("latest"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProviderError::InvalidResponse(format!("npm response lacked latest for {}", p.name))
            })?
            .to_owned();
        Ok(version_result(p, latest, false))
    }
    async fn pypi(&self, p: &Package) -> Result<LatestVersions, ProviderError> {
        let _permit = self.limits[&Ecosystem::PyPI]
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let url = format!("https://pypi.org/pypi/{}/json", encode(&p.name));
        let data = self
            .metadata(&format!("pypi:{}", p.name), &url, HeaderMap::new())
            .await?;
        let releases = data
            .get("releases")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ProviderError::InvalidResponse("PyPI response lacked releases".to_owned())
            })?;
        let latest = select_pypi_release(releases, &p.version).ok_or_else(|| {
            ProviderError::InvalidResponse(format!("PyPI has no suitable release for {}", p.name))
        })?;
        let yanked = releases.get(&p.version).is_some_and(pypi_release_is_yanked);
        Ok(version_result(p, latest, yanked))
    }
    async fn nuget(&self, p: &Package) -> Result<LatestVersions, ProviderError> {
        let _permit = self.limits[&Ecosystem::NuGet]
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let url = nuget_registry_url(p);
        let cache_key = nuget_registry_cache_key(p);
        let data = self.metadata(&cache_key, &url, HeaderMap::new()).await?;
        let latest = select_nuget_release(
            data.get("versions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str),
        )
        .ok_or_else(|| {
            ProviderError::InvalidResponse(format!("NuGet has no stable version for {}", p.name))
        })?;
        Ok(version_result(p, latest, false))
    }
    async fn crates(&self, p: &Package) -> Result<LatestVersions, ProviderError> {
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
        let mut all: Vec<String> = Vec::new();
        let mut yanked = false;
        for entry in entries {
            if entry.vers == p.version {
                yanked = entry.yanked;
            }
            if !entry.yanked && !is_prerelease(Ecosystem::CratesIo, &entry.vers) {
                all.push(entry.vers);
            }
        }
        let latest = maximum_version(Ecosystem::CratesIo, all.iter().map(String::as_str))
            .ok_or_else(|| {
                ProviderError::InvalidResponse(format!(
                    "crates.io has no stable version for {}",
                    p.name
                ))
            })?;
        Ok(version_result(p, latest, yanked))
    }
}
#[async_trait]
impl VersionProvider for RegistryClient {
    async fn latest(&self, package: &Package) -> Result<LatestVersions, ProviderError> {
        match package.ecosystem {
            Ecosystem::Npm => self.npm(package).await,
            Ecosystem::PyPI => self.pypi(package).await,
            Ecosystem::NuGet => self.nuget(package).await,
            Ecosystem::CratesIo => self.crates(package).await,
        }
    }
}

fn version_result(package: &Package, latest: String, yanked: bool) -> LatestVersions {
    let staleness = if package.resolved_from_range {
        depscan_core::Staleness::Unknown
    } else {
        classify_staleness(package.ecosystem, &package.version, &latest)
    };
    LatestVersions {
        latest_stable: latest.clone(),
        latest_matching: package.resolved_from_range.then_some(latest),
        staleness,
        yanked,
    }
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

#[derive(Debug, Serialize, Deserialize)]
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

// crates.io sparse-index entries are newline-delimited JSON. Decode and validate the entire
// response before writing the versioned cache envelope, so a truncated response cannot be reused.
impl RegistryClient {
    async fn crates_metadata_for_index(
        &self,
        key: &str,
        expected_name: &str,
        url: &str,
    ) -> Result<Vec<CratesIndexEntry>, ProviderError> {
        if let Some((value, _)) =
            self.cache
                .get("registry", key, Duration::seconds(REGISTRY_TTL_SECS))
        {
            if let Ok(cached) = serde_json::from_value::<CratesIndexCache>(value)
                && cached.schema_version == CRATES_IO_INDEX_CACHE_SCHEMA_VERSION
                && validate_crates_index_entries(
                    cached
                        .entries
                        .iter()
                        .enumerate()
                        .map(|(index, entry)| (index + 1, entry)),
                    expected_name,
                    "cached crates.io sparse index",
                )
                .is_ok()
            {
                return Ok(cached.entries);
            }
            debug!(%key, "ignoring legacy or invalid crates.io sparse-index cache entry");
        }
        let bytes = self
            .http
            .get_bytes_limited(url, CRATES_IO_MAX_INDEX_RESPONSE_BYTES)
            .await?;
        let entries = decode_crates_index(&bytes, expected_name, url)?;
        let value = serde_json::to_value(CratesIndexCache {
            schema_version: CRATES_IO_INDEX_CACHE_SCHEMA_VERSION,
            entries: entries.clone(),
        })
        .map_err(|error| ProviderError::Cache(error.to_string()))?;
        self.cache.put("registry", key, &value, None)?;
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, method, path},
    };
    use zip::write::SimpleFileOptions;

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
                archive
                    .start_file(format!("{id}.json"), SimpleFileOptions::default())
                    .unwrap();
                archive
                    .write_all(serde_json::to_string(&fixture.document).unwrap().as_bytes())
                    .unwrap();
            }
            archive.finish().unwrap();
        }
    }

    fn nuget_package(name: &str) -> Package {
        Package::new(
            Ecosystem::NuGet,
            name,
            "12.0.1",
            PathBuf::from("packages.lock.json"),
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

    fn crates_package(name: &str) -> Package {
        Package::new(
            Ecosystem::CratesIo,
            name,
            "1.0.0",
            PathBuf::from("Cargo.lock"),
        )
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
            assert_eq!(latest.latest_stable, "1.0.0");
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
            assert_eq!(latest.latest_stable, "2.0.0");
            assert!(latest.yanked);
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
                    "vulns": [{"id": "GHSA-5crp-9r3c-p9vr"}]
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

        assert_eq!(results, vec![vec!["GHSA-5crp-9r3c-p9vr".to_owned()]]);
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
                "malformed later result",
                json!({"results": [
                    {"vulns": []},
                    {"vulns": [{"id": null}]}
                ]}),
                2,
                "result 1 vulnerability 0 has no string id",
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

        assert_eq!(results.len(), packages.len());
        for package in &packages {
            assert!(results[&package.key()].is_empty());
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
        let offline_dir = dir.path().join("offline");
        fs::create_dir_all(&offline_dir).unwrap();
        let archive_path = offline_dir.join("NuGet.zip");
        let file = File::create(archive_path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        archive
            .start_file("GHSA-5crp-9r3c-p9vr.json", SimpleFileOptions::default())
            .unwrap();
        archive
            .write_all(
                serde_json::to_string(&json!({
                    "id": "GHSA-5crp-9r3c-p9vr",
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

        let cache = Cache {
            root: dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
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
            Mock::given(method("POST"))
                .and(path("/v1/querybatch"))
                .and(body_json(osv_query_body(std::slice::from_ref(package))))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "results": [{"vulns": [{"id": id}]}]
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(&fixture.document))
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
            let hydrated_results = online.query(std::slice::from_ref(package)).await.unwrap();
            let hydrated = hydrated_results[&package.key()]
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

            let dir = tempfile::tempdir().unwrap();
            write_fixture_archives(dir.path(), std::slice::from_ref(fixture));
            let offline_provider = OsvOffline::new(Cache {
                root: dir.path().to_path_buf(),
                policy: CachePolicy::default(),
            });
            let offline_results = offline_provider
                .query_blocking(std::slice::from_ref(package))
                .unwrap();
            let offline = offline_results[&package.key()]
                .iter()
                .map(|vulnerability| (vulnerability.id.clone(), vulnerability.fixed_in.clone()))
                .collect::<Vec<_>>();
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
        write_fixture_archives(dir.path(), std::slice::from_ref(&fixture));
        let offline = OsvOffline::new(Cache {
            root: dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        });
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
