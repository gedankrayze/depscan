//! Network providers, disk cache, and OSV offline-dump support.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use cvss::Cvss;
use depscan_core::{
    classify_staleness, compare_versions, normalize_name, osv_fixed_versions, osv_range_matches,
    Ecosystem, LatestVersions, Package, ProviderError, Severity, VersionProvider, VulnMap,
    VulnProvider, Vulnerability,
};
use directories::ProjectDirs;
use fs2::FileExt;
use futures::{stream, StreamExt};
use rand::Rng;
use reqwest::{
    header::{HeaderMap, HeaderValue, ACCEPT, ETAG, RETRY_AFTER},
    Client, StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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

fn package_name_matches(package: &Package, candidate: &str) -> bool {
    normalize_name(package.ecosystem, candidate) == package.name
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
        self.root.join(namespace).join(format!("{:x}.json", digest))
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
                        .unwrap_or_else(|| (1u64 << attempt) + rand::thread_rng().gen_range(0..=1));
                    sleep(StdDuration::from_secs(delay)).await;
                }
                Err(error) => {
                    last_error = format!("{url}: {error}");
                    if attempt < 2 {
                        let jitter = rand::thread_rng().gen_range(0..100);
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
        Ok(response
            .get("results")
            .and_then(Value::as_array)
            .map(|results| {
                results
                    .iter()
                    .map(|r| {
                        r.get("vulns")
                            .and_then(Value::as_array)
                            .map(|v| {
                                v.iter()
                                    .filter_map(|item| {
                                        item.get("id").and_then(Value::as_str).map(str::to_owned)
                                    })
                                    .collect()
                            })
                            .unwrap_or_default()
                    })
                    .collect()
            })
            .unwrap_or_default())
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
            let package = packages.iter().find(|p| p.key() == *key);
            for vuln in vulns {
                if let Some(doc) = hydrated.get(&vuln.id) {
                    *vuln = vulnerability_from_osv(doc, package);
                }
            }
        }
        Ok(map)
    }
}

fn vulnerability_from_osv(doc: &Value, package: Option<&Package>) -> Vulnerability {
    let score = osv_cvss_score(doc, package);
    let fixed_in = package
        .map(|p| {
            osv_fixed_versions(
                p.ecosystem,
                &p.version,
                doc.get("affected")
                    .and_then(Value::as_array)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            )
        })
        .unwrap_or_default();
    Vulnerability {
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
    }
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
        && normalize_name(package.ecosystem, name) == package.name
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
                let affected = document
                    .get("affected")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for package in &scoped {
                    let matches = affected.iter().any(|item| {
                        let identity_matches = item
                            .get("package")
                            .and_then(|x| x.get("name"))
                            .and_then(Value::as_str)
                            .is_some_and(|name| package_name_matches(package, name))
                            && item
                                .get("package")
                                .and_then(|x| x.get("ecosystem"))
                                .and_then(Value::as_str)
                                == Some(package.ecosystem.osv_name());
                        let range_matches = item
                            .get("ranges")
                            .and_then(Value::as_array)
                            .is_some_and(|ranges| {
                                ranges.iter().any(|range| {
                                    range.get("events").and_then(Value::as_array).is_some_and(
                                        |events| {
                                            osv_range_matches(
                                                package.ecosystem,
                                                &package.version,
                                                events,
                                            )
                                        },
                                    )
                                })
                            });
                        identity_matches && range_matches
                    });
                    if matches {
                        output
                            .entry(package.key())
                            .or_default()
                            .push(vulnerability_from_osv(&document, Some(package)));
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

#[derive(Clone)]
pub struct RegistryClient {
    http: HttpClient,
    cache: Cache,
    limits: Arc<HashMap<Ecosystem, Arc<Semaphore>>>,
}
impl RegistryClient {
    pub fn new(http: HttpClient, cache: Cache) -> Self {
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
        let installed_prerelease = is_prerelease(Ecosystem::PyPI, &p.version);
        let mut candidates: Vec<String> = releases
            .iter()
            .filter(|(version, files)| {
                let prerelease_allowed =
                    installed_prerelease || !is_prerelease(Ecosystem::PyPI, version);
                let all_yanked = files.as_array().is_some_and(|files| {
                    !files.is_empty()
                        && files.iter().all(|file| {
                            file.get("yanked").and_then(Value::as_bool).unwrap_or(false)
                        })
                });
                prerelease_allowed && !all_yanked
            })
            .map(|(version, _)| version.to_owned())
            .collect();
        candidates.sort_by(|a, b| compare_versions(Ecosystem::PyPI, a, b));
        let latest = candidates.pop().ok_or_else(|| {
            ProviderError::InvalidResponse(format!("PyPI has no suitable release for {}", p.name))
        })?;
        let yanked = releases
            .get(&p.version)
            .and_then(Value::as_array)
            .is_some_and(|files| {
                !files.is_empty()
                    && files
                        .iter()
                        .all(|file| file.get("yanked").and_then(Value::as_bool).unwrap_or(false))
            });
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
        let latest = maximum_version(
            Ecosystem::NuGet,
            data.get("versions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter(|v| !is_prerelease(Ecosystem::NuGet, v)),
        )
        .ok_or_else(|| {
            ProviderError::InvalidResponse(format!("NuGet has no stable version for {}", p.name))
        })?;
        Ok(version_result(p, latest, false))
    }
    async fn crates(&self, p: &Package) -> Result<LatestVersions, ProviderError> {
        let _permit = self.limits[&Ecosystem::CratesIo]
            .acquire()
            .await
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        let name = &p.name;
        let path = match name.len() {
            1 => format!("1/{name}"),
            2 => format!("2/{name}"),
            3 => format!("3/{}/{name}", &name[0..1]),
            _ => format!("{}/{}/{}", &name[0..2], &name[2..4], name),
        };
        let url = format!("https://index.crates.io/{path}");
        let data = self
            .crates_metadata_for_index(&format!("crates:{}", name), &url)
            .await?;
        let lines = data
            .get("lines")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut all: Vec<String> = Vec::new();
        let mut yanked = false;
        for line in lines {
            if let Some(version) = line.get("vers").and_then(Value::as_str) {
                if version == p.version {
                    yanked = line.get("yanked").and_then(Value::as_bool).unwrap_or(false);
                }
                if !line.get("yanked").and_then(Value::as_bool).unwrap_or(false)
                    && !is_prerelease(Ecosystem::CratesIo, version)
                {
                    all.push(version.to_owned());
                }
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
fn is_prerelease(eco: Ecosystem, version: &str) -> bool {
    match eco {
        Ecosystem::Npm | Ecosystem::CratesIo | Ecosystem::NuGet => version.contains('-'),
        Ecosystem::PyPI => {
            let lower = version.to_ascii_lowercase();
            lower.contains("a")
                || lower.contains("b")
                || lower.contains("rc")
                || lower.contains("dev")
        }
    }
}

// crates.io sparse-index entries are newline-delimited JSON. Convert the raw bytes into a JSON
// envelope before cache storage so the generic cache can retain it without a special format.
impl RegistryClient {
    async fn crates_metadata_for_index(
        &self,
        key: &str,
        url: &str,
    ) -> Result<Value, ProviderError> {
        if let Some((value, _)) =
            self.cache
                .get("registry", key, Duration::seconds(REGISTRY_TTL_SECS))
        {
            return Ok(value);
        }
        let bytes = self.http.get_bytes(url).await?;
        let lines: Vec<Value> = String::from_utf8_lossy(&bytes)
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        let value = json!({"lines": lines});
        self.cache.put("registry", key, &value, None)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use wiremock::{
        matchers::{body_json, method, path},
        Mock, MockServer, ResponseTemplate,
    };
    use zip::write::SimpleFileOptions;

    fn nuget_package(name: &str) -> Package {
        Package::new(
            Ecosystem::NuGet,
            name,
            "12.0.1",
            PathBuf::from("packages.lock.json"),
        )
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
            let vulnerability = vulnerability_from_osv(&document, None);

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

        let vulnerability = vulnerability_from_osv(&document, Some(&package));
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
            let vulnerability = vulnerability_from_osv(&document, None);
            assert_eq!(vulnerability.cvss_score, None);
            assert_eq!(vulnerability.severity, None);
        }
    }

    #[test]
    fn builds_sparse_paths() {
        let path = match "serde".len() {
            1 => "1/serde".to_owned(),
            2 => "2/serde".to_owned(),
            3 => "3/s/serde".to_owned(),
            _ => format!("{}/{}/{}", &"serde"[0..2], &"serde"[2..4], "serde"),
        };
        assert_eq!(path, "se/rd/serde");
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
}
