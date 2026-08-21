use super::*;

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
pub(crate) struct CacheEntry {
    pub(crate) stored_at: DateTime<Utc>,
    pub(crate) etag: Option<String>,
    pub(crate) value: Value,
}

#[derive(Debug, Clone)]
pub(crate) struct CacheLookup {
    pub(crate) etag: Option<String>,
    pub(crate) value: Value,
    pub(crate) fresh: bool,
}

pub(crate) enum CacheCommit {
    Written,
    Conflict(Option<CacheLookup>),
}

pub(crate) fn add_if_none_match(headers: &mut HeaderMap, cached: Option<&CacheLookup>) -> bool {
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
    pub(crate) root: PathBuf,
    pub(crate) policy: CachePolicy,
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
    pub(crate) fn from_root(
        requested: PathBuf,
        policy: CachePolicy,
    ) -> Result<Self, ProviderError> {
        let root = initialize_cache_root(&requested, false)?;
        Ok(Self { root, policy })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub(crate) fn filename(&self, namespace: &str, key: &str) -> PathBuf {
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
    pub(crate) fn lookup(&self, namespace: &str, key: &str, ttl: Duration) -> Option<CacheLookup> {
        if !self.policy.read {
            return None;
        }
        self.snapshot_blocking(namespace, key, ttl)
    }
    pub(crate) fn snapshot_blocking(
        &self,
        namespace: &str,
        key: &str,
        ttl: Duration,
    ) -> Option<CacheLookup> {
        let path = self.filename(namespace, key);
        let entry = Self::read_entry(&path)?;
        Some(self.lookup_from_entry(entry, ttl))
    }
    pub(crate) async fn snapshot(
        &self,
        namespace: &str,
        key: &str,
        ttl: Duration,
    ) -> Option<CacheLookup> {
        let cache = self.clone();
        let namespace = namespace.to_owned();
        let key = key.to_owned();
        match tokio::task::spawn_blocking(move || cache.snapshot_blocking(&namespace, &key, ttl))
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                debug!(%error, "cache snapshot task failed");
                None
            }
        }
    }
    pub(crate) async fn get_if_fresh(
        &self,
        namespace: &str,
        key: &str,
        ttl: Duration,
    ) -> Option<(Value, Option<String>)> {
        let cache = self.clone();
        let namespace = namespace.to_owned();
        let key = key.to_owned();
        match tokio::task::spawn_blocking(move || cache.get(&namespace, &key, ttl)).await {
            Ok(cached) => cached,
            Err(error) => {
                debug!(%error, "cache read task failed");
                None
            }
        }
    }
    pub(crate) fn read_entry(path: &Path) -> Option<CacheEntry> {
        let text = fs::read_to_string(path).ok()?;
        serde_json::from_str(&text).ok()
    }
    pub(crate) fn lookup_from_entry(&self, entry: CacheEntry, ttl: Duration) -> CacheLookup {
        self.lookup_from_entry_at(entry, ttl, Utc::now())
    }
    pub(crate) fn lookup_from_entry_at(
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
    pub(crate) fn lock_for(&self, path: &Path) -> Result<File, ProviderError> {
        let parent = path.parent().expect("cache filename has parent");
        fs::create_dir_all(parent).map_err(|e| ProviderError::Cache(e.to_string()))?;
        let lock =
            File::create(parent.join(".lock")).map_err(|e| ProviderError::Cache(e.to_string()))?;
        lock.lock_exclusive()
            .map_err(|e| ProviderError::Cache(e.to_string()))?;
        Ok(lock)
    }
    pub(crate) fn write_entry(
        path: &Path,
        value: &Value,
        etag: Option<String>,
    ) -> Result<(), ProviderError> {
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
    pub(crate) async fn put_if_unchanged(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<CacheLookup>,
        value: &Value,
        etag: Option<String>,
        ttl: Duration,
    ) -> Result<CacheCommit, ProviderError> {
        let cache = self.clone();
        let namespace = namespace.to_owned();
        let key = key.to_owned();
        let value = value.clone();
        tokio::task::spawn_blocking(move || {
            cache.put_if_unchanged_blocking(&namespace, &key, expected.as_ref(), &value, etag, ttl)
        })
        .await
        .map_err(|error| ProviderError::Cache(error.to_string()))?
    }
    pub(crate) fn put_if_unchanged_blocking(
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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CacheStats {
    pub files: u64,
    pub bytes: u64,
}

#[derive(Debug)]
pub(crate) enum Revalidated<T> {
    Modified { value: T, etag: Option<String> },
    NotModified { etag: Option<String> },
}

pub(crate) struct PublishedHydration {
    pub(crate) value: Value,
    pub(crate) reusable: bool,
}

pub(crate) struct HydratedDocument {
    pub(crate) value: Value,
    pub(crate) cache_warning: Option<ProviderError>,
}
