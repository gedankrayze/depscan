use super::*;

pub(crate) const TEST_OSV_MODIFIED: &str = "2026-08-19T00:00:00Z";

pub(crate) fn osv_query_vulnerability_at(id: &str, modified: &str) -> Value {
    json!({"id": id, "modified": modified})
}

pub(crate) fn osv_query_vulnerability(id: &str) -> Value {
    osv_query_vulnerability_at(id, TEST_OSV_MODIFIED)
}

pub(crate) fn read_cache_entry(cache: &Cache, namespace: &str, key: &str) -> CacheEntry {
    serde_json::from_str(
        &fs::read_to_string(cache.filename(namespace, key)).expect("read cache entry"),
    )
    .expect("decode cache entry")
}

pub(crate) fn write_cache_entry(cache: &Cache, namespace: &str, key: &str, entry: &CacheEntry) {
    let path = cache.filename(namespace, key);
    fs::create_dir_all(path.parent().unwrap()).expect("create cache namespace");
    fs::write(path, serde_json::to_vec(entry).unwrap()).expect("write cache entry");
}

pub(crate) fn age_cache_entry(cache: &Cache, namespace: &str, key: &str, age: Duration) {
    let mut entry = read_cache_entry(cache, namespace, key);
    entry.stored_at = Utc::now() - age;
    write_cache_entry(cache, namespace, key, &entry);
}

pub(crate) fn set_cache_entry_timestamp(
    cache: &Cache,
    namespace: &str,
    key: &str,
    stored_at: DateTime<Utc>,
) {
    let mut entry = read_cache_entry(cache, namespace, key);
    entry.stored_at = stored_at;
    write_cache_entry(cache, namespace, key, &entry);
}

pub(crate) fn test_timestamp(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}
