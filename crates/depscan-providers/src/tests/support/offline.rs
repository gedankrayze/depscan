use super::*;

pub(crate) fn valid_offline_document(id: &str, details: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "id": id,
        "modified": TEST_OSV_MODIFIED,
        "details": details,
        "affected": []
    }))
    .unwrap()
}

pub(crate) fn valid_osv_document_value(id: &str, package: &Package) -> Value {
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

pub(crate) fn scan_offline_archive(
    archive_bytes: &[u8],
    limits: OsvDumpLimits,
) -> Result<VulnMap, ProviderError> {
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache::from_root(directory.path().join("cache"), CachePolicy::default()).unwrap();
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
