use super::*;

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
