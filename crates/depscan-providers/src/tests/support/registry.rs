use super::*;

pub(crate) fn nuget_package(name: &str) -> Package {
    Package::new(
        Ecosystem::NuGet,
        name,
        "12.0.1",
        PathBuf::from("packages.lock.json"),
    )
}

pub(crate) fn nuget_registration_index(id: &str, versions: &[&str]) -> Value {
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

pub(crate) fn nuget_registry_client(server: &MockServer, cache: Cache) -> RegistryClient {
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

pub(crate) fn npm_package(name: &str) -> Package {
    Package::new(
        Ecosystem::Npm,
        name,
        "1.0.0",
        PathBuf::from("package-lock.json"),
    )
}

pub(crate) fn pypi_package(name: &str) -> Package {
    Package::new(Ecosystem::PyPI, name, "1.0.0", PathBuf::from("uv.lock"))
}

pub(crate) fn cache_osv_document(cache: &Cache, package: &Package, id: &str) {
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

pub(crate) fn crates_package(name: &str) -> Package {
    Package::new(
        Ecosystem::CratesIo,
        name,
        "1.0.0",
        PathBuf::from("Cargo.lock"),
    )
}

#[derive(Debug, Deserialize)]
pub(crate) struct RegistryRangeFixture {
    pub(crate) ecosystem: String,
    pub(crate) package: String,
    pub(crate) constraint: String,
    pub(crate) cache_key: String,
    pub(crate) registry: Value,
    pub(crate) latest_stable: String,
    pub(crate) latest_matching: String,
}

pub(crate) fn registry_range_fixtures() -> Vec<RegistryRangeFixture> {
    serde_json::from_str(include_str!("../../../tests/fixtures/registry-ranges.json")).unwrap()
}

pub(crate) fn assert_invalid_crates_name(name: &str) {
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

pub(crate) async fn assert_invalid_sparse_response(body: Vec<u8>, expected_fragments: &[&str]) {
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
    let client =
        RegistryClient::with_crates_index_base_url(HttpClient::new().unwrap(), cache, server.uri());

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
