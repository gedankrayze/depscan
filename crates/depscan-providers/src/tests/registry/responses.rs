use super::*;

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
        let ecosystem = fixture_ecosystem(&fixture.ecosystem);
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
