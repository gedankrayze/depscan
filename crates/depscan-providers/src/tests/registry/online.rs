use super::*;

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
