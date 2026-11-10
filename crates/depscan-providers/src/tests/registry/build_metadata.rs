use super::*;

#[test]
fn semver_build_metadata_hyphens_do_not_mark_stable_releases_as_prerelease() {
    for ecosystem in [Ecosystem::CratesIo, Ecosystem::Npm] {
        for version in [
            "1.0.4+wasi-0.2.12",
            "2.0.1+wasi-0.2.12",
            "1.0.0+build-feature.sha",
            "1.0.0",
        ] {
            assert!(
                !is_prerelease(ecosystem, version),
                "{ecosystem:?}: {version}"
            );
        }
        for version in [
            "1.0.4-rc.1+wasi-0.2.12",
            "3.0.0-alpha.2+build-sha",
            "2.0.0-beta",
        ] {
            assert!(
                is_prerelease(ecosystem, version),
                "{ecosystem:?}: {version}"
            );
        }
    }
}

#[test]
fn crate_candidates_keep_stable_build_metadata_and_exclude_yanked_and_prereleases() {
    let entries: Vec<CratesIndexEntry> = serde_json::from_value(json!([
        {"name": "wasip2", "vers": "1.0.4+wasi-0.2.12", "yanked": false},
        {"name": "wasip2", "vers": "2.0.1+wasi-0.2.12", "yanked": false},
        {"name": "wasip2", "vers": "3.0.0-rc.1+wasi-0.2.12", "yanked": false},
        {"name": "wasip2", "vers": "4.0.0+wasi-0.2.12", "yanked": true}
    ]))
    .unwrap();
    let mut package = crates_package("wasip2");
    package.version = "1.0.4+wasi-0.2.12".to_owned();

    let result = crates_version_result(&package, &entries).unwrap();

    assert_eq!(result.latest_stable, "2.0.1+wasi-0.2.12");
    assert_eq!(result.staleness, depscan_core::Staleness::Major);
    assert!(!result.yanked);
}

#[tokio::test]
async fn sparse_registry_selects_stable_wasip2_versions_through_the_http_path() {
    let server = MockServer::start().await;
    let body = concat!(
        "{\"name\":\"wasip2\",\"vers\":\"1.0.4+wasi-0.2.12\",\"yanked\":false}\n",
        "{\"name\":\"wasip2\",\"vers\":\"2.0.1+wasi-0.2.12\",\"yanked\":false}\n",
        "{\"name\":\"wasip2\",\"vers\":\"3.0.0-rc.1+wasi-0.2.12\",\"yanked\":false}\n",
    );
    Mock::given(method("GET"))
        .and(path("/wa/si/wasip2"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/plain"))
        .expect(1)
        .mount(&server)
        .await;
    let directory = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: directory.path().to_owned(),
        policy: CachePolicy::default(),
    };
    let client =
        RegistryClient::with_crates_index_base_url(HttpClient::new().unwrap(), cache, server.uri());
    let mut package = crates_package("wasip2");
    package.version = "1.0.4+wasi-0.2.12".to_owned();

    let result = client.latest(&package).await.unwrap();

    assert_eq!(result.latest.latest_stable, "2.0.1+wasi-0.2.12");
    assert_eq!(result.latest.staleness, depscan_core::Staleness::Major);
    server.verify().await;
}
