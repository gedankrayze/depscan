use super::*;

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
        let mut hydrated_document = fixture.document.clone();
        hydrated_document
            .as_object_mut()
            .unwrap()
            .insert("modified".to_owned(), json!(TEST_OSV_MODIFIED));
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(std::slice::from_ref(package))))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [osv_query_vulnerability(id)]}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(hydrated_document))
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
        let hydrated_result = online.query(std::slice::from_ref(package)).await;
        let hydrated = if fixture.name == "wrong package identity" {
            let error = hydrated_result.unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("no matching evaluable affected entry"),
                "unexpected wrong-identity query error: {error}"
            );
            Vec::new()
        } else {
            let hydrated_results = hydrated_result.unwrap();
            let hydrated = hydrated_results.vulnerabilities[&package.key()]
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
            hydrated
        };

        let dir = tempfile::tempdir().unwrap();
        let cache = Cache::from_root(dir.path().join("cache"), CachePolicy::default()).unwrap();
        write_fixture_archives(cache.root(), std::slice::from_ref(fixture));
        let offline_provider = OsvOffline::new(cache);
        let offline_results = offline_provider
            .query_blocking(std::slice::from_ref(package))
            .unwrap();
        let offline = offline_results[&package.key()]
            .iter()
            .map(|vulnerability| (vulnerability.id.clone(), vulnerability.fixed_in.clone()))
            .collect::<Vec<_>>();
        if fixture.name == "wrong package identity" {
            assert!(offline.is_empty());
            continue;
        }
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
        "modified": TEST_OSV_MODIFIED,
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
    let cache = Cache::from_root(dir.path().join("cache"), CachePolicy::default()).unwrap();
    write_fixture_archives(cache.root(), std::slice::from_ref(&fixture));
    let offline = OsvOffline::new(cache);
    let offline_error = offline
        .query_blocking(std::slice::from_ref(&package))
        .unwrap_err();
    assert!(
        offline_error
            .to_string()
            .contains("unsupported OSV range type")
    );
}
