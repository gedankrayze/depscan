use super::*;

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

#[test]
fn validates_osv_database_scoped_ids() {
    for id in [
        "OSV-2020-111",
        "GHSA-vp9c-fpxx-744v",
        "DEBIAN-CVE-2000-0001",
        "x_CUSTOM-0001",
    ] {
        assert!(valid_osv_id(id), "expected {id:?} to be valid");
    }
    for id in [
        "",
        "unscoped",
        "-missing-db",
        "GHSA-",
        "GHSA---",
        "GHSA-not valid",
    ] {
        assert!(!valid_osv_id(id), "expected {id:?} to be invalid");
    }
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
                "vulns": [osv_query_vulnerability("GHSA-5crp-9r3c-p9vr")]
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

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].len(), 1);
    assert_eq!(results[0][0].id, "GHSA-5crp-9r3c-p9vr");
}

#[tokio::test]
async fn paginates_queries_independently_and_caches_complete_deduplicated_ids() {
    let server = MockServer::start().await;
    let packages = vec![npm_package("alpha"), npm_package("beta")];
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(&packages)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {
                    "vulns": [
                        osv_query_vulnerability("TEST-ALPHA-1"),
                        osv_query_vulnerability("TEST-ALPHA-DUP")
                    ],
                    "next_page_token": "alpha-page-2"
                },
                {
                    "vulns": [osv_query_vulnerability("TEST-BETA-1")],
                    "next_page_token": "beta-page-2"
                }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body_with_tokens(&[
            (&packages[0], Some("alpha-page-2")),
            (&packages[1], Some("beta-page-2")),
        ])))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {
                    "vulns": [
                        osv_query_vulnerability("TEST-ALPHA-DUP"),
                        osv_query_vulnerability("TEST-ALPHA-2")
                    ]
                },
                {
                    "vulns": [
                        osv_query_vulnerability("TEST-BETA-1"),
                        osv_query_vulnerability("TEST-BETA-2")
                    ],
                    "next_page_token": "beta-page-3"
                }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body_with_tokens(&[(
            &packages[1],
            Some("beta-page-3"),
        )])))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "vulns": [osv_query_vulnerability("TEST-BETA-3")]
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
    for id in ["TEST-ALPHA-1", "TEST-ALPHA-2", "TEST-ALPHA-DUP"] {
        cache_osv_document(&cache, &packages[0], id);
    }
    for id in ["TEST-BETA-1", "TEST-BETA-2", "TEST-BETA-3"] {
        cache_osv_document(&cache, &packages[1], id);
    }
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

    let results = client.query(&packages).await.unwrap();

    assert_eq!(
        results.vulnerabilities[&packages[0].key()]
            .iter()
            .map(|vulnerability| vulnerability.id.as_str())
            .collect::<Vec<_>>(),
        ["TEST-ALPHA-1", "TEST-ALPHA-2", "TEST-ALPHA-DUP"]
    );
    assert_eq!(
        results.vulnerabilities[&packages[1].key()]
            .iter()
            .map(|vulnerability| vulnerability.id.as_str())
            .collect::<Vec<_>>(),
        ["TEST-BETA-1", "TEST-BETA-2", "TEST-BETA-3"]
    );
    for (package, expected) in [
        (
            &packages[0],
            json!([
                osv_query_vulnerability("TEST-ALPHA-1"),
                osv_query_vulnerability("TEST-ALPHA-2"),
                osv_query_vulnerability("TEST-ALPHA-DUP")
            ]),
        ),
        (
            &packages[1],
            json!([
                osv_query_vulnerability("TEST-BETA-1"),
                osv_query_vulnerability("TEST-BETA-2"),
                osv_query_vulnerability("TEST-BETA-3")
            ]),
        ),
    ] {
        let (cached, _) = cache
            .get(
                "osv/query",
                &osv_query_cache_key(package),
                Duration::seconds(OSV_QUERY_TTL_SECS),
            )
            .expect("complete paginated query cache entry");
        assert_eq!(cached, expected);
    }
    server.verify().await;
}

#[tokio::test]
async fn rejects_a_regressing_osv_query_revision_without_downgrading_cache() {
    let server = MockServer::start().await;
    let package = npm_package("regressing-revision");
    let id = "TEST-REGRESSION-1";
    let older = "2026-08-18T00:00:00Z";
    let newer = "2026-08-19T00:00:00Z";
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(std::slice::from_ref(&package))))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"vulns": [osv_query_vulnerability_at(id, older)]}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    let query_key = osv_query_cache_key(&package);
    cache
        .put(
            "osv/query",
            &query_key,
            &json!([osv_query_vulnerability_at(id, newer)]),
            None,
        )
        .unwrap();
    age_cache_entry(&cache, "osv/query", &query_key, Duration::hours(2));
    let before = read_cache_entry(&cache, "osv/query", &query_key);
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

    let error = client
        .query(std::slice::from_ref(&package))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("regressed below"));
    let after = read_cache_entry(&cache, "osv/query", &query_key);
    assert_eq!(after.stored_at, before.stored_at);
    assert_eq!(after.value, before.value);
    server.verify().await;
}
