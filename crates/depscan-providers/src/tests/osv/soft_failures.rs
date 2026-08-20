use super::*;

#[tokio::test]
async fn rejects_repeated_page_tokens_without_caching_partial_ids() {
    let server = MockServer::start().await;
    let package = npm_package("repeated-token");
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(std::slice::from_ref(&package))))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "vulns": [osv_query_vulnerability("TEST-PARTIAL-1")],
                "next_page_token": "repeat-me"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body_with_tokens(&[(
            &package,
            Some("repeat-me"),
        )])))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "vulns": [osv_query_vulnerability("TEST-PARTIAL-2")],
                "next_page_token": "repeat-me"
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
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

    let error = client
        .query(std::slice::from_ref(&package))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("repeated a next_page_token"));
    assert!(
        !cache
            .filename("osv/query", &osv_query_cache_key(&package))
            .exists()
    );
    server.verify().await;
}

#[tokio::test]
async fn later_page_failure_does_not_cache_the_partial_query() {
    let server = MockServer::start().await;
    let package = npm_package("page-failure");
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(std::slice::from_ref(&package))))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "vulns": [osv_query_vulnerability("TEST-PARTIAL-1")],
                "next_page_token": "broken-page"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body_with_tokens(&[(
            &package,
            Some("broken-page"),
        )])))
        .respond_with(ResponseTemplate::new(400))
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

    let error = client
        .query(std::slice::from_ref(&package))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("HTTP 400"));
    assert!(
        !cache
            .filename("osv/query", &osv_query_cache_key(&package))
            .exists()
    );
    server.verify().await;
}

#[tokio::test]
async fn later_page_failure_is_soft_for_only_the_still_pending_package() {
    let server = MockServer::start().await;
    let packages = vec![npm_package("page-complete"), npm_package("page-incomplete")];
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(&packages)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {},
                {
                    "vulns": [osv_query_vulnerability("TEST-PARTIAL-PAGE")],
                    "next_page_token": "broken-page"
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
            Some("broken-page"),
        )])))
        .respond_with(ResponseTemplate::new(400))
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

    let outcome = client.query(&packages).await.unwrap();

    assert!(outcome.vulnerabilities[&packages[0].key()].is_empty());
    assert!(!outcome.vulnerabilities.contains_key(&packages[1].key()));
    assert!(!outcome.errors.contains_key(&packages[0].key()));
    assert!(
        outcome.errors[&packages[1].key()][0]
            .message
            .contains("HTTP 400")
    );
    assert!(
        cache
            .filename("osv/query", &osv_query_cache_key(&packages[0]))
            .exists()
    );
    assert!(
        !cache
            .filename("osv/query", &osv_query_cache_key(&packages[1]))
            .exists()
    );
    server.verify().await;
}

#[tokio::test]
async fn failed_query_chunk_is_soft_when_another_chunk_completes() {
    let server = MockServer::start().await;
    let packages = (0..1001)
        .map(|index| npm_package(&format!("chunk-{index}")))
        .collect::<Vec<_>>();
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(&packages[..1000])))
        .respond_with(ResponseTemplate::new(400))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(&packages[1000..])))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": [{}]})))
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

    let outcome = client.query(&packages).await.unwrap();

    assert_eq!(outcome.errors.len(), 1000);
    assert!(outcome.vulnerabilities[&packages[1000].key()].is_empty());
    assert!(!outcome.errors.contains_key(&packages[1000].key()));
    assert!(
        !cache
            .filename("osv/query", &osv_query_cache_key(&packages[0]))
            .exists()
    );
    assert!(
        cache
            .filename("osv/query", &osv_query_cache_key(&packages[1000]))
            .exists()
    );
    server.verify().await;
}

#[tokio::test]
async fn query_cache_failure_does_not_discard_a_valid_network_result() {
    let server = MockServer::start().await;
    let package = npm_package("query-cache-unwritable");
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(std::slice::from_ref(&package))))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": [{}]})))
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    fs::write(cache_dir.path().join("osv"), b"not a directory").unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache, server.uri());

    let outcome = client.query(std::slice::from_ref(&package)).await.unwrap();

    assert!(outcome.vulnerabilities[&package.key()].is_empty());
    assert!(
        outcome.errors[&package.key()]
            .iter()
            .any(|error| error.message.contains("query cache publication failed"))
    );
    server.verify().await;
}

#[tokio::test]
async fn hydration_cache_failure_does_not_discard_a_valid_advisory() {
    let server = MockServer::start().await;
    let package = npm_package("hydration-cache-unwritable");
    let advisory = "TEST-CACHE-WARNING";
    let revision = OsvVulnerabilityRevision {
        id: advisory.to_owned(),
        modified: test_timestamp(TEST_OSV_MODIFIED),
    };
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{advisory}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": advisory,
            "modified": TEST_OSV_MODIFIED,
            "summary": "valid advisory despite an unwritable cache",
            "affected": [{
                "package": {"ecosystem": "npm", "name": package.name},
                "versions": [package.version]
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
    cache
        .put(
            "osv/query",
            &osv_query_cache_key(&package),
            &serde_json::to_value(vec![revision]).unwrap(),
            None,
        )
        .unwrap();
    fs::write(cache.root().join("osv/vuln"), b"not a directory").unwrap();
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache, server.uri());

    let outcome = client.query(std::slice::from_ref(&package)).await.unwrap();

    assert_eq!(outcome.vulnerabilities[&package.key()].len(), 1);
    assert_eq!(outcome.vulnerabilities[&package.key()][0].id, advisory);
    assert!(
        outcome.errors[&package.key()]
            .iter()
            .any(|error| error.message.contains("cache publication failed"))
    );
    server.verify().await;
}

#[tokio::test]
async fn malformed_affected_hydration_fails_hard_without_entering_the_cache() {
    let server = MockServer::start().await;
    let package = npm_package("malformed-affected");
    let advisory = "TEST-MALFORMED-AFFECTED";
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(std::slice::from_ref(&package))))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"vulns": [osv_query_vulnerability(advisory)]}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{advisory}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": advisory,
            "modified": TEST_OSV_MODIFIED,
            "affected": {"package": "not-an-array"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

    let error = client
        .query(std::slice::from_ref(&package))
        .await
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("affected must be a present array")
    );
    let revision = OsvVulnerabilityRevision {
        id: advisory.to_owned(),
        modified: test_timestamp(TEST_OSV_MODIFIED),
    };
    assert!(!cache.filename("osv/vuln", &revision.cache_key()).exists());
    server.verify().await;
}
