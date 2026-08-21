use super::*;

#[tokio::test]
async fn malformed_osv_batch_responses_fail_closed_without_query_cache_entries() {
    let cases = [
        (
            "non-object response",
            json!([]),
            1,
            "top-level value is not an object",
        ),
        (
            "missing results",
            json!({}),
            1,
            "required results field is missing",
        ),
        (
            "non-array results",
            json!({"results": {}}),
            1,
            "results field is not an array",
        ),
        (
            "too few results",
            json!({"results": [{}]}),
            2,
            "returned 1 results for 2 queries",
        ),
        (
            "too many results",
            json!({"results": [{}, {}, {}]}),
            2,
            "returned 3 results for 2 queries",
        ),
        (
            "non-object result",
            json!({"results": [null]}),
            1,
            "result 0 is not an object",
        ),
        (
            "non-empty result without vulns",
            json!({"results": [{"unexpected": true}]}),
            1,
            "result 0 is non-empty but has no vulns field",
        ),
        (
            "non-array vulns",
            json!({"results": [{"vulns": {}}]}),
            1,
            "result 0 has a non-array vulns field",
        ),
        (
            "non-string next page token",
            json!({"results": [{"vulns": [], "next_page_token": 42}]}),
            1,
            "result 0 has a non-string next_page_token field",
        ),
        (
            "empty next page token",
            json!({"results": [{"vulns": [], "next_page_token": ""}]}),
            1,
            "result 0 has an empty next_page_token field",
        ),
        (
            "non-object vulnerability",
            json!({"results": [{"vulns": ["GHSA-5crp-9r3c-p9vr"]}]}),
            1,
            "vulnerability 0 is not an object",
        ),
        (
            "missing vulnerability id",
            json!({"results": [{"vulns": [{"modified": "2026-08-19T00:00:00Z"}]}]}),
            1,
            "vulnerability 0 has no string id",
        ),
        (
            "non-string vulnerability id",
            json!({"results": [{"vulns": [{"id": 42}]}]}),
            1,
            "vulnerability 0 has no string id",
        ),
        (
            "missing modified timestamp",
            json!({"results": [{"vulns": [{"id": "TEST-MISSING-MODIFIED"}]}]}),
            1,
            "vulnerability 0 has no string modified timestamp",
        ),
        (
            "non-string modified timestamp",
            json!({"results": [{"vulns": [{
                "id": "TEST-NONSTRING-MODIFIED",
                "modified": 42
            }]}]}),
            1,
            "vulnerability 0 has no string modified timestamp",
        ),
        (
            "invalid modified timestamp",
            json!({"results": [{"vulns": [{
                "id": "TEST-INVALID-MODIFIED",
                "modified": "not-a-timestamp"
            }]}]}),
            1,
            "vulnerability 0 has an invalid modified timestamp",
        ),
        (
            "empty vulnerability id",
            json!({"results": [{"vulns": [{"id": ""}]}]}),
            1,
            "vulnerability 0 has an invalid id",
        ),
        (
            "unscoped vulnerability id",
            json!({"results": [{"vulns": [{"id": "invalid"}]}]}),
            1,
            "vulnerability 0 has an invalid id",
        ),
        (
            "whitespace vulnerability id",
            json!({"results": [{"vulns": [{"id": "GHSA-not valid"}]}]}),
            1,
            "vulnerability 0 has an invalid id",
        ),
    ];

    for (case, response, package_count, expected_message) in cases {
        let server = MockServer::start().await;
        let packages = (0..package_count)
            .map(|index| npm_package(&format!("fixture-{case}-{index}")))
            .collect::<Vec<_>>();
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(body_json(osv_query_body(&packages)))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        let client =
            OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

        let error = client.query(&packages).await.unwrap_err();

        match error {
            ProviderError::InvalidResponse(message) => assert!(
                message.contains(expected_message),
                "{case}: expected {expected_message:?}, got {message:?}"
            ),
            other => panic!("{case}: expected InvalidResponse, got {other:?}"),
        }
        for package in &packages {
            assert!(
                !cache
                    .filename("osv/query", &osv_query_cache_key(package))
                    .exists(),
                "{case}: malformed response created a query cache entry for {}",
                package.display_name
            );
        }
        server.verify().await;
    }
}

#[tokio::test]
async fn malformed_result_is_soft_when_an_aligned_package_result_is_complete() {
    let server = MockServer::start().await;
    let packages = vec![npm_package("valid-empty"), npm_package("malformed")];
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(&packages)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"vulns": []},
                {"vulns": [{"id": null}]}
            ]
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

    let outcome = client.query(&packages).await.unwrap();

    assert!(outcome.vulnerabilities[&packages[0].key()].is_empty());
    assert!(!outcome.vulnerabilities.contains_key(&packages[1].key()));
    assert!(
        outcome.errors[&packages[1].key()][0]
            .message
            .contains("result 1 vulnerability 0 has no string id")
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
async fn valid_empty_osv_batch_results_preserve_alignment_and_are_cached() {
    let server = MockServer::start().await;
    let packages = vec![npm_package("empty-object"), npm_package("empty-array")];
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(&packages)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{}, {"vulns": []}]
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

    let results = client.query(&packages).await.unwrap();

    assert_eq!(results.vulnerabilities.len(), packages.len());
    for package in &packages {
        assert!(results.vulnerabilities[&package.key()].is_empty());
        let (cached, _) = cache
            .get(
                "osv/query",
                &osv_query_cache_key(package),
                Duration::seconds(OSV_QUERY_TTL_SECS),
            )
            .unwrap();
        assert_eq!(cached, json!([]));
    }
    server.verify().await;
}

#[tokio::test]
async fn batch_pagination_stops_at_the_wall_clock_deadline() {
    let server = MockServer::start().await;
    let pages = Arc::new(AtomicUsize::new(0));
    let responder_pages = pages.clone();
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .respond_with(move |_: &wiremock::Request| {
            let page = responder_pages.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "results": [{
                        "vulns": [osv_query_vulnerability("TEST-DEADLINE-1")],
                        "next_page_token": format!("page-{page}")
                    }]
                }))
                .set_delay(std::time::Duration::from_millis(100))
        })
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache, server.uri())
        .with_batch_deadline(StdDuration::from_millis(250));
    let package = npm_package("deadline-fixture");

    let outcomes = client
        .query_batch_outcomes(std::slice::from_ref(&package))
        .await;

    assert_eq!(outcomes.len(), 1);
    let error = outcomes[0].as_ref().unwrap_err();
    assert!(
        error.to_string().contains("pagination deadline"),
        "expected a deadline failure, got: {error}"
    );
    let served = pages.load(Ordering::SeqCst);
    assert!(
        (1..OSV_MAX_QUERY_PAGES).contains(&served),
        "deadline must stop pagination well before the page cap, served {served} pages"
    );
}
