use super::*;

#[tokio::test]
async fn malformed_security_fields_fail_hydration_without_entering_the_cache() {
    let package = npm_package("malformed-security-fields");
    let mut cases = Vec::new();

    let mut document = valid_osv_document_value("TEST-MISSING-AFFECTED", &package);
    document.as_object_mut().unwrap().remove("affected");
    cases.push((
        "TEST-MISSING-AFFECTED",
        document,
        "affected must be a present array",
    ));

    let mut document = valid_osv_document_value("TEST-MALFORMED-IDENTITY", &package);
    document["affected"][0]["package"]["name"] = Value::Null;
    cases.push((
        "TEST-MALFORMED-IDENTITY",
        document,
        "package.name must be a string",
    ));

    for (id, value, expected) in [
        ("TEST-NULL-WITHDRAWN", Value::Null, "RFC 3339 string"),
        ("TEST-BOOL-WITHDRAWN", json!(false), "RFC 3339 string"),
        (
            "TEST-BAD-WITHDRAWN",
            json!("not-a-timestamp"),
            "valid RFC 3339 timestamp",
        ),
    ] {
        let mut document = valid_osv_document_value(id, &package);
        document["withdrawn"] = value;
        cases.push((id, document, expected));
    }

    for (advisory, document, expected) in cases {
        let server = MockServer::start().await;
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
            .respond_with(ResponseTemplate::new(200).set_body_json(document))
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

        let error = client
            .query(std::slice::from_ref(&package))
            .await
            .unwrap_err();

        assert!(
            error.to_string().contains(expected),
            "{advisory}: expected {expected:?}, got {error}"
        );
        let revision = OsvVulnerabilityRevision {
            id: advisory.to_owned(),
            modified: test_timestamp(TEST_OSV_MODIFIED),
        };
        assert!(
            !cache.filename("osv/vuln", &revision.cache_key()).exists(),
            "{advisory}: malformed hydration entered the cache"
        );
        server.verify().await;
    }
}

#[tokio::test]
async fn malformed_hydration_cache_is_bypassed_and_replaced() {
    let server = MockServer::start().await;
    let package = npm_package("malformed-cached-advisory");
    let advisory = "TEST-MALFORMED-CACHED-ADVISORY";
    let revision = OsvVulnerabilityRevision {
        id: advisory.to_owned(),
        modified: test_timestamp(TEST_OSV_MODIFIED),
    };
    let mut malformed = valid_osv_document_value(advisory, &package);
    malformed["withdrawn"] = Value::Null;
    let valid = valid_osv_document_value(advisory, &package);

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{advisory}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&valid))
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
            &serde_json::to_value(std::slice::from_ref(&revision)).unwrap(),
            None,
        )
        .unwrap();
    cache
        .put("osv/vuln", &revision.cache_key(), &malformed, None)
        .unwrap();
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

    let outcome = client.query(std::slice::from_ref(&package)).await.unwrap();

    assert_eq!(outcome.vulnerabilities[&package.key()].len(), 1);
    assert_eq!(outcome.vulnerabilities[&package.key()][0].id, advisory);
    let cached = read_cache_entry(&cache, "osv/vuln", &revision.cache_key());
    assert_eq!(cached.value, valid);
    server.verify().await;
}

#[tokio::test]
async fn query_hits_require_a_matching_evaluable_affected_entry() {
    let package = npm_package("query-hit-shape");
    let cases = [
        ("TEST-EMPTY-AFFECTED", json!([])),
        (
            "TEST-WRONG-AFFECTED-IDENTITY",
            json!([{
                "package": {"ecosystem": "npm", "name": "another-package"},
                "versions": ["1.0.0"]
            }]),
        ),
        (
            "TEST-NON-EVALUABLE-AFFECTED",
            json!([{
                "package": {"ecosystem": "npm", "name": "query-hit-shape"},
                "versions": [],
                "ranges": []
            }]),
        ),
    ];

    for (advisory, affected) in cases {
        let server = MockServer::start().await;
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
                "affected": affected
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

        let error = client
            .query(std::slice::from_ref(&package))
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("no matching evaluable affected entry"),
            "{advisory}: unexpected error {error}"
        );
        server.verify().await;
    }
}

#[tokio::test]
async fn hydration_and_evaluation_failures_preserve_other_advisories() {
    let server = MockServer::start().await;
    let package = npm_package("partial-advisories");
    let hydration_failure = "TEST-HYDRATION-FAILURE";
    let evaluation_failure = "TEST-EVALUATION-FAILURE";
    let malformed_affected = "TEST-MALFORMED-AFFECTED-SOFT";
    let mismatched_identity = "TEST-MISMATCHED-IDENTITY-SOFT";
    let invalid_withdrawn = "TEST-INVALID-WITHDRAWN-SOFT";
    let valid = "TEST-VALID-ADVISORY";
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(std::slice::from_ref(&package))))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"vulns": [
                osv_query_vulnerability(hydration_failure),
                osv_query_vulnerability(evaluation_failure),
                osv_query_vulnerability(malformed_affected),
                osv_query_vulnerability(mismatched_identity),
                osv_query_vulnerability(invalid_withdrawn),
                osv_query_vulnerability(valid)
            ]}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{mismatched_identity}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": mismatched_identity,
            "modified": TEST_OSV_MODIFIED,
            "affected": [{
                "package": {"ecosystem": "npm", "name": "another-package"},
                "versions": ["1.0.0"]
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{invalid_withdrawn}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": invalid_withdrawn,
            "modified": TEST_OSV_MODIFIED,
            "withdrawn": null,
            "affected": [{
                "package": {"ecosystem": "npm", "name": "partial-advisories"},
                "versions": ["1.0.0"]
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{malformed_affected}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": malformed_affected,
            "modified": TEST_OSV_MODIFIED,
            "affected": "not-an-array"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{hydration_failure}")))
        .respond_with(ResponseTemplate::new(400))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{evaluation_failure}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": evaluation_failure,
            "modified": TEST_OSV_MODIFIED,
            "summary": "cannot evaluate a commit graph",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "partial-advisories"},
                "ranges": [{
                    "type": "GIT",
                    "repo": "https://example.invalid/partial-advisories.git",
                    "events": [{"introduced": "0"}]
                }]
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{valid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": valid,
            "modified": TEST_OSV_MODIFIED,
            "summary": "valid advisory",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "partial-advisories"},
                "versions": ["1.0.0"]
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

    let outcome = client.query(std::slice::from_ref(&package)).await.unwrap();

    assert_eq!(outcome.vulnerabilities[&package.key()].len(), 1);
    assert_eq!(outcome.vulnerabilities[&package.key()][0].id, valid);
    let messages = outcome.errors[&package.key()]
        .iter()
        .map(|error| error.message.as_str())
        .collect::<Vec<_>>();
    assert!(messages.iter().any(|message| {
        message.contains(hydration_failure) && message.contains("hydration failed")
    }));
    assert!(messages.iter().any(|message| {
        message.contains(evaluation_failure) && message.contains("evaluation failed")
    }));
    assert!(messages.iter().any(|message| {
        message.contains(malformed_affected) && message.contains("hydration failed")
    }));
    assert!(messages.iter().any(|message| {
        message.contains(mismatched_identity) && message.contains("evaluation failed")
    }));
    assert!(messages.iter().any(|message| {
        message.contains(invalid_withdrawn) && message.contains("hydration failed")
    }));
    let failed_revision = OsvVulnerabilityRevision {
        id: hydration_failure.to_owned(),
        modified: DateTime::parse_from_rfc3339(TEST_OSV_MODIFIED)
            .unwrap()
            .with_timezone(&Utc),
    };
    assert!(
        !cache
            .filename("osv/vuln", &failed_revision.cache_key())
            .exists()
    );
    let malformed_revision = OsvVulnerabilityRevision {
        id: malformed_affected.to_owned(),
        modified: test_timestamp(TEST_OSV_MODIFIED),
    };
    assert!(
        !cache
            .filename("osv/vuln", &malformed_revision.cache_key())
            .exists()
    );
    let invalid_withdrawn_revision = OsvVulnerabilityRevision {
        id: invalid_withdrawn.to_owned(),
        modified: test_timestamp(TEST_OSV_MODIFIED),
    };
    assert!(
        !cache
            .filename("osv/vuln", &invalid_withdrawn_revision.cache_key())
            .exists()
    );
    server.verify().await;
}
