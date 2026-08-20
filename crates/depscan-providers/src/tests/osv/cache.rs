use super::*;

#[test]
fn hydration_cache_keys_never_downgrade_newer_alias_documents() {
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    let client = OsvClient::with_base_url(
        HttpClient::new().unwrap(),
        cache.clone(),
        "https://unused.invalid",
    );
    let id = "TEST-HYDRATION-MONOTONIC-1";
    let requested = OsvVulnerabilityRevision {
        id: id.to_owned(),
        modified: DateTime::parse_from_rfc3339("2026-08-18T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
    };
    let newer_document = json!({
        "id": id,
        "modified": "2026-08-20T00:00:00Z",
        "summary": "newer alias document",
        "affected": []
    });
    let older_document = json!({
        "id": id,
        "modified": "2026-08-19T00:00:00Z",
        "summary": "late older document",
        "affected": []
    });
    cache
        .put("osv/vuln", &requested.cache_key(), &newer_document, None)
        .unwrap();

    let winner = client
        .publish_hydrated_document(&requested.cache_key(), id, &older_document, None, true)
        .unwrap();

    assert_eq!(winner.value, newer_document);
    assert_eq!(
        read_cache_entry(&cache, "osv/vuln", &requested.cache_key()).value,
        newer_document
    );
}

#[test]
fn cache_bypass_publication_preserves_the_newer_disk_winner() {
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy {
            read: false,
            max_age: None,
        },
    };
    let client = OsvClient::with_base_url(
        HttpClient::new().unwrap(),
        cache.clone(),
        "https://unused.invalid",
    );
    let id = "TEST-HYDRATION-BYPASS-1";
    let revision = OsvVulnerabilityRevision {
        id: id.to_owned(),
        modified: DateTime::parse_from_rfc3339("2026-08-18T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
    };
    let cached_newer = json!({
        "id": id,
        "modified": "2026-08-20T00:00:00Z",
        "summary": "cached representation",
        "affected": []
    });
    let network_candidate = json!({
        "id": id,
        "modified": "2026-08-19T00:00:00Z",
        "summary": "network representation",
        "affected": []
    });
    cache
        .put("osv/vuln", &revision.cache_key(), &cached_newer, None)
        .unwrap();

    let reported = client
        .publish_hydrated_document(&revision.cache_key(), id, &network_candidate, None, true)
        .unwrap();

    assert_eq!(reported.value, cached_newer);
    assert_eq!(
        read_cache_entry(&cache, "osv/vuln", &revision.cache_key()).value,
        cached_newer
    );
}

#[tokio::test]
async fn newer_hydration_is_reused_under_the_requested_revision_without_etag_aliasing() {
    let server = MockServer::start().await;
    let id = "TEST-HYDRATION-ALIAS-1";
    let requested = OsvVulnerabilityRevision {
        id: id.to_owned(),
        modified: DateTime::parse_from_rfc3339("2026-08-18T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
    };
    let actual = OsvVulnerabilityRevision {
        id: id.to_owned(),
        modified: DateTime::parse_from_rfc3339("2026-08-19T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
    };
    let document = json!({
        "id": id,
        "modified": "2026-08-19T00:00:00Z",
        "summary": "newer than querybatch",
        "affected": []
    });
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{id}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"hydration-2\"")
                .set_body_json(&document),
        )
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

    let first = client.hydrate(&requested).await.unwrap();
    assert_eq!(first.value, document);
    assert!(first.cache_warning.is_none());
    let second = client.hydrate(&requested).await.unwrap();
    assert_eq!(second.value, document);
    assert!(second.cache_warning.is_none());

    let actual_entry = read_cache_entry(&cache, "osv/vuln", &actual.cache_key());
    assert_eq!(actual_entry.value, document);
    assert_eq!(actual_entry.etag.as_deref(), Some("\"hydration-2\""));
    let alias_entry = read_cache_entry(&cache, "osv/vuln", &requested.cache_key());
    assert_eq!(alias_entry.value, document);
    assert!(alias_entry.etag.is_none());
    server.verify().await;
}

#[tokio::test]
async fn future_hydration_entry_is_not_reused_without_network_validation() {
    let server = MockServer::start().await;
    let id = "TEST-HYDRATION-FUTURE-1";
    let revision = OsvVulnerabilityRevision {
        id: id.to_owned(),
        modified: test_timestamp(TEST_OSV_MODIFIED),
    };
    let cached_document = json!({
        "id": id,
        "modified": TEST_OSV_MODIFIED,
        "summary": "future-dated cached representation",
        "affected": []
    });
    let network_document = json!({
        "id": id,
        "modified": TEST_OSV_MODIFIED,
        "summary": "network-validated representation",
        "affected": []
    });
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&network_document))
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    cache
        .put("osv/vuln", &revision.cache_key(), &cached_document, None)
        .unwrap();
    set_cache_entry_timestamp(
        &cache,
        "osv/vuln",
        &revision.cache_key(),
        Utc::now() + Duration::days(1),
    );
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

    let reported = client.hydrate(&revision).await.unwrap();

    assert_eq!(reported.value, network_document);
    assert!(reported.cache_warning.is_none());
    assert_eq!(
        read_cache_entry(&cache, "osv/vuln", &revision.cache_key()).value,
        cached_document,
        "the future entry remains only as a raw CAS generation, not a reusable result"
    );
    server.verify().await;
}

#[tokio::test]
async fn cache_bypass_returns_network_hydration_but_aliases_the_newer_disk_winner() {
    let server = MockServer::start().await;
    let id = "TEST-HYDRATION-BYPASS-ALIAS-1";
    let requested = OsvVulnerabilityRevision {
        id: id.to_owned(),
        modified: DateTime::parse_from_rfc3339("2026-08-18T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
    };
    let actual = OsvVulnerabilityRevision {
        id: id.to_owned(),
        modified: DateTime::parse_from_rfc3339("2026-08-19T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
    };
    let network_document = json!({
        "id": id,
        "modified": "2026-08-19T00:00:00Z",
        "summary": "fresh network representation",
        "affected": []
    });
    let cached_newer = json!({
        "id": id,
        "modified": "2026-08-20T00:00:00Z",
        "summary": "newer cached representation",
        "affected": []
    });
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&network_document))
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy {
            read: false,
            max_age: None,
        },
    };
    cache
        .put(
            "osv/vuln",
            &actual.cache_key(),
            &cached_newer,
            Some("\"hydration-3\"".to_owned()),
        )
        .unwrap();
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

    let reported = client.hydrate(&requested).await.unwrap();

    assert_eq!(reported.value, network_document);
    assert!(reported.cache_warning.is_none());
    assert_eq!(
        read_cache_entry(&cache, "osv/vuln", &actual.cache_key()).value,
        cached_newer
    );
    let alias = read_cache_entry(&cache, "osv/vuln", &requested.cache_key());
    assert_eq!(alias.value, cached_newer);
    assert!(alias.etag.is_none());
    server.verify().await;
}

#[tokio::test]
async fn cache_bypass_ignores_a_future_dated_stale_osv_revision() {
    let server = MockServer::start().await;
    let package = npm_package("bypass-future-revision");
    let id = "TEST-BYPASS-FUTURE-1";
    let origin_modified = "2026-08-19T00:00:00Z";
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(std::slice::from_ref(&package))))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "vulns": [osv_query_vulnerability_at(id, origin_modified)]
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": id,
            "modified": origin_modified,
            "summary": "fresh bypass response",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "bypass-future-revision"},
                "versions": ["1.0.0"]
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy {
            read: false,
            max_age: None,
        },
    };
    let query_key = osv_query_cache_key(&package);
    cache
        .put(
            "osv/query",
            &query_key,
            &json!([osv_query_vulnerability_at(id, "2026-08-21T00:00:00Z")]),
            None,
        )
        .unwrap();
    set_cache_entry_timestamp(
        &cache,
        "osv/query",
        &query_key,
        Utc::now() + Duration::days(1),
    );
    let client = OsvClient::with_base_url(HttpClient::new().unwrap(), cache.clone(), server.uri());

    let result = client.query(std::slice::from_ref(&package)).await.unwrap();

    assert_eq!(
        result.vulnerabilities[&package.key()][0].summary,
        "fresh bypass response"
    );
    assert_eq!(
        read_cache_entry(&cache, "osv/query", &query_key).value,
        json!([osv_query_vulnerability_at(id, origin_modified)])
    );
    server.verify().await;
}
