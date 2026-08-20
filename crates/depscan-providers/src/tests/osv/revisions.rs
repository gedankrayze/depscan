use super::*;

#[tokio::test]
async fn concurrent_osv_query_refresh_retries_instead_of_publishing_stale_results() {
    let server = MockServer::start().await;
    let package = npm_package("query-race");
    let id = "TEST-QUERY-RACE-1";
    let initial = "2026-08-17T00:00:00Z";
    let older = "2026-08-18T00:00:00Z";
    let newer = "2026-08-19T00:00:00Z";
    let slow_received = Arc::new(tokio::sync::Notify::new());
    let slow_responder_received = slow_received.clone();
    let slow_calls = Arc::new(AtomicUsize::new(0));
    let responder_calls = slow_calls.clone();
    Mock::given(method("POST"))
        .and(path("/slow/v1/querybatch"))
        .and(body_json(osv_query_body(std::slice::from_ref(&package))))
        .respond_with(move |_: &wiremock::Request| {
            if responder_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                slow_responder_received.notify_one();
                ResponseTemplate::new(200)
                    .set_body_json(json!({
                        "results": [{
                            "vulns": [osv_query_vulnerability_at(id, older)]
                        }]
                    }))
                    .set_delay(std::time::Duration::from_secs(1))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "results": [{
                        "vulns": [osv_query_vulnerability_at(id, newer)]
                    }]
                }))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/fast/v1/querybatch"))
        .and(body_json(osv_query_body(std::slice::from_ref(&package))))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"vulns": [osv_query_vulnerability_at(id, newer)]}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let newer_document = json!({
        "id": id,
        "modified": newer,
        "summary": "newest concurrent revision",
        "affected": [{
            "package": {"ecosystem": "npm", "name": "query-race"},
            "versions": ["1.0.0"]
        }]
    });
    Mock::given(method("GET"))
        .and(path(format!("/fast/v1/vulns/{id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&newer_document))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/slow/v1/vulns/{id}")))
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
            &json!([osv_query_vulnerability_at(id, initial)]),
            None,
        )
        .unwrap();
    age_cache_entry(&cache, "osv/query", &query_key, Duration::hours(2));
    let slow_client = OsvClient::with_base_url(
        HttpClient::new().unwrap(),
        cache.clone(),
        format!("{}/slow", server.uri()),
    );
    let fast_client = OsvClient::with_base_url(
        HttpClient::new().unwrap(),
        cache.clone(),
        format!("{}/fast", server.uri()),
    );
    let slow_package = package.clone();
    let slow_started = slow_received.notified();
    let slow =
        tokio::spawn(async move { slow_client.query(std::slice::from_ref(&slow_package)).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), slow_started)
        .await
        .expect("slow OSV query request was not received");

    let fast = fast_client
        .query(std::slice::from_ref(&package))
        .await
        .unwrap();
    let slow = slow.await.unwrap().unwrap();

    assert_eq!(
        fast.vulnerabilities[&package.key()][0].summary,
        "newest concurrent revision"
    );
    assert_eq!(
        slow.vulnerabilities[&package.key()][0].summary,
        "newest concurrent revision"
    );
    assert_eq!(slow_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        read_cache_entry(&cache, "osv/query", &query_key).value,
        json!([osv_query_vulnerability_at(id, newer)])
    );
    server.verify().await;
}

#[tokio::test]
async fn query_revisions_invalidate_legacy_and_changed_hydrated_advisories() {
    let package = npm_package("revisioned");
    let id = "TEST-REVISION-1";
    let first_modified = "2026-08-18T00:00:00Z";
    let second_modified = "2026-08-19T00:00:00Z";
    let first_document = json!({
        "id": id,
        "modified": first_modified,
        "summary": "first revision",
        "severity": [{
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
        }],
        "affected": [{
            "package": {"ecosystem": "npm", "name": "revisioned"},
            "ranges": [{
                "type": "SEMVER",
                "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]
            }]
        }]
    });
    let second_document = json!({
        "id": id,
        "modified": second_modified,
        "withdrawn": "2026-08-19T00:00:00Z",
        "summary": "updated revision",
        "severity": [{
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }],
        "affected": [{
            "package": {"ecosystem": "npm", "name": "revisioned"},
            "ranges": [{
                "type": "SEMVER",
                "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]
            }]
        }]
    });
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    // These are the two legacy ID-only cache shapes. Neither may be treated as revisioned.
    cache
        .put(
            "osv/query",
            &osv_query_cache_key(&package),
            &json!([id]),
            None,
        )
        .unwrap();
    cache.put("osv/vuln", id, &first_document, None).unwrap();

    let first_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(std::slice::from_ref(&package))))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "vulns": [osv_query_vulnerability_at(id, first_modified)]
            }]
        })))
        .expect(1)
        .mount(&first_server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&first_document))
        .expect(1)
        .mount(&first_server)
        .await;
    let first_client = OsvClient::with_base_url(
        HttpClient::new().unwrap(),
        cache.clone(),
        first_server.uri(),
    );

    let first = first_client
        .query(std::slice::from_ref(&package))
        .await
        .unwrap();
    let first = &first.vulnerabilities[&package.key()][0];
    assert_eq!(first.summary, "first revision");
    assert_eq!(first.fixed_in, ["2.0.0"]);
    assert!(!first.withdrawn);
    let first_score = first.cvss_score.unwrap();
    first_server.verify().await;

    age_cache_entry(
        &cache,
        "osv/query",
        &osv_query_cache_key(&package),
        Duration::hours(2),
    );
    let second_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(std::slice::from_ref(&package))))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "vulns": [osv_query_vulnerability_at(id, second_modified)]
            }]
        })))
        .expect(1)
        .mount(&second_server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vulns/{id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&second_document))
        .expect(1)
        .mount(&second_server)
        .await;
    let second_client = OsvClient::with_base_url(
        HttpClient::new().unwrap(),
        cache.clone(),
        second_server.uri(),
    );

    let second = second_client
        .query(std::slice::from_ref(&package))
        .await
        .unwrap();
    let second = &second.vulnerabilities[&package.key()][0];
    assert_eq!(second.summary, "updated revision");
    assert_eq!(second.fixed_in, ["3.0.0"]);
    assert!(second.withdrawn);
    assert!(second.cvss_score.unwrap() > first_score);
    second_server.verify().await;

    // Refreshing the query with an unchanged revision must reuse the hydrated revision cache.
    age_cache_entry(
        &cache,
        "osv/query",
        &osv_query_cache_key(&package),
        Duration::hours(2),
    );
    let unchanged_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/querybatch"))
        .and(body_json(osv_query_body(std::slice::from_ref(&package))))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{
                "vulns": [osv_query_vulnerability_at(id, second_modified)]
            }]
        })))
        .expect(1)
        .mount(&unchanged_server)
        .await;
    let unchanged_client = OsvClient::with_base_url(
        HttpClient::new().unwrap(),
        cache.clone(),
        unchanged_server.uri(),
    );

    let unchanged = unchanged_client
        .query(std::slice::from_ref(&package))
        .await
        .unwrap();

    assert_eq!(
        unchanged.vulnerabilities[&package.key()][0].summary,
        "updated revision"
    );
    unchanged_server.verify().await;
    let cached_query = read_cache_entry(&cache, "osv/query", &osv_query_cache_key(&package));
    assert_eq!(
        cached_query.value,
        json!([osv_query_vulnerability_at(id, second_modified)])
    );
}
