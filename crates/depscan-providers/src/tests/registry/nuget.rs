use super::*;

#[tokio::test]
async fn nuget_registration_follows_the_target_page_and_returns_canonical_identity() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/nuget/newtonsoft.json/index.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "versions": ["12.0.1", "13.0.3"]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let page_url = format!(
        "{}/registration/newtonsoft.json/page/12.0.1/13.0.3.json",
        server.uri()
    );
    Mock::given(method("GET"))
        .and(path("/registration/newtonsoft.json/index.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "count": 1,
            "items": [{
                "@id": page_url,
                "count": 2,
                "lower": "12.0.1",
                "upper": "13.0.3"
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/registration/newtonsoft.json/page/12.0.1/13.0.3.json",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "count": 2,
            "items": [
                {"catalogEntry": {"id": "Newtonsoft.Json", "version": "12.0.1"}},
                {"catalogEntry": {"id": "Newtonsoft.Json", "version": "13.0.3"}}
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
    let package = nuget_package("newtonsoft.json");

    let enrichment = nuget_registry_client(&server, cache)
        .latest(&package)
        .await
        .unwrap();

    assert_eq!(
        enrichment.canonical_name.as_deref(),
        Some("Newtonsoft.Json")
    );
    assert_eq!(enrichment.latest.latest_stable, "13.0.3");
    assert_eq!(package.display_name, "newtonsoft.json");
    assert_eq!(package.key(), "NuGet:newtonsoft.json:12.0.1");
    server.verify().await;
}

#[test]
fn nuget_registration_rejects_malformed_and_mismatched_catalog_identities() {
    let package = nuget_package("newtonsoft.json");
    let mismatched = nuget_registration_index("Other.Package", &["12.0.1"]);
    let NugetRegistrationPageSource::Inline(page) =
        nuget_registration_page_for_version(&mismatched, "12.0.1").unwrap()
    else {
        panic!("fixture page must be inline");
    };
    let mismatch =
        canonical_nuget_name_from_registration_page(&package, "12.0.1", &page).unwrap_err();
    assert!(
        mismatch
            .to_string()
            .contains("does not match requested package")
    );

    let malformed = json!({
        "count": 1,
        "items": [{
            "count": 1,
            "items": [{"catalogEntry": {"version": "12.0.1"}}],
            "lower": "12.0.1",
            "upper": "12.0.1"
        }]
    });
    let NugetRegistrationPageSource::Inline(page) =
        nuget_registration_page_for_version(&malformed, "12.0.1").unwrap()
    else {
        panic!("fixture page must be inline");
    };
    let missing =
        canonical_nuget_name_from_registration_page(&package, "12.0.1", &page).unwrap_err();
    assert!(missing.to_string().contains("has no catalogEntry.id"));
}

#[tokio::test]
async fn nuget_registry_enrichment_fails_when_registration_identity_is_unavailable() {
    let package = nuget_package("newtonsoft.json");
    let cases = [
        (
            "absent target version",
            json!({"count": 0, "items": []}),
            "no index page contains version",
        ),
        (
            "missing catalog ID",
            json!({
                "count": 1,
                "items": [{
                    "count": 1,
                    "items": [{"catalogEntry": {"version": "12.0.1"}}],
                    "lower": "12.0.1",
                    "upper": "12.0.1"
                }]
            }),
            "has no catalogEntry.id",
        ),
        (
            "mismatched catalog ID",
            nuget_registration_index("Other.Package", &["12.0.1"]),
            "does not match requested package",
        ),
    ];

    for (case, registration, expected) in cases {
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            root: cache_dir.path().to_path_buf(),
            policy: CachePolicy::default(),
        };
        cache
            .put(
                "registry",
                &nuget_registry_cache_key(&package),
                &json!({"versions": ["12.0.1", "13.0.3"]}),
                None,
            )
            .unwrap();
        cache
            .put(
                "registry",
                &nuget_registration_cache_key(&package),
                &registration,
                None,
            )
            .unwrap();

        let error = RegistryClient::new(HttpClient::new().unwrap(), cache)
            .latest(&package)
            .await
            .unwrap_err();

        assert!(
            error.to_string().contains(expected),
            "{case}: expected {expected:?}, got {error}"
        );
    }
}

#[test]
fn nuget_registration_page_links_are_origin_and_package_prefix_confined() {
    let package = nuget_package("newtonsoft.json");
    let base = "https://api.nuget.test/v3/registration";
    let valid = "https://api.nuget.test/v3/registration/newtonsoft.json/page/1/2.json";
    assert_eq!(
        validated_nuget_registration_page_url(base, &package, valid).unwrap(),
        valid
    );

    for invalid in [
        "https://attacker.invalid/v3/registration/newtonsoft.json/page/1/2.json",
        "https://api.nuget.test/v3/registration/other.package/page/1/2.json",
        "https://user:secret@api.nuget.test/v3/registration/newtonsoft.json/page/1/2.json",
    ] {
        assert!(
            validated_nuget_registration_page_url(base, &package, invalid).is_err(),
            "accepted unconfined registration page {invalid:?}"
        );
    }
}

#[test]
fn nuget_registration_page_prefix_encodes_the_package_segment_exactly() {
    let package = nuget_package("Contoso.Tools/@Edge %");
    let base = "https://api.nuget.test/v3/registration";
    let valid = concat!(
        "https://api.nuget.test/v3/registration/",
        "contoso.tools%2F%40edge%20%25/page/1/2.json"
    );

    assert_eq!(
        validated_nuget_registration_page_url(base, &package, valid).unwrap(),
        valid
    );
    for invalid in [
        "https://api.nuget.test/v3/registration/contoso.tools/@edge%20%25/page/1/2.json",
        "https://api.nuget.test/v3/registration/contoso.tools%2F%40other%20%25/page/1/2.json",
    ] {
        assert!(
            validated_nuget_registration_page_url(base, &package, invalid).is_err(),
            "accepted mismatched encoded prefix {invalid:?}"
        );
    }
}
