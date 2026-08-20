use super::*;

#[test]
fn builds_lowercase_sparse_paths_at_every_length_boundary() {
    let max_name = format!("A{}", "z".repeat(CRATES_IO_MAX_NAME_LEN - 1));
    let max_path = format!("az/zz/{}", max_name.to_ascii_lowercase());
    let cases = [
        ("a".to_owned(), "1/a".to_owned()),
        ("Z".to_owned(), "1/z".to_owned()),
        ("a1".to_owned(), "2/a1".to_owned()),
        ("AB".to_owned(), "2/ab".to_owned()),
        ("a-b".to_owned(), "3/a/a-b".to_owned()),
        ("A_B".to_owned(), "3/a/a_b".to_owned()),
        ("abcd".to_owned(), "ab/cd/abcd".to_owned()),
        ("Serde_JSON".to_owned(), "se/rd/serde_json".to_owned()),
        (max_name, max_path),
    ];

    for (name, expected) in cases {
        assert_eq!(crates_io_sparse_path(&name).unwrap(), expected, "{name}");
    }
}

#[test]
fn accepts_all_structural_name_characters_through_the_length_limit() {
    const FIRST_CHARACTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const REMAINING_CHARACTERS: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

    for len in 1..=CRATES_IO_MAX_NAME_LEN {
        for &first in FIRST_CHARACTERS {
            for &remaining in REMAINING_CHARACTERS {
                let mut bytes = vec![remaining; len];
                bytes[0] = first;
                let name = String::from_utf8(bytes).unwrap();
                let result = std::panic::catch_unwind(|| crates_io_sparse_path(&name));
                let path = result
                    .unwrap_or_else(|_| panic!("sparse path construction panicked for {name:?}"))
                    .unwrap_or_else(|error| panic!("valid name {name:?} failed: {error}"));

                assert!(path.is_ascii());
                assert_eq!(path, path.to_ascii_lowercase());
                assert!(path.ends_with(&name.to_ascii_lowercase()));
            }
        }
    }
}

#[test]
fn rejects_every_disallowed_ascii_character_without_panicking() {
    for byte in 0_u8..=127 {
        if !byte.is_ascii_alphabetic() {
            assert_invalid_crates_name(&char::from(byte).to_string());
        }

        if !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')) {
            assert_invalid_crates_name(&format!("a{}", char::from(byte)));
        }
    }
}

#[test]
fn rejects_empty_unicode_separators_controls_overlong_and_punctuation() {
    let overlong = "a".repeat(CRATES_IO_MAX_NAME_LEN + 1);
    let very_long = "a".repeat(4_096);
    let invalid = [
        "",
        "é",
        "a🦀",
        "a/b",
        "a\\b",
        "../serde",
        "a\0b",
        "a\nb",
        "a\tb",
        "1crate",
        "-crate",
        "_crate",
        "crate.name",
        "crate@name",
        "crate name",
        overlong.as_str(),
        very_long.as_str(),
    ];

    for name in invalid {
        assert_invalid_crates_name(name);
    }
}

#[tokio::test]
async fn valid_crates_names_request_the_expected_sparse_index_paths() {
    let server = MockServer::start().await;
    let cases = [
        ("A", "/1/a"),
        ("aB", "/2/ab"),
        ("A-B", "/3/a/a-b"),
        ("Serde_JSON", "/se/rd/serde_json"),
    ];
    for (name, expected_path) in cases {
        let body = format!("{{\"name\":\"{name}\",\"vers\":\"1.0.0\",\"yanked\":false}}\n");
        Mock::given(method("GET"))
            .and(path(expected_path))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "text/plain"))
            .expect(1)
            .mount(&server)
            .await;
    }
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = Cache {
        root: cache_dir.path().to_path_buf(),
        policy: CachePolicy::default(),
    };
    let client =
        RegistryClient::with_crates_index_base_url(HttpClient::new().unwrap(), cache, server.uri());

    for (name, _) in cases {
        let latest = client.latest(&crates_package(name)).await.unwrap();
        assert_eq!(latest.latest.latest_stable, "1.0.0");
    }
    server.verify().await;
}

#[tokio::test]
async fn invalid_crates_names_return_typed_errors_without_http_requests() {
    let server = MockServer::start().await;
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
    let client =
        RegistryClient::with_crates_index_base_url(HttpClient::new().unwrap(), cache, server.uri());
    let invalid = ["", "é", "a/b", "a\0b", "1crate", "crate.name"];

    for name in invalid {
        let error = client.latest(&crates_package(name)).await.unwrap_err();
        match error {
            ProviderError::InvalidPackageName {
                ecosystem,
                name: rejected,
                reason,
            } => {
                assert_eq!(ecosystem, Ecosystem::CratesIo);
                assert_eq!(rejected, name);
                assert!(!reason.is_empty());
            }
            other => panic!("expected a typed package-name error, got {other:?}"),
        }
    }
    server.verify().await;
}
