use super::*;

#[tokio::test]
async fn rejects_invalid_utf8_with_the_source_line_number() {
    let mut body = b"{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":false}\n".to_vec();
    body.extend_from_slice(&[0xff, b'\n']);

    assert_invalid_sparse_response(body, &["sparse-index line 2", "not valid UTF-8"]).await;
}

#[tokio::test]
async fn rejects_a_malformed_line_between_valid_entries() {
    let body = concat!(
        "{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
        "{\"name\":\"fixture\",\"vers\":\"1.1.0\"\n",
        "{\"name\":\"fixture\",\"vers\":\"2.0.0\",\"yanked\":false}\n",
    );

    assert_invalid_sparse_response(
        body.as_bytes().to_vec(),
        &["sparse-index line 2", "invalid JSON"],
    )
    .await;
}

#[tokio::test]
async fn rejects_a_truncated_final_sparse_index_line() {
    let body = concat!(
        "{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
        "{\"name\":\"fixture\",\"vers\":\"2.0.0\"",
    );

    assert_invalid_sparse_response(
        body.as_bytes().to_vec(),
        &["sparse-index line 2", "invalid JSON"],
    )
    .await;
}

#[tokio::test]
async fn rejects_missing_wrong_or_invalid_selection_fields() {
    let cases = [
        (
            "{\"vers\":\"1.0.0\",\"yanked\":false}\n",
            vec!["sparse-index line 1", "missing field `name`"],
        ),
        (
            "{\"name\":7,\"vers\":\"1.0.0\",\"yanked\":false}\n",
            vec!["sparse-index line 1", "invalid type"],
        ),
        (
            "{\"name\":\"fixture\",\"yanked\":false}\n",
            vec!["sparse-index line 1", "missing field `vers`"],
        ),
        (
            "{\"name\":\"fixture\",\"vers\":false,\"yanked\":false}\n",
            vec!["sparse-index line 1", "invalid type"],
        ),
        (
            "{\"name\":\"fixture\",\"vers\":\"not-semver\",\"yanked\":false}\n",
            vec!["sparse-index line 1", "field `vers` is not valid SemVer"],
        ),
        (
            "{\"name\":\"fixture\",\"vers\":\"1.0.0\"}\n",
            vec!["sparse-index line 1", "missing field `yanked`"],
        ),
        (
            "{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":\"no\"}\n",
            vec!["sparse-index line 1", "invalid type"],
        ),
        (
            "{\"name\":\"different\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
            vec!["sparse-index line 1", "does not match requested crate"],
        ),
        ("", vec!["contains no version entries"]),
    ];

    for (body, expected_fragments) in cases {
        assert_invalid_sparse_response(body.as_bytes().to_vec(), &expected_fragments).await;
    }
}

#[tokio::test]
async fn rejects_duplicate_or_conflicting_version_records() {
    let body = concat!(
        "{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":false}\n",
        "{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":true}\n",
    );

    assert_invalid_sparse_response(
        body.as_bytes().to_vec(),
        &["sparse-index line 2", "duplicate version", "line 1"],
    )
    .await;
}

#[tokio::test]
async fn rejects_oversized_sparse_index_lines() {
    let padding = "x".repeat(CRATES_IO_MAX_INDEX_LINE_BYTES);
    let body = format!(
        "{{\"name\":\"fixture\",\"vers\":\"1.0.0\",\"yanked\":false,\"padding\":\"{padding}\"}}\n"
    );

    assert_invalid_sparse_response(body.into_bytes(), &["sparse-index line 1", "line exceeds"])
        .await;
}
