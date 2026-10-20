pub(super) enum BodyError {
    Transport(reqwest::Error),
    TooLarge,
}

// Reqwest exposes decompressed chunks, so the cap also applies to gzip expansion.
pub(super) async fn read_body(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, BodyError> {
    let content_length = response.content_length();
    if content_length.is_some_and(|length| length > max_bytes as u64) {
        return Err(BodyError::TooLarge);
    }
    let capacity = content_length
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or_default()
        .min(max_bytes);
    let mut bytes = Vec::with_capacity(capacity);
    while let Some(chunk) = response.chunk().await.map_err(BodyError::Transport)? {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > max_bytes)
        {
            return Err(BodyError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
