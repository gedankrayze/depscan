use super::*;

#[test]
fn dump_rejects_a_decoded_name_that_does_not_match_the_document() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid-name.zip");
    let mut bytes = archive_with_entry(
        "TEST-1.json",
        br#"{"id":"TEST-1","modified":"2026-10-20T00:00:00Z","affected":[]}"#,
    );
    let central = bytes
        .windows(4)
        .rposition(|part| part == b"PK\x01\x02")
        .unwrap();
    for (offset, flags_offset, name_offset) in [(0, 6, 30), (central, 8, 46)] {
        let flags = u16::from_le_bytes([
            bytes[offset + flags_offset],
            bytes[offset + flags_offset + 1],
        ]) | 0x800;
        bytes[offset + flags_offset..offset + flags_offset + 2]
            .copy_from_slice(&flags.to_le_bytes());
        bytes[offset + name_offset] = 0xff;
    }
    fs::write(&path, bytes).unwrap();
    let config = OsvSyncConfig::new(OsvSyncOptions::default()).unwrap();
    let error = validate_osv_dump(&path, Ecosystem::Npm, &config).unwrap_err();
    assert!(matches!(error, ProviderError::InvalidResponse(_)));
    assert!(
        error
            .to_string()
            .contains("filename does not match advisory id"),
        "{error}"
    );
}
