use super::*;

pub(crate) fn dump_archive_bytes(payload_bytes: usize) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut archive = zip::ZipWriter::new(cursor);
    archive
        .start_file(
            "TEST-1.json",
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
    archive
        .write_all(br#"{"id":"TEST-1","modified":"2026-08-19T00:00:00Z","affected":[],"details":""#)
        .unwrap();
    archive.write_all(&vec![b'x'; payload_bytes]).unwrap();
    archive.write_all(br#""}"#).unwrap();
    archive.finish().unwrap().into_inner()
}

pub(crate) fn archive_with_entry(name: &str, contents: &[u8]) -> Vec<u8> {
    archive_with_entries(&[(name, contents)], zip::CompressionMethod::Stored)
}

pub(crate) fn archive_with_entries(
    entries: &[(&str, &[u8])],
    compression: zip::CompressionMethod,
) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut archive = zip::ZipWriter::new(cursor);
    for (name, contents) in entries {
        archive
            .start_file(
                *name,
                SimpleFileOptions::default().compression_method(compression),
            )
            .unwrap();
        archive.write_all(contents).unwrap();
    }
    archive.finish().unwrap().into_inner()
}

pub(crate) fn cache_for_sync(root: &Path) -> Cache {
    Cache::from_root(root.to_path_buf(), CachePolicy::default()).unwrap()
}

pub(crate) fn sync_paths(cache: &Cache) -> (PathBuf, PathBuf) {
    let archive = cache.root().join("offline/npm.zip");
    let marker = archive.with_extension("synced-at");
    (archive, marker)
}

pub(crate) fn seed_sync_files(cache: &Cache, archive_bytes: &[u8], marker: &str) {
    let (archive, synced_at) = sync_paths(cache);
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::write(archive, archive_bytes).unwrap();
    fs::write(synced_at, marker).unwrap();
}

pub(crate) fn assert_no_sync_temps(cache: &Cache) {
    let offline = cache.root().join("offline");
    let temporary = fs::read_dir(offline)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    assert!(
        temporary.is_empty(),
        "temporary files remain: {temporary:?}"
    );
}
