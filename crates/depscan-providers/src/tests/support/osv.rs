use super::*;

#[derive(Debug, Deserialize)]
pub(crate) struct OsvRangeFixture {
    pub(crate) name: String,
    pub(crate) ecosystem: String,
    pub(crate) package: String,
    pub(crate) installed: String,
    pub(crate) affected: bool,
    pub(crate) fixed_in: Vec<String>,
    pub(crate) document: Value,
}

pub(crate) fn osv_range_fixtures() -> Vec<OsvRangeFixture> {
    serde_json::from_str(include_str!("../../../../../fixtures/osv-range-cases.json")).unwrap()
}

pub(crate) fn fixture_ecosystem(value: &str) -> Ecosystem {
    [
        Ecosystem::Npm,
        Ecosystem::PyPI,
        Ecosystem::NuGet,
        Ecosystem::CratesIo,
    ]
    .into_iter()
    .find(|ecosystem| ecosystem.osv_name().eq_ignore_ascii_case(value))
    .unwrap_or_else(|| panic!("unknown fixture ecosystem {value:?}"))
}

pub(crate) fn fixture_package(fixture: &OsvRangeFixture) -> Package {
    let ecosystem = fixture_ecosystem(&fixture.ecosystem);
    Package::new(
        ecosystem,
        &fixture.package,
        &fixture.installed,
        PathBuf::from("fixture.lock"),
    )
}

pub(crate) fn write_fixture_archives(root: &Path, fixtures: &[OsvRangeFixture]) {
    let offline_dir = root.join("offline");
    fs::create_dir_all(&offline_dir).unwrap();
    for ecosystem in [
        Ecosystem::Npm,
        Ecosystem::PyPI,
        Ecosystem::NuGet,
        Ecosystem::CratesIo,
    ] {
        let file = File::create(
            offline_dir.join(format!("{}.zip", ecosystem.osv_name().replace('.', "_"))),
        )
        .unwrap();
        let mut archive = zip::ZipWriter::new(file);
        for fixture in fixtures
            .iter()
            .filter(|fixture| fixture_ecosystem(&fixture.ecosystem) == ecosystem)
        {
            let id = fixture.document.get("id").and_then(Value::as_str).unwrap();
            let mut document = fixture.document.clone();
            document
                .as_object_mut()
                .unwrap()
                .insert("modified".to_owned(), json!(TEST_OSV_MODIFIED));
            archive
                .start_file(format!("{id}.json"), SimpleFileOptions::default())
                .unwrap();
            archive
                .write_all(serde_json::to_string(&document).unwrap().as_bytes())
                .unwrap();
        }
        archive.finish().unwrap();
        fs::write(
            offline_dir.join(format!(
                "{}.synced-at",
                ecosystem.osv_name().replace('.', "_")
            )),
            Utc::now().to_rfc3339(),
        )
        .unwrap();
    }
}
