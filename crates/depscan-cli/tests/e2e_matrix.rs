use chrono::Utc;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

#[derive(Clone, Copy)]
struct ExpectedPackage {
    name: &'static str,
    display_name: &'static str,
    version: &'static str,
    direct: bool,
    dev: bool,
}

#[derive(Clone, Copy)]
struct EcosystemCase {
    fixture: &'static str,
    cli_name: &'static str,
    report_name: &'static str,
    display_name: &'static str,
    dump_name: &'static str,
    source_name: &'static str,
    packages: &'static [ExpectedPackage],
}

const NPM_PACKAGES: &[ExpectedPackage] = &[
    ExpectedPackage {
        name: "chalk",
        display_name: "chalk",
        version: "5.4.1",
        direct: true,
        dev: true,
    },
    ExpectedPackage {
        name: "lodash",
        display_name: "lodash",
        version: "4.17.21",
        direct: true,
        dev: false,
    },
    ExpectedPackage {
        name: "minimist",
        display_name: "minimist",
        version: "1.2.8",
        direct: false,
        dev: false,
    },
];

const PYPI_PACKAGES: &[ExpectedPackage] = &[
    ExpectedPackage {
        name: "pytest",
        display_name: "pytest",
        version: "8.3.5",
        direct: true,
        dev: true,
    },
    ExpectedPackage {
        name: "requests",
        display_name: "requests",
        version: "2.31.0",
        direct: true,
        dev: false,
    },
    ExpectedPackage {
        name: "urllib3",
        display_name: "urllib3",
        version: "2.2.1",
        direct: false,
        dev: false,
    },
];

const NUGET_PACKAGES: &[ExpectedPackage] = &[
    ExpectedPackage {
        name: "newtonsoft.json",
        display_name: "Newtonsoft.Json",
        version: "13.0.3",
        direct: true,
        dev: false,
    },
    ExpectedPackage {
        name: "system.memory",
        display_name: "System.Memory",
        version: "4.5.5",
        direct: false,
        dev: false,
    },
];

const CARGO_PACKAGES: &[ExpectedPackage] = &[
    ExpectedPackage {
        name: "depscan-e2e-cargo",
        display_name: "depscan-e2e-cargo",
        version: "1.0.0",
        direct: false,
        dev: false,
    },
    ExpectedPackage {
        name: "regex",
        display_name: "regex",
        version: "1.11.2",
        direct: true,
        dev: true,
    },
    ExpectedPackage {
        name: "regex-syntax",
        display_name: "regex-syntax",
        version: "0.8.5",
        direct: false,
        dev: false,
    },
    ExpectedPackage {
        name: "serde",
        display_name: "serde",
        version: "1.0.228",
        direct: true,
        dev: false,
    },
];

const ECOSYSTEMS: &[EcosystemCase] = &[
    EcosystemCase {
        fixture: "npm",
        cli_name: "npm",
        report_name: "npm",
        display_name: "npm",
        dump_name: "npm",
        source_name: "package-lock.json",
        packages: NPM_PACKAGES,
    },
    EcosystemCase {
        fixture: "python",
        cli_name: "pypi",
        report_name: "pypi",
        display_name: "PyPI",
        dump_name: "PyPI",
        source_name: "uv.lock",
        packages: PYPI_PACKAGES,
    },
    EcosystemCase {
        fixture: "nuget",
        cli_name: "nuget",
        report_name: "nuget",
        display_name: "NuGet",
        dump_name: "NuGet",
        source_name: "packages.lock.json",
        packages: NUGET_PACKAGES,
    },
    EcosystemCase {
        fixture: "cargo",
        cli_name: "cargo",
        report_name: "cratesio",
        display_name: "crates.io",
        dump_name: "crates_io",
        source_name: "Cargo.lock",
        packages: CARGO_PACKAGES,
    },
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("CLI crate is inside the workspace")
        .to_path_buf()
}

fn fixture(case: EcosystemCase) -> PathBuf {
    workspace_root().join("fixtures/e2e").join(case.fixture)
}

fn fixture_snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, current: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = fs::read_dir(current)
            .expect("read E2E fixture directory")
            .map(|entry| entry.expect("read E2E fixture entry"))
            .collect::<Vec<_>>();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if entry
                .file_type()
                .expect("inspect E2E fixture entry")
                .is_dir()
            {
                collect(root, &path, files);
            } else {
                files.insert(
                    path.strip_prefix(root)
                        .expect("fixture entry is below root")
                        .to_path_buf(),
                    fs::read(path).expect("read E2E fixture file"),
                );
            }
        }
    }

    let mut files = BTreeMap::new();
    collect(root, root, &mut files);
    files
}

fn initialize_cache(path: &Path) {
    fs::create_dir_all(path).expect("create isolated cache");
    fs::write(
        path.join(".depscan-cache.json"),
        r#"{"schema_version":1,"owner":"depscan"}"#,
    )
    .expect("write cache ownership marker");
}

fn seed_empty_dump(cache: &Path, dump_name: &str) {
    let offline = cache.join("offline");
    fs::create_dir_all(&offline).expect("create offline cache directory");
    zip::ZipWriter::new(
        fs::File::create(offline.join(format!("{dump_name}.zip")))
            .expect("create empty OSV fixture archive"),
    )
    .finish()
    .expect("finish empty OSV fixture archive");
    fs::write(
        offline.join(format!("{dump_name}.synced-at")),
        Utc::now().to_rfc3339(),
    )
    .expect("write offline archive timestamp");
}

fn command(cache: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_depscan"));
    command
        .env("DEPSCAN_CACHE_DIR", cache)
        .env("NO_COLOR", "1")
        .env("SOURCE_DATE_EPOCH", "1700000000")
        // An offline test must fail rather than silently reaching a public service.
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env("NO_PROXY", "");
    command
}

fn run_offline(cache: &Path, case: EcosystemCase, format: &str) -> Output {
    command(cache)
        .args([
            "scan",
            "--offline",
            "--format",
            format,
            "--ecosystem",
            case.cli_name,
        ])
        .arg(fixture(case))
        .output()
        .expect("run depscan E2E fixture")
}

fn assert_clean(output: &Output, context: &str) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{context}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{context} emitted unexpected diagnostics: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn parse_json_report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "JSON report was invalid: {error}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn result_map(report: &Value) -> BTreeMap<&str, &Value> {
    report["results"]
        .as_array()
        .expect("JSON report results")
        .iter()
        .map(|result| {
            (
                result["package"]["name"]
                    .as_str()
                    .expect("reported package name"),
                result,
            )
        })
        .collect()
}

fn assert_json_contract(case: EcosystemCase, report: &Value) {
    assert_eq!(report["schema_version"], 4);
    assert_eq!(report["generated_at"], "2023-11-14T22:13:20Z");
    let results = result_map(report);
    assert_eq!(results.len(), case.packages.len());

    for expected in case.packages {
        let result = results
            .get(expected.name)
            .unwrap_or_else(|| panic!("{} report omitted {}", case.fixture, expected.name));
        let package = &result["package"];
        assert_eq!(package["ecosystem"], case.report_name, "{}", expected.name);
        assert_eq!(package["display_name"], expected.display_name);
        assert_eq!(package["version"], expected.version);
        assert_eq!(package["direct"], expected.direct);
        assert_eq!(package["direct_known"], true);
        assert_eq!(package["dev"], expected.dev);
        assert_eq!(package["dev_known"], true);
        assert!(
            package["source_file"]
                .as_str()
                .is_some_and(|source| source.ends_with(case.source_name)),
            "{} had unexpected source file: {}",
            expected.name,
            package["source_file"]
        );
        assert_eq!(result["vulns"], serde_json::json!([]));

        if package["enrichable"] == true {
            assert_eq!(result["latest"]["latest_stable"], "");
            assert!(result["latest"]["latest_matching"].is_null());
            assert_eq!(result["latest"]["staleness"], "unknown");
            assert_eq!(result["latest"]["yanked"], false);
            let errors = result["errors"].as_array().expect("provider errors array");
            assert_eq!(errors.len(), 1, "{} provider errors", expected.name);
            assert_eq!(errors[0]["provider"], "registry");
            assert!(
                errors[0]["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("no cached entry exists"))
            );
        } else {
            assert_eq!(result["errors"], serde_json::json!([]));
        }
    }
}

#[test]
fn offline_ecosystem_output_matrix() {
    for case in ECOSYSTEMS {
        let directory = tempfile::tempdir().expect("create E2E temp directory");
        let cache = directory.path().join("cache");
        initialize_cache(&cache);
        seed_empty_dump(&cache, case.dump_name);
        let fixture_root = fixture(*case);
        let before = fixture_snapshot(&fixture_root);

        let json = run_offline(&cache, *case, "json");
        assert_clean(&json, &format!("{} JSON E2E", case.fixture));
        assert_json_contract(*case, &parse_json_report(&json));

        let table = run_offline(&cache, *case, "table");
        assert_clean(&table, &format!("{} table E2E", case.fixture));
        let table = String::from_utf8(table.stdout).expect("UTF-8 table report");
        assert!(table.starts_with("depscan: "));
        assert!(table.contains(&format!("\n{} (", case.display_name)));

        let summary = run_offline(&cache, *case, "summary");
        assert_clean(&summary, &format!("{} summary E2E", case.fixture));
        let summary = String::from_utf8(summary.stdout).expect("UTF-8 summary report");
        assert!(summary.starts_with(&format!(
            "depscan: {} packages | 0 vulns",
            case.packages.len()
        )));

        let sarif = run_offline(&cache, *case, "sarif");
        assert_clean(&sarif, &format!("{} SARIF E2E", case.fixture));
        let sarif = parse_json_report(&sarif);
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "depscan");
        assert!(
            sarif["runs"][0]["results"]
                .as_array()
                .is_some_and(|results| !results.is_empty()),
            "offline registry gaps must remain visible in SARIF"
        );
        assert_eq!(
            fixture_snapshot(&fixture_root),
            before,
            "{} scans changed project files",
            case.fixture
        );
    }
}

#[test]
fn offline_workspace_self_scan() {
    let directory = tempfile::tempdir().expect("create self-scan temp directory");
    let cache = directory.path().join("cache");
    initialize_cache(&cache);
    seed_empty_dump(&cache, "crates_io");

    let output = command(&cache)
        .args([
            "scan",
            "--offline",
            "--format",
            "json",
            "--ecosystem",
            "cargo",
        ])
        .arg(workspace_root())
        .output()
        .expect("run offline workspace self-scan");
    assert_clean(&output, "workspace self-scan");
    let report = parse_json_report(&output);
    let results = result_map(&report);
    for package in ["depscan-cli", "depscan-core", "depscan-parsers", "serde"] {
        assert!(results.contains_key(package), "self-scan omitted {package}");
    }
    assert!(
        results
            .values()
            .all(|result| result["package"]["ecosystem"] == "cratesio")
    );
}

#[test]
#[ignore = "opt in with DEPSCAN_RUN_LIVE=1; calls public OSV and registry APIs"]
fn live_provider_matrix_for_every_ecosystem() {
    assert_eq!(
        std::env::var("DEPSCAN_RUN_LIVE").as_deref(),
        Ok("1"),
        "set DEPSCAN_RUN_LIVE=1 to acknowledge public API access"
    );

    for case in ECOSYSTEMS {
        let directory = tempfile::tempdir().expect("create live test directory");
        let cache = directory.path().join("cache");
        initialize_cache(&cache);
        let output = Command::new(env!("CARGO_BIN_EXE_depscan"))
            .env("DEPSCAN_CACHE_DIR", &cache)
            .env("NO_COLOR", "1")
            .args([
                "scan",
                "--no-cache",
                "--format",
                "json",
                "--ecosystem",
                case.cli_name,
            ])
            .arg(fixture(*case))
            .output()
            .expect("run live depscan fixture");
        assert!(
            matches!(output.status.code(), Some(0 | 1)),
            "{} live scan failed\nstdout:\n{}\nstderr:\n{}",
            case.fixture,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report = parse_json_report(&output);
        let results = result_map(&report);
        for expected in case.packages {
            let result = results
                .get(expected.name)
                .unwrap_or_else(|| panic!("live report omitted {}", expected.name));
            if result["package"]["enrichable"] == true {
                assert!(
                    result["latest"].is_object(),
                    "{} live registry lookup did not complete: {}",
                    expected.name,
                    result["errors"]
                );
                assert_eq!(result["errors"], serde_json::json!([]));
            }
        }
        let vulnerability_count = results
            .values()
            .map(|result| result["vulns"].as_array().map_or(0, Vec::len))
            .sum::<usize>();
        eprintln!(
            "live {} evidence: {} packages, {} vulnerability records, registry enrichment complete",
            case.display_name,
            results.len(),
            vulnerability_count
        );
    }
}
