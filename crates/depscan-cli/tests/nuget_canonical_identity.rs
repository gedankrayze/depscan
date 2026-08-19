use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, process::Command};

const ADVISORY_ID: &str = "GHSA-5crp-9r3c-p9vr";
const MODIFIED: &str = "2026-08-19T00:00:00Z";

struct NugetProject {
    _directory: tempfile::TempDir,
    root: PathBuf,
    cache: PathBuf,
}

impl NugetProject {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("create isolated NuGet project");
        let root = directory.path().join("project");
        let cache = directory.path().join("cache");
        fs::create_dir_all(root.join("exact")).expect("create exact project");
        fs::create_dir_all(root.join("range")).expect("create range project");
        fs::create_dir_all(&cache).expect("create cache");
        fs::write(
            cache.join(".depscan-cache.json"),
            r#"{"schema_version":1,"owner":"depscan"}"#,
        )
        .expect("write cache ownership marker");
        fs::write(
            root.join("exact/packages.lock.json"),
            r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "newtonsoft.json": {
        "type": "Direct",
        "resolved": "12.0.1",
        "contentHash": "fixture"
      }
    }
  }
}"#,
        )
        .expect("write exact NuGet lock");
        fs::write(
            root.join("range/Range.csproj"),
            r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="newtonsoft.json" Version="[12.0.1]" />
  </ItemGroup>
</Project>"#,
        )
        .expect("write ranged NuGet project");

        let project = Self {
            _directory: directory,
            root,
            cache,
        };
        project.seed_cache(
            "registry",
            "nuget:newtonsoft.json",
            json!({"versions": ["12.0.1", "13.0.3"]}),
        );
        project.seed_cache(
            "registry",
            "nuget-registration:newtonsoft.json",
            json!({
                "count": 1,
                "items": [{
                    "@id": "https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json#page/12.0.1/12.0.1",
                    "count": 1,
                    "items": [
                        {"catalogEntry": {"id": "Newtonsoft.Json", "version": "12.0.1"}}
                    ],
                    "lower": "12.0.1",
                    "upper": "12.0.1"
                }]
            }),
        );
        project.seed_cache(
            "osv/query",
            "NuGet:Newtonsoft.Json:12.0.1",
            json!([{"id": ADVISORY_ID, "modified": MODIFIED}]),
        );
        project.seed_cache("osv/vuln", &format!("{ADVISORY_ID}@{MODIFIED}"), advisory());
        project
    }

    fn seed_cache(&self, namespace: &str, key: &str, value: Value) {
        let directory = self.cache.join(namespace);
        fs::create_dir_all(&directory).expect("create cache namespace");
        let entry = json!({
            "stored_at": Utc::now().to_rfc3339(),
            "etag": null,
            "value": value,
        });
        fs::write(
            directory.join(format!("{}.json", sha256_hex(key.as_bytes()))),
            serde_json::to_vec(&entry).expect("encode cache entry"),
        )
        .expect("write cache entry");
    }

    fn run(&self) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_depscan"))
            .env("DEPSCAN_CACHE_DIR", &self.cache)
            .env("NO_COLOR", "1")
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .env("HTTP_PROXY", "http://127.0.0.1:9")
            .env("HTTPS_PROXY", "http://127.0.0.1:9")
            .env("ALL_PROXY", "http://127.0.0.1:9")
            .env("NO_PROXY", "")
            .args(["scan", "--format", "json", "--ecosystem", "nuget"])
            .arg(&self.root)
            .output()
            .expect("run depscan")
    }
}

fn advisory() -> Value {
    json!({
        "id": ADVISORY_ID,
        "modified": MODIFIED,
        "summary": "Improper handling of metadata properties in Newtonsoft.Json",
        "severity": [{
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }],
        "affected": [{
            "package": {"ecosystem": "NuGet", "name": "Newtonsoft.Json"},
            "versions": ["12.0.1"]
        }]
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[test]
fn lowercase_exact_and_range_sources_use_canonical_only_osv_cache_without_report_mutation() {
    let project = NugetProject::new();

    let output = project.run();

    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(output.stderr.is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).expect("decode JSON report");
    let results = report["results"].as_array().expect("report results");
    assert_eq!(results.len(), 2);
    for result in results {
        assert_eq!(result["package"]["name"], "newtonsoft.json");
        assert_eq!(result["package"]["display_name"], "newtonsoft.json");
        assert_eq!(result["vulns"][0]["id"], ADVISORY_ID);
        assert_eq!(result["errors"].as_array().map(Vec::len), Some(0));
    }
    assert!(results.iter().any(|result| {
        result["package"]["version"] == "12.0.1"
            && result["package"]["resolved_from_range"] == false
    }));
    assert!(results.iter().any(|result| {
        result["package"]["version"] == "[12.0.1]"
            && result["package"]["resolved_from_range"] == true
            && result["latest"]["latest_matching"] == "12.0.1"
    }));
}
