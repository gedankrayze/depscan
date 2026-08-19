use depscan_core::{DetectedSource, ParseError, SourceKind};
use depscan_parsers::ParserSet;
use std::path::{Path, PathBuf};

#[derive(Clone)]
struct LockFormat {
    directory: &'static str,
    file: &'static str,
    kind: SourceKind,
}

const FORMATS: [LockFormat; 8] = [
    LockFormat {
        directory: "npm",
        file: "package-lock.json",
        kind: SourceKind::PackageLock,
    },
    LockFormat {
        directory: "bun",
        file: "bun.lock",
        kind: SourceKind::BunLock,
    },
    LockFormat {
        directory: "pnpm",
        file: "pnpm-lock.yaml",
        kind: SourceKind::PnpmLock,
    },
    LockFormat {
        directory: "uv",
        file: "uv.lock",
        kind: SourceKind::UvLock,
    },
    LockFormat {
        directory: "poetry",
        file: "poetry.lock",
        kind: SourceKind::PoetryLock,
    },
    LockFormat {
        directory: "pipfile",
        file: "Pipfile.lock",
        kind: SourceKind::PipfileLock,
    },
    LockFormat {
        directory: "nuget",
        file: "packages.lock.json",
        kind: SourceKind::PackagesLock,
    },
    LockFormat {
        directory: "cargo",
        file: "Cargo.lock",
        kind: SourceKind::CargoLock,
    },
];

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn schema_fixture(format: &LockFormat, case: &str) -> PathBuf {
    fixtures()
        .join("schema-validation")
        .join(format.directory)
        .join(case)
        .join(format.file)
}

fn parse(path: PathBuf, kind: SourceKind) -> Result<Vec<depscan_core::Package>, ParseError> {
    ParserSet::default().parse(&DetectedSource { path, kind })
}

#[test]
fn accepts_valid_empty_dependency_collections_for_every_lock_format() {
    for format in FORMATS {
        let path = schema_fixture(&format, "empty-valid");
        let packages = parse(path.clone(), format.kind).unwrap_or_else(|error| {
            panic!("{} rejected valid empty lock: {error}", path.display())
        });
        assert!(
            packages.is_empty(),
            "{} did not remain an empty dependency set",
            path.display()
        );
    }
}

#[test]
fn parses_realistic_nonempty_fixtures_for_every_lock_format() {
    for (path, kind) in [
        (
            fixtures().join("npm-v3-nested/package-lock.json"),
            SourceKind::PackageLock,
        ),
        (
            fixtures().join("bun/current-v2-mixed/bun.lock"),
            SourceKind::BunLock,
        ),
        (
            fixtures().join("pnpm/current-v9/pnpm-lock.yaml"),
            SourceKind::PnpmLock,
        ),
        (
            fixtures().join("python/uv-current/uv.lock"),
            SourceKind::UvLock,
        ),
        (
            fixtures().join("python/poetry-current/poetry.lock"),
            SourceKind::PoetryLock,
        ),
        (
            fixtures().join("python/pipenv-current/Pipfile.lock"),
            SourceKind::PipfileLock,
        ),
        (
            fixtures().join("dotnet/multi-project/packages.lock.json"),
            SourceKind::PackagesLock,
        ),
        (
            fixtures().join("cargo/workspace-manifest/Cargo.lock"),
            SourceKind::CargoLock,
        ),
    ] {
        let packages = parse(path.clone(), kind)
            .unwrap_or_else(|error| panic!("{} failed realistic parse: {error}", path.display()));
        assert!(
            !packages.is_empty(),
            "{} unexpectedly parsed as an empty dependency set",
            path.display()
        );
        assert!(
            packages.iter().all(|package| package.source_file == path),
            "{} lost lockfile provenance",
            path.display()
        );
    }
}

#[test]
fn parses_npm11_mixed_negative_extglob_workspace_fixture() {
    let path = fixtures().join("npm-v3-mixed-negative-extglob/package-lock.json");
    let packages = parse(path.clone(), SourceKind::PackageLock).unwrap_or_else(|error| {
        panic!("{} failed npm 11 workspace parse: {error}", path.display())
    });

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "left-pad");
    assert_eq!(packages[0].version, "1.3.0");
    assert!(packages[0].direct);
    assert!(packages[0].direct_known);
    assert_eq!(packages[0].source_file, path);
}

#[test]
fn accepts_supported_numeric_pnpm_v6_schema() {
    let format = FORMATS
        .iter()
        .find(|format| format.directory == "pnpm")
        .expect("pnpm format");
    let path = schema_fixture(format, "supported-v6");

    let packages = parse(path.clone(), format.kind.clone()).unwrap();

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "left-pad");
    assert_eq!(packages[0].version, "1.3.0");
    assert_eq!(packages[0].source_file, path);
}

#[test]
fn rejects_wrong_missing_malformed_and_future_schemas_as_invalid() {
    let expected = [
        (
            "npm",
            [
                ("wrong-format", "expected npm package-lock.json"),
                ("missing-section", "without a packages object"),
                ("malformed", "without an integer lockfileVersion"),
                ("future-schema", "unsupported npm package-lock.json"),
            ],
        ),
        (
            "bun",
            [
                ("wrong-format", "missing an integer lockfileVersion"),
                ("missing-section", "without packages"),
                ("malformed", "missing a workspaces object"),
                ("future-schema", "unsupported Bun lockfileVersion"),
            ],
        ),
        (
            "pnpm",
            [
                ("wrong-format", "unsupported pnpm lockfileVersion"),
                ("missing-section", "without a packages mapping"),
                ("malformed", "must be a mapping"),
                ("future-schema", "unsupported pnpm lockfileVersion"),
            ],
        ),
        (
            "uv",
            [
                ("wrong-format", "uv lockfile is missing an integer version"),
                ("missing-section", "uv lockfile is missing an array package"),
                ("malformed", "uv package entry 0 must be a table"),
                ("future-schema", "unsupported uv lockfile version"),
            ],
        ),
        (
            "poetry",
            [
                ("wrong-format", "missing a metadata table"),
                ("missing-section", "missing an array package"),
                ("malformed", "Poetry package entry 0 must be a table"),
                ("future-schema", "unsupported Poetry lock-version"),
            ],
        ),
        (
            "pipfile",
            [
                ("wrong-format", "expected Pipfile.lock metadata"),
                ("missing-section", "without a develop object"),
                ("malformed", "package \"requests\" must be an object"),
                ("future-schema", "unsupported Pipfile.lock pipfile-spec"),
            ],
        ),
        (
            "nuget",
            [
                ("wrong-format", "expected NuGet packages.lock.json"),
                ("missing-section", "without a dependencies object"),
                ("malformed", "framework \"net8.0\" must be an object"),
                ("future-schema", "unsupported NuGet lockfile version"),
            ],
        ),
        (
            "cargo",
            [
                ("wrong-format", "without a package array"),
                ("missing-section", "without a package array"),
                ("malformed", "package entry 0 must be a table"),
                ("future-schema", "unsupported Cargo.lock version"),
            ],
        ),
    ];

    for (directory, cases) in expected {
        let format = FORMATS
            .iter()
            .find(|format| format.directory == directory)
            .cloned()
            .expect("known lock format");
        for (case, expected_message) in cases {
            let path = schema_fixture(&format, case);
            let error = match parse(path.clone(), format.kind.clone()) {
                Ok(_) => panic!("{} parsed as a clean lock", path.display()),
                Err(error) => error,
            };
            match error {
                ParseError::Invalid {
                    path: error_path,
                    message,
                } => {
                    assert_eq!(error_path, path, "{directory}/{case} lost source path");
                    assert!(
                        message.contains(expected_message),
                        "{directory}/{case} returned unexpected context: {message}"
                    );
                }
                ParseError::Io { .. } => {
                    panic!("{directory}/{case} returned I/O instead of invalid-format error")
                }
            }
        }
    }
}

#[test]
fn rejects_malformed_npm_v3_package_entry_after_valid_records() {
    let format = FORMATS
        .iter()
        .find(|format| format.directory == "npm")
        .expect("npm format");
    let path = schema_fixture(format, "malformed-entry");

    let error = parse(path.clone(), format.kind.clone()).unwrap_err();
    let ParseError::Invalid {
        path: error_path,
        message,
    } = error
    else {
        panic!("malformed npm entry returned an I/O error");
    };
    assert_eq!(error_path, path);
    assert!(message.contains("node_modules/missing-version"));
    assert!(message.contains("non-empty string version"));
}
