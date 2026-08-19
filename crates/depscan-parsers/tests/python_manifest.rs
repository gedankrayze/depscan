use depscan_core::{
    DetectedSource, Ecosystem, EcosystemParser, Package, SourceKind, latest_matching_version,
};
use depscan_parsers::PythonParser;
use std::{collections::BTreeSet, fs, path::PathBuf};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/python/poetry-manifest/pyproject.toml")
}

fn parse(path: PathBuf) -> Result<Vec<Package>, String> {
    PythonParser
        .parse(&DetectedSource {
            path,
            kind: SourceKind::PyProject,
        })
        .map_err(|error| error.to_string())
}

fn package<'a>(packages: &'a [Package], name: &str) -> &'a Package {
    packages
        .iter()
        .find(|package| package.name == name)
        .unwrap_or_else(|| panic!("missing package {name:?}"))
}

#[test]
fn parses_poetry_constraints_groups_metadata_and_sources_without_pseudo_packages() {
    let packages = parse(fixture()).unwrap();
    let names = packages
        .iter()
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from([
            "anything",
            "attrs",
            "coverage",
            "django",
            "exact",
            "git-dep",
            "hybrid",
            "legacy-dev",
            "optional-project",
            "parenthesized",
            "path-dep",
            "private-dep",
            "prod-group",
            "project-extra",
            "project-git",
            "pypi-explicit",
            "pytest",
            "requests",
            "ruff",
            "shared-tool",
            "sphinx",
            "table-dep",
            "url-dep",
        ])
    );
    assert!(
        !names.contains("python"),
        "Python is an interpreter constraint"
    );
    assert!(
        !names.contains("feature"),
        "project extras are not packages"
    );
    assert!(
        !names.contains("socks"),
        "dependency extras are not packages"
    );

    assert!(packages.iter().all(|package| package.direct));
    assert!(packages.iter().all(|package| package.direct_known));
    assert!(packages.iter().all(|package| package.dev_known));
    assert!(
        packages
            .iter()
            .filter(|package| package.manifest_constraint.is_some())
            .all(|package| package.resolved_from_range)
    );
    for name in ["coverage", "legacy-dev", "pytest", "ruff", "sphinx"] {
        assert!(package(&packages, name).dev, "development scope for {name}");
    }
    for name in [
        "optional-project",
        "parenthesized",
        "prod-group",
        "project-extra",
        "requests",
        "shared-tool",
        "table-dep",
    ] {
        assert!(!package(&packages, name).dev, "production scope for {name}");
    }

    for name in [
        "git-dep",
        "hybrid",
        "path-dep",
        "private-dep",
        "project-git",
        "url-dep",
    ] {
        assert!(
            !package(&packages, name).enrichable,
            "{name} must not be sent to public PyPI or OSV"
        );
    }
    for name in ["git-dep", "path-dep", "project-git", "url-dep"] {
        let package = package(&packages, name);
        assert!(!package.resolved_from_range);
        assert!(package.manifest_constraint.is_none());
    }
    assert!(package(&packages, "pypi-explicit").enrichable);
    assert_eq!(
        package(&packages, "git-dep").version,
        "git+https://github.com/example/git-dep.git@0123456789abcdef#subdirectory=python"
    );
    assert_eq!(
        package(&packages, "project-git").version,
        "git+https://github.com/example/project-git.git@main"
    );
    assert_eq!(
        package(&packages, "path-dep").version,
        "path:../path-dep#develop=true"
    );
    assert_eq!(
        package(&packages, "url-dep").version,
        "https://packages.example.invalid/url-dep-1.0.0.tar.gz"
    );

    let hybrid = package(&packages, "hybrid");
    let hybrid_constraint = hybrid.manifest_constraint.as_ref().unwrap();
    assert_eq!(hybrid_constraint.raw(), ">=2.0,<3.0");
    assert_eq!(hybrid_constraint.normalized(), ">=2.0, <3.0");

    let project_extra = package(&packages, "project-extra");
    assert_eq!(project_extra.display_name, "Project_Extra");
    let project_extra_constraint = project_extra.manifest_constraint.as_ref().unwrap();
    assert_eq!(project_extra_constraint.raw(), ">=1.0,<2.0");
    assert_eq!(project_extra_constraint.normalized(), ">=1.0, <2.0");

    let parenthesized = package(&packages, "parenthesized")
        .manifest_constraint
        .as_ref()
        .unwrap();
    assert_eq!(parenthesized.raw(), "(>=3,<4)");
    assert_eq!(parenthesized.normalized(), ">=3, <4");

    let public_registry_queries = packages
        .iter()
        .filter(|package| package.enrichable)
        .map(|package| package.name.as_str())
        .collect::<BTreeSet<_>>();
    assert!(!public_registry_queries.contains("python"));
    assert!(!public_registry_queries.contains("git-dep"));
    assert!(!public_registry_queries.contains("private-dep"));
    assert!(!public_registry_queries.contains("project-git"));
    assert!(
        !packages
            .iter()
            .any(|package| package.enrichable && !package.resolved_from_range),
        "manifest-only packages must not be submitted as resolved OSV coordinates"
    );
}

#[test]
fn applies_global_poetry_repository_policy_before_public_enrichment() {
    let cases = [
        ("primary", "primary", false),
        ("supplemental", "supplemental", false),
        ("explicit", "explicit", true),
    ];
    for (case, priority, unqualified_enrichable) in cases {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(format!("{case}-pyproject.toml"));
        fs::write(
            &path,
            format!(
                r#"
[project]
dependencies = ["project-dep>=1"]

[tool.poetry.dependencies]
legacy-dep = "^1"
pypi-dep = {{ version = "~1", source = "pypi" }}
private-dep = {{ version = "1", source = "private" }}

[[tool.poetry.source]]
name = "private"
url = "https://packages.example.invalid/simple/"
priority = "{priority}"
"#
            ),
        )
        .unwrap();
        let packages = parse(path).unwrap();
        assert_eq!(
            package(&packages, "project-dep").enrichable,
            unqualified_enrichable,
            "project dependency under {priority} source"
        );
        assert_eq!(
            package(&packages, "legacy-dep").enrichable,
            unqualified_enrichable,
            "Poetry dependency under {priority} source"
        );
        assert!(package(&packages, "pypi-dep").enrichable);
        assert!(!package(&packages, "private-dep").enrichable);
    }
}

#[test]
fn normalized_poetry_constraints_preserve_raw_text_and_match_expected_releases() {
    let packages = parse(fixture()).unwrap();
    let cases = [
        (
            "requests",
            "^2.31.0",
            ["2.31.0", "2.32.4", "3.0.0"],
            "2.32.4",
        ),
        ("attrs", "~23.1", ["23.1.0", "23.1.9", "23.2.0"], "23.1.9"),
        ("django", "5.*", ["5.0", "5.2.1", "6.0"], "5.2.1"),
        ("exact", "1.2.3", ["1.2.2", "1.2.3", "1.2.4"], "1.2.3"),
        ("table-dep", "^1.2", ["1.2", "1.9", "2.0"], "1.9"),
    ];
    for (name, raw, releases, expected) in cases {
        let constraint = package(&packages, name)
            .manifest_constraint
            .as_ref()
            .unwrap();
        assert_eq!(constraint.raw(), raw);
        assert_ne!(
            constraint.normalized(),
            raw,
            "Poetry-only syntax must be normalized for {name}"
        );
        assert_eq!(
            latest_matching_version(Ecosystem::PyPI, constraint.normalized(), releases).unwrap(),
            Some(expected.to_owned()),
            "matching release for {name} using {:?}",
            constraint.normalized()
        );
    }
}

#[test]
fn rejects_unsupported_or_malformed_poetry_declarations_with_source_context() {
    let cases = [
        (
            "union",
            "[tool.poetry.dependencies]\nfoo = \"^1 || ^2\"\n",
            "tool.poetry.dependencies.foo",
        ),
        (
            "array",
            "[tool.poetry.dependencies]\nfoo = [{ version = \"<2\", python = \"<3.10\" }]\n",
            "unsupported multiple Poetry constraints",
        ),
        (
            "extras",
            "[tool.poetry.dependencies]\nfoo = { version = \"1\", extras = [7] }\n",
            "tool.poetry.dependencies.foo.extras",
        ),
        (
            "source",
            "[tool.poetry.dependencies]\nfoo = { git = \"https://example.invalid/foo.git\", path = \"../foo\" }\n",
            "conflicting dependency sources",
        ),
        (
            "reserved-python",
            "[tool.poetry.dependencies]\npython = { version = \"^3.12\" }\n",
            "interpreter constraint must be a string",
        ),
        (
            "invalid-interpreter",
            "[tool.poetry.dependencies]\npython = \"^\"\n",
            "interpreter constraint has unsupported Poetry constraint",
        ),
        (
            "invalid-requires-python",
            "[project]\nrequires-python = \"^3.12\"\n",
            "project.requires-python is not valid PEP 440",
        ),
        (
            "allow-prereleases",
            "[tool.poetry.dependencies]\nfoo = { version = \"^1\", allow-prereleases = true }\n",
            "candidate-selection policy cannot be represented safely",
        ),
        (
            "disallow-prereleases",
            "[tool.poetry.dependencies]\nfoo = { version = \"^1\", allow-prereleases = false }\n",
            "candidate-selection policy cannot be represented safely",
        ),
        (
            "invalid-project-requirement",
            "[project]\ndependencies = [\"foo => 1\"]\n",
            "project.dependencies entry 0 is not a valid PEP 508 requirement",
        ),
        (
            "invalid-marker",
            "[tool.poetry.dependencies]\nfoo = { version = \"1\", markers = \"python_version => '3.10'\" }\n",
            "markers is not a valid PEP 508 marker",
        ),
        (
            "invalid-python-condition",
            "[tool.poetry.dependencies]\nfoo = { version = \"1\", python = \"^\" }\n",
            "python condition has unsupported Poetry constraint",
        ),
        (
            "unconfigured-source",
            "[tool.poetry.dependencies]\nfoo = { version = \"1\", source = \"private\" }\n",
            "references unconfigured Poetry source",
        ),
        (
            "bad-source-priority",
            "[[tool.poetry.source]]\nname = \"private\"\nurl = \"https://example.invalid/simple/\"\npriority = \"default\"\n",
            "priority has unsupported value",
        ),
        (
            "dependency-group-cycle",
            "[dependency-groups]\na = [{ include-group = \"b\" }]\nb = [{ include-group = \"a\" }]\n",
            "dependency-groups include cycle",
        ),
    ];
    for (case, manifest, expected) in cases {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(format!("{case}-pyproject.toml"));
        fs::write(&path, manifest).unwrap();
        let error = parse(path).unwrap_err();
        assert!(error.contains(&format!("{case}-pyproject.toml")), "{error}");
        assert!(error.contains(expected), "{case}: {error}");
    }
}
