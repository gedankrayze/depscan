use depscan_core::{DetectedSource, EcosystemParser, SourceKind};
use depscan_parsers::NodeParser;
use std::fs;

#[test]
fn pnpm_resolution_controls_public_registry_eligibility() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pnpm-lock.yaml");
    fs::write(
        &path,
        r#"lockfileVersion: '9.0'
packages:
  public@1.0.0:
    resolution: {integrity: sha512-fixture}
  public-tarball@1.0.0:
    resolution: {tarball: 'https://registry.npmjs.org/public-tarball/-/public-tarball-1.0.0.tgz'}
  private@1.0.0:
    resolution: {tarball: 'https://user:secret@private.test/private.tgz'}
  wrong-public@1.0.0:
    resolution: {tarball: 'https://registry.npmjs.org/other/-/other-1.0.0.tgz'}
  git-package@1.0.0:
    resolution: {type: git, repo: 'https://git.test/repo', commit: abcdef}
"#,
    )
    .unwrap();
    let packages = NodeParser
        .parse(&DetectedSource {
            path,
            kind: SourceKind::PnpmLock,
        })
        .unwrap();
    assert_eq!(packages.len(), 5);
    for package in packages {
        let public = matches!(package.name.as_str(), "public" | "public-tarball");
        assert_eq!(package.enrichable, public, "{package:?}");
        assert!(!package.version.contains("secret"));
    }
}

#[test]
fn pnpm_rejects_malformed_resolution_without_exposing_credentials() {
    for resolution in ["false", "{tarball: false}", "{type: []}"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pnpm-lock.yaml");
        fs::write(
            &path,
            format!(
                "lockfileVersion: '9.0'\npackages:\n  pkg@1.0.0:\n    resolution: {resolution}\n"
            ),
        )
        .unwrap();
        assert!(
            NodeParser
                .parse(&DetectedSource {
                    path,
                    kind: SourceKind::PnpmLock
                })
                .is_err()
        );
    }
}
