# depscan

`depscan` is a Rust CLI that scans resolved project dependencies for **known vulnerabilities** through [OSV.dev](https://osv.dev) and for **available updates** through the corresponding native package registries. It is designed for local development and CI: reports are deterministic, diagnostics are sent to standard error, and the scanner returns documented exit codes.

> This repository implements the version 0.1 development direction. The command is intentionally report-only; it never rewrites lockfiles or upgrades dependencies.

## Supported sources

| Ecosystem | Normal sources | Manifest-only fallback |
|---|---|---|
| npm / Bun | `bun.lock`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | `package.json` |
| Python | `uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements.txt` | `pyproject.toml` |
| .NET | `packages.lock.json`, project XML, `packages.config` | project XML ranges |
| Rust | `Cargo.lock` | `Cargo.toml` |

Resolved lockfile versions are preferred. Manifest-only records are marked as range-derived, because they are not an installed dependency resolution.

## Package identity and provider names

Package identity and provider request spelling are related but not always identical:

| Ecosystem | Internal identity | OSV query name | Registry request name |
|---|---|---|---|
| npm | Source spelling | Source spelling | Source spelling |
| PyPI | PEP 503 normalized | PEP 503 normalized | PEP 503 normalized |
| NuGet | Lowercase, case-insensitive | Source-preserved casing | Lowercase flat-container ID |
| crates.io | Source spelling | Source spelling | Validated crate name |

NuGet's split is intentional: its package identity and flat-container endpoint are case-insensitive, while OSV currently requires the advisory's canonical/source casing for some records. Human output retains the spelling read from the project file.

## Installation

The repository pins its development and release toolchain in `rust-toolchain.toml`:

```bash
cargo install --path crates/depscan-cli
```

Alternatively, build and execute the workspace binary directly:

```bash
cargo run -p depscan-cli -- --help
```

## Usage

```text
depscan [SCAN OPTIONS] [PATH]
depscan scan [OPTIONS] [PATH]
depscan sync [--ecosystem <ecosystem>...]
depscan cache <clear|stats|path>
depscan completions <shell>
```

A typical CI invocation uses SARIF output and fails only for high-or-higher vulnerabilities:

```bash
depscan scan . --format sarif --output depscan.sarif --fail-on high
```

The supported report formats are `table`, `json`, `sarif`, and `summary`. When no format is specified, terminal output uses a table and redirected output uses a one-line summary. A file extension of `.json`, `.sarif`, `.txt`, or `.log` selects a matching format unless `--format` overrides it.

| Exit code | Meaning |
|---:|---|
| 0 | Completed without a finding at the configured failure thresholds. |
| 1 | A vulnerability met `--fail-on`. |
| 2 | An update met `--fail-on-outdated`, and no vulnerability exit was required. |
| 20 | No supported dependency source was detected. |
| 30 | A provider or scan operation failed. |

## Configuration and suppressions

`depscan.toml` is read from the scan root unless `--config` is supplied. Command-line values take precedence.

```toml
fail-on = "high"
fail-on-outdated = "never"

[[ignore]]
id = "GHSA-xxxx-xxxx-xxxx"
reason = "Documented exploitability assessment"
expires = 2026-12-31
```

Expired suppressions are not applied and are emitted as warnings. Repeated `--ignore <ID>` arguments are also supported for ephemeral CI suppression.

## Offline scans

Populate offline advisory archives once:

```bash
depscan sync
```

Then run an air-gapped vulnerability scan:

```bash
depscan scan --offline .
```

Offline scans use the downloaded per-ecosystem OSV archives. Registry freshness checks are intentionally skipped in offline mode, since they require current registry metadata.

## Development

The pinned toolchain is the latest verified stable patch (Rust 1.97.1 as of 2026-08-19). The supported MSRV follows an N−2 stable policy and is currently Rust 1.95.0. On each stable Rust release, refresh the pin, move the MSRV to the new N−2 release, update CI, and verify both toolchains before merging.

The workspace is divided at its architectural boundaries:

| Crate | Responsibility |
|---|---|
| `depscan-core` | Normalized model, traits, version comparison, OSV ranges. |
| `depscan-parsers` | Filesystem-only ecosystem source parsing. |
| `depscan-providers` | OSV, registry, cache, retry, and offline archive providers. |
| `depscan-report` | Table, JSON, SARIF 2.1.0, and summary renderers. |
| `depscan-cli` | CLI, config, orchestration, filters, and exit policy. |

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace --all-targets
```

## Known v0.1 limitations

The implementation does not execute package-manager binaries automatically. `bun.lockb` is recognized but requires a textual `bun.lock` for parsing at present. The latest-version provider does not yet resolve semver/PEP 440 ranges to a range-constrained latest release; manifest-only results are identified as range-derived. Registry deprecation/unlisted checks are also intentionally not inferred where the lightweight public endpoint does not expose them.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.
