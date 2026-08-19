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

For manifest-only records, the registry provider preserves the exact source constraint and evaluates a separate normalized form using the ecosystem's native rules: npm ranges, Cargo version requirements, PEP 440 specifiers, or NuGet intervals and floating versions. `latest_stable` is always the registry's unconstrained stable release; `latest_matching` is the newest non-yanked release accepted by the manifest. Table reports show both when a range is resolved. Invalid or unsupported constraints are per-package registry warnings and never fall back to the unconstrained release.

Python lock provenance is format-aware. `uv.lock` schema version 1 uses project/workspace dependency edges to classify direct, transitive, optional, and development-group reachability. Poetry lock versions 1.0, 1.1, 2.0, and 2.1 use category/group metadata when the lock records it and, when present, the sibling `pyproject.toml` for directness; Poetry 2.0 packages without category/group metadata retain unknown development scope. Only packages resolved from the canonical PyPI index are enriched; Git, URL, path, directory, editable, file, and alternate-registry coordinates remain visible without being sent to PyPI or OSV as registry packages.

For Poetry manifest-only scans, the reserved `python` interpreter constraint and extra names are metadata, not packages. PEP 508 `project.dependencies`, `project.optional-dependencies`, PEP 735 dependency groups, legacy development dependencies, and Poetry named groups are parsed explicitly, including group inclusions. Poetry strings and expanded tables support extras, optional and environment metadata, and git, URL, path, or named repository sources. Caret, tilde, wildcard, exact, and PEP 440 constraints retain their original spelling while using an equivalent PEP 440 range for release matching; conditional declarations are conservatively reported because a scan has no target installation environment. Repository priority is applied before enrichment, so ambiguous custom primary or supplemental origins and explicitly named non-PyPI sources remain visible but are never queried as public PyPI or OSV coordinates. Environment-dependent multiple-constraint arrays, per-dependency `allow-prereleases` policy that the current package model cannot represent, and malformed declarations fail with a source-qualified error instead of producing guessed packages.

`requirements.txt` uses the current PEP 508 grammar for names, extras, version specifiers, markers, and named direct URLs. It accepts pip's separated and attached `-r`/`--requirement` forms, applies `-c`/`--constraint` bounds without treating constraints as installed packages, joins continuations before stripping comments, and validates per-requirement hashes and configuration settings. Environment markers are conservatively assumed true and logged as warnings. Unpinned/ranged entries remain range-derived; URLs, editables, local artifacts, alternate indexes, and `--find-links` entries remain visible but are never queried as public PyPI coordinates. Options that alter pip's candidate policy, such as `--pre` or binary-selection flags, disable range freshness when their semantics cannot be represented safely.

Requirements includes resolve relative to the file containing the directive. The root file and every include must be regular, non-symlink files within the canonical scan root. Expansion is limited to 32 levels, 256 file reads, and 8 MiB of cumulative input. Unsupported options fail with a configuration error instead of being silently ignored or interpreted as package names.

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

Published crates.io releases use the package name `depscan-cli` and install the `depscan` binary:

```bash
cargo install depscan-cli --locked
```

Before the first registry release, or to install from a source checkout instead, use the repository's pinned development and release toolchain:

```bash
cargo install --path crates/depscan-cli --locked
```

Alternatively, build and execute the workspace binary directly:

```bash
cargo run -p depscan-cli -- --help
```

## Release artifacts

Linux release binaries target musl on both supported architectures:

| Target | Architecture | Runtime contract |
|---|---|---|
| `x86_64-unknown-linux-musl` | x86-64 | Statically linked ELF; no glibc or distribution packages required |
| `aarch64-unknown-linux-musl` | ARM64 | Statically linked ELF; no glibc or distribution packages required |

The static-Linux workflow builds each target natively on its matching GitHub runner, rejects any ELF dynamic-library requirement with `file` and `readelf`, executes `--help`, and runs an offline Cargo fixture in a read-only `scratch` container with networking disabled. The uploaded CI artifact includes the binary and its SHA-256 checksum. macOS and Windows remain native platform binaries; the complete publication workflow and platform matrix are tracked in DS-045.

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

`--direct-only` removes packages confirmed to be transitive, and `--no-dev` removes packages confirmed to be development-only. When a lockfile cannot prove one of those classifications—for example, a Poetry lock without its sibling manifest—the package is retained. JSON reports distinguish that conservative result with `direct_known` and `dev_known`; the corresponding `direct` or `dev` value must only be interpreted when its `*_known` field is true.

The supported report formats are `table`, `json`, `sarif`, and `summary`. When no format is specified, terminal output uses a table and redirected output uses a one-line summary. A file extension of `.json`, `.sarif`, `.txt`, or `.log` selects a matching format unless `--format` overrides it.

JSON reports contain one RFC 3339 UTC `generated_at` timestamp captured by the scan orchestration. By default it is the real scan time. For byte-reproducible CI evidence, set the standard `SOURCE_DATE_EPOCH` environment variable to an integer number of seconds since the Unix epoch:

```bash
SOURCE_DATE_EPOCH=1700000000 depscan scan . --format json --output depscan.json
```

In that mode, equivalent scan results have canonical package, vulnerability, alias, fix, reference, suppression, and error ordering. An invalid or out-of-range epoch is a configuration error and exits with code `10`.

The current JSON report schema is version `4`. Version `1` represented `results[].suppressed` as advisory-ID strings; version `2` replaced those strings with audit objects containing the complete vulnerability, whether the suppression was active, and every matching rule's ID/alias, CLI/config source, reason, expiry, and active/expired state. Version `3` adds `results[].package.direct_known` and `dev_known` so unknown classifications are no longer serialized as apparent facts. Version `4` adds `results[].package.manifest_constraint`, retaining both its source spelling (`raw`) and registry-standard evaluator form (`normalized`). Consumers must branch on `schema_version`. Only matching suppression and manifest-constraint fields are emitted—other configuration values are never copied into a report.

| Exit code | Meaning |
|---:|---|
| 0 | Completed without a finding at the configured failure thresholds. |
| 1 | A vulnerability met `--fail-on`. |
| 2 | An update met `--fail-on-outdated`, and no vulnerability exit was required. |
| 10 | Command usage or configuration is invalid. |
| 20 | No supported dependency source was detected. |
| 30 | A provider or scan operation failed. |

An installed version reported as yanked or deprecated is an independent freshness risk: it is shown even when version ordering classifies it as current, contributes once to the outdated total, and triggers exit code `2` for any active `--fail-on-outdated` threshold (`patch`, `minor`, or `major`). Use `never` to report without failing. The `yanked` field always describes the installed version, not `latest_stable`; PyPI releases are considered yanked only when every published file for that release is yanked.

## Configuration and suppressions

`depscan.toml` is read from the scan root unless `--config` selects another readable, non-symlink regular file. Configuration is opened without following the final symlink, validated from that open file handle, and read from the same handle. The containing capability and file identities are checked again after the read, so a detected concurrent pathname replacement fails with exit `10` instead of substituting different configuration. The schema is strict: unknown keys, wrong TOML types, invalid enum values, invalid durations, and simultaneous non-zero `quiet`/`verbose` settings are configuration errors.

```toml
ecosystem = ["cargo", "npm"]
no-dev = false
direct-only = false
format = "json"
output = "reports/depscan.json"
fail-on = "high"
fail-on-outdated = "never"
offline = false
no-cache = false
max-cache-age = "24h"
include-withdrawn = false
allow-tools = false
quiet = 0
verbose = 0

[[ignore]]
id = "GHSA-xxxx-xxxx-xxxx"
reason = "Documented exploitability assessment"
expires = 2026-12-31
```

Scalar precedence is CLI value, then config value, then the documented CLI default. Format is merged independently: CLI `--format`, then configured `format`, then inference from the effective output path or TTY. Enable-only switches such as `--offline`, `--no-cache`, and `--include-withdrawn` set their effective value to true when present; when absent, the configured boolean is used. There are no negative CLI forms. Any CLI `--ecosystem` entries replace the configured `ecosystem` array; an empty configured array means auto-detect all ecosystems. CLI and configured ignores are combined with their provenance retained. Any CLI quiet/verbose occurrence replaces the entire configured logging group.

The remaining defaults are: all detected ecosystems, development and transitive dependencies included, output to stdout, format inferred from output/TTY, vulnerability threshold `high`, outdated threshold `never`, online/cache reads enabled, no maximum cache age, withdrawn advisories excluded, external tools disabled, and warning-level diagnostics. A configured relative `output` resolves from the scan root. For auto-discovered configuration, the capability used to read `depscan.toml` is handed directly to report publication; the scan root is not reopened as a new trust decision. Depscan opens every output-parent component without following symlinks and retains the validated capabilities throughout the scan. It snapshots any existing final file, writes and syncs a same-directory temporary file, preserves the existing Unix mode and portable read-only state, revalidates the root, parent, and target identities, then atomically replaces the final entry. Detected swaps fail with exit `10`; temporary cleanup and publication remain relative to the held directory and never follow a substituted final symlink. The final identity check and atomic rename are not a portable compare-and-swap, so a change in that last interval can replace only the held parent entry, not redirect a write to an external symlink target. CLI output paths and output paths from an explicitly selected trusted config retain their ambient-path semantics and may target other locations.

`allow-tools` is a supply-chain boundary. An auto-discovered project config cannot self-authorize it: `allow-tools = true` requires either the CLI `--allow-tools` flag or an explicitly selected trusted `--config` file. Once authorized, supported fallbacks may execute package-manager binaries in the scanned checkout. Inspect the checkout and configuration before enabling this for untrusted input.

Expired suppressions are not applied and are emitted as warnings and report metadata. Active suppressions remain visible in table, JSON, SARIF, and summary output but do not affect failure thresholds. Suppression reasons are intentionally included in reports for auditability, so they should not contain secrets. Repeated `--ignore <ID>` arguments are also supported for ephemeral CI suppression.

Withdrawn OSV advisories are excluded by default, so they do not render, contribute to totals, or affect exit thresholds. `--include-withdrawn` retains them in the scan model; table, JSON, SARIF, and summary output then label and count them explicitly, and their severity participates in `--fail-on` like any other retained advisory.

## Offline scans

Populate offline advisory archives once:

```bash
depscan sync
```

Then run an air-gapped vulnerability scan:

```bash
depscan scan --offline .
```

Offline scans use the downloaded per-ecosystem OSV archives and never construct an HTTP provider. Each archive must have the valid `*.synced-at` marker written by `depscan sync`; a missing, malformed, or future marker fails safely. Without `--max-cache-age`, archives older than seven days remain usable but emit a warning. With `--max-cache-age <duration>`, an older archive is rejected as stale and must be synchronized again.

Every archive is revalidated while it is scanned, using the same ZIP, OSV document-shape, per-entry, entry-count, compressed-size, and aggregate decompression limits applied before a synchronized dump is published. A malformed, truncated, invalid UTF-8, schema-invalid, or oversized entry is reported with its archive and entry name as a provider hard failure (exit `30`), never as an empty vulnerability result. A structurally valid archive with no advisory entries is accepted as a valid empty ecosystem dump.

Version freshness is evaluated from cached registry metadata when a usable entry exists. The normal six-hour registry TTL applies by default; an explicit `--max-cache-age` selects the age that an offline scan is willing to tolerate. Missing, stale, future-dated, corrupt, or `--no-cache` entries produce an `Unknown` freshness result and an explicit per-package reason in the report. No registry request is attempted in any of those cases.

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

The implementation does not execute package-manager binaries automatically. `bun.lockb` is recognized but requires a textual `bun.lock` for parsing at present. Registry deprecation/unlisted checks are also intentionally not inferred where the lightweight public endpoint does not expose them.

## License

Licensed under either the Apache License, Version 2.0 or the MIT license, at your option. Both complete license texts are distributed together in [LICENSE](LICENSE).
