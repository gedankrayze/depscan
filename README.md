# depscan

`depscan` is a Rust CLI that scans resolved project dependencies for **known vulnerabilities** through [OSV.dev](https://osv.dev) and for **available updates** through the corresponding native package registries. It is designed for local development and CI: reports are deterministic, diagnostics are sent to standard error, and the scanner returns documented exit codes.

> This repository implements the version 0.1 development direction. The command is intentionally report-only; it never rewrites lockfiles or upgrades dependencies.
> Normative corrections to that draft are recorded in the [development specification errata](docs/specification-errata.md).

## Supported sources

| Ecosystem | Normal sources | Manifest-only fallback |
|---|---|---|
| npm / Bun | `bun.lock`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`; authorized `bun.lockb` extraction | root/workspace `package.json`, including the fallback for unavailable binary-lock extraction |
| Python | `uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements.txt` | `pyproject.toml` |
| .NET | `packages.lock.json`, project XML, `packages.config`; authorized SDK transitive enumeration | project XML ranges |
| Rust | `Cargo.lock` | `Cargo.toml` |

Resolved lockfile versions are preferred. Manifest-only records are marked as range-derived, because they are not an installed dependency resolution.

`package-lock.json` versions 2 and 3 are parsed fail-closed: malformed package records, install locations, field types, aliases, required dependency edges, and registry versions stop the scan instead of being omitted. npm dependency declarations are resolved to their concrete installed locations using Node ancestor lookup and npm's dependency-group precedence, so hoisting and workspaces cannot transfer source provenance or canonical identity between unrelated records. Workspace links use a bounded npm-minimatch-compatible subset for brace, class, wildcard, and negation rules; unsafe unsupported mixed extglob forms fail closed pending [DS-063](docs/issues/DS-063.md). An installed-package link target remains scannable, while a local descriptor is skipped only after its target and workspace identity are validated. Explicit Git, file, URL, alternate-registry, configured-registry, and origin-omitted records remain visible with public npm/OSV enrichment disabled; source-only coordinates are redacted before reporting. If the same normalized coordinate also has a proven canonical-public occurrence, that occurrence keeps the coordinate eligible for enrichment. Legacy version 1 locks remain best-effort because their recursive schema does not provide the same complete package-location contract.

For manifest-only records, the registry provider preserves the exact source constraint and evaluates a separate normalized form using the ecosystem's native rules: npm ranges, Cargo version requirements, PEP 440 specifiers, or NuGet intervals and floating versions. `latest_stable` is always the registry's unconstrained stable release; `latest_matching` is the newest non-yanked release accepted by the manifest. Table reports show both when a range is resolved. Invalid or unsupported constraints are per-package registry warnings and never fall back to the unconstrained release.

A legacy `bun.lockb` is never parsed as binary data. When external tools are disabled, or an explicitly authorized Bun executable cannot be found or started, depscan reads the colocated root `package.json` and every safely contained manifest declared by its workspace patterns. It marks every dependency as range-derived, retains the declaring manifest and exact constraint, and warns that the scan is operating in degraded manifest-only mode. A missing, malformed, escaping, or otherwise unusable manifest fails with exit `10`; it cannot become an empty successful scan. Once an explicitly authorized Bun process starts, non-zero status, timeout, oversized or invalid output, and malformed extracted lock data remain hard parse failures rather than being hidden by the manifest fallback.

Vulnerability checks for a manifest range use that same `latest_matching` release as a temporary OSV coordinate. The report continues to identify the original manifest constraint and marks it as range-derived; only the provider query uses the concrete release. Offline scans require acceptable cached registry metadata for this step. An unresolved package remains a visible soft error when another concrete dependency has a trustworthy OSV result. If none of the scan's intended registry-backed manifest dependencies can be resolved to a concrete coordinate, the scan fails with provider exit `30` instead of treating an empty OSV plan as clean. Non-registry dependencies remain report-only and are never sent to a public registry or OSV as registry coordinates.

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
| NuGet | Lowercase, case-insensitive | Online: registration-derived canonical ID; offline: normalized match | Lowercase flat-container and registration ID |
| crates.io | Source spelling | Source spelling | Validated crate name |

NuGet's split is intentional: package references and registry lookup coordinates are case-insensitive, while OSV currently requires the registry's canonical package ID for some advisory records. The spelling read from the project file is retained unchanged in human and machine reports, but it is not assumed to be canonical. Online registry enrichment selects the registration leaf for the exact version being queried (or the range's `latest_matching` release), validates its `catalogEntry.id`, and uses that ID only in the ephemeral OSV request. Missing or malformed canonical metadata leaves the online vulnerability status visibly unresolved rather than sending source spelling as a fallback. Offline dump matching remains ecosystem-normalized and does not require registration metadata.

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

The tag-driven release workflow publishes this platform matrix:

| Target | Architecture | Artifact contract |
|---|---|---|
| `x86_64-unknown-linux-musl` | Linux x86-64 | Statically linked ELF; no glibc or distribution packages required |
| `aarch64-unknown-linux-musl` | Linux ARM64 | Statically linked ELF; no glibc or distribution packages required |
| `x86_64-apple-darwin` | Intel macOS | Native tar.xz archive |
| `aarch64-apple-darwin` | Apple-silicon macOS | Native tar.xz archive |
| `x86_64-pc-windows-msvc` | Windows x86-64 | Native ZIP archive and MSI installer |

Windows ARM64 is not published because the pinned cargo-dist 0.32.0 target matrix does not support it. It must not be added until the release tool and a Windows ARM64 CI run have both been verified.

The static-Linux workflow builds each Linux target natively on its matching GitHub runner, rejects any ELF dynamic-library requirement with `file` and `readelf`, executes `--help`, and runs an offline Cargo fixture in a read-only `scratch` container with networking disabled. The uploaded CI artifact includes the binary and its SHA-256 checksum.

Cargo-dist 0.32.0 generates the release plan and MSI definition. The checked-in workflow pins every external action by commit, runs formatting, all-target tests, strict Clippy, `cargo package --workspace --locked`, and a release-binary startup check before artifact jobs, then publishes shell and Homebrew installers, the Windows MSI, archives, source, and SHA-256 files. Host-phase GitHub artifact attestations bind every published file to the tag workflow. Workflow permissions default to read-only; only the host job receives `contents: write`, `id-token: write`, and `attestations: write`. `scripts/verify-release-workflow.sh` guards those pins, permissions, attestation scope, and quality dependency.

After a release, verify a downloaded artifact before running it:

```bash
gh release download v1.1.0 --repo gedankrayze/depscan --pattern 'depscan-cli-aarch64-apple-darwin.tar.xz*'
grep -v '^[[:space:]]*$' depscan-cli-aarch64-apple-darwin.tar.xz.sha256 | shasum -a 256 -c -
gh attestation verify depscan-cli-aarch64-apple-darwin.tar.xz --repo gedankrayze/depscan
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

The repository also includes a thin composite GitHub Action. It downloads the archive for the runner's supported OS/architecture from an exact release tag, validates the paired SHA-256 record before extraction, and passes only typed inputs to the CLI—there is no free-form shell argument input:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4.3.1
    with:
      persist-credentials: false
  - id: depscan
    uses: gedankrayze/depscan@v1.1.0
    with:
      version: v1.1.0
      path: .
      format: sarif
      output: depscan.sarif
      fail-on: high
```

The `report` action output contains the configured report path. The action supports the five release runners listed above and fails closed on every other OS/architecture. It never enables `--allow-tools`; projects requiring Bun or dotnet execution must invoke the CLI explicitly after making that trust decision. Release-asset downloads are intentionally unauthenticated for the zero-auth public distribution model, so the current private repository must be made public before this path can work; retaining a private repository would require a separately reviewed authenticated GitHub API download path. The first public release still needs an end-to-end action run that downloads the real archive and verifies its checksum; the local CI smoke deliberately supplies the just-built binary so action input and invocation behavior are testable before publication.

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

The authorized Bun fallback runs `bun bun.lockb` in the lockfile directory and parses its Yarn Classic output. The authorized .NET fallback runs `dotnet list ./<project> package --include-transitive --format json --output-version 1 --verbosity quiet` for each unlocked project; the explicit `./` prevents a project filename from being interpreted as an option, and an offline scan adds `--no-restore` so the SDK cannot restore over the network. Both commands use an absolute executable resolved only from absolute `PATH` entries, a canonical working directory, a temporary home, an allowlisted environment, null standard input, a 10-second timeout, and bounded stdout/stderr capture. No shell is involved. A missing or pre-start Bun executable condition uses the documented manifest-only fallback when its manifests are valid. A missing dotnet executable remains a configuration failure; once either process starts, non-zero status, timeout, oversized/non-UTF-8 output, capture failure, or malformed machine data is a hard parse failure (exit `10`), never a clean or partial resolved dependency result.

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

Synchronization opens the sentinel-owned cache root and its `offline` child as no-follow directory capabilities and retains those handles from lock acquisition through publication. Per-ecosystem locks, abandoned-temp cleanup, archive and marker temporaries, rollback staging, final atomic renames, and handled-error cleanup all operate relative to the held `offline` handle. Root or child namespace replacement is still revalidated and reported, but confinement does not depend on winning that race: a late symlink swap cannot redirect a read, write, removal, lock, rollback, or publication into the replacement namespace. Unix permits a held directory to be renamed and therefore exercises the confined-detached-directory path; Windows commonly denies the rename while the directory handle is held, which is an equally safe outcome.

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

The checked-in [verification matrix](docs/test-matrix.md) maps the development specification and every audit issue to parser fixtures, version tables, provider mocks, process-level E2E tests, platform CI, live probes, or artifact gates. Pull requests dogfood an offline scan of this workspace on Linux, macOS, and Windows; public API checks remain an explicitly enabled scheduled/manual job.

## Known v0.1 limitations

The implementation never executes package-manager binaries automatically. Legacy `bun.lockb` resolved-version extraction and .NET transitive enumeration require the explicit `allow-tools` trust decision described above; without it, `bun.lockb` scans visibly degrade to manifest constraints. Registry deprecation/unlisted checks are also intentionally not inferred where the lightweight public endpoint does not expose them.

## License

Licensed under either the Apache License, Version 2.0 or the MIT license, at your option. Both complete license texts are distributed together in [LICENSE](LICENSE).
