# depscan issue ledger

This directory is the authoritative ledger for defects and specification gaps found during the 2026-08-19 code, runtime, dependency, and release audit.

## Workflow

1. Select one open `DS-*` issue.
2. Implement only the issue's bounded scope, including its tests and documentation.
3. Run every check named under **Verification**, plus the workspace quality gates where Rust changed:
   - `cargo fmt --all -- --check`
   - `cargo test --workspace --all-targets`
   - `cargo clippy --all-targets -- -D warnings`
4. Change **Status** to `Closed` only after recording concrete verification evidence in the issue.
5. Commit that completed issue separately; include its ID in the commit subject.

Allowed status values are `Open`, `In progress`, `Blocked`, and `Closed`. Do not delete closed issues or reuse their IDs.

## Index

| ID | Priority | Status | Finding |
|---|---|---|---|
| [DS-001](DS-001.md) | P1 | Open | Repository hygiene and branch governance |
| [DS-002](DS-002.md) | P0 | Closed | Replace approximate CVSS scoring |
| [DS-003](DS-003.md) | P0 | Closed | Preserve canonical NuGet names for OSV |
| [DS-004](DS-004.md) | P0 | Closed | Use standards-compliant PEP 440 ordering |
| [DS-005](DS-005.md) | P0 | Closed | Correct shared OSV range evaluation and fix extraction |
| [DS-006](DS-006.md) | P0 | Closed | Remove vulnerable `quick-xml` release |
| [DS-007](DS-007.md) | P1 | Closed | Parse Bun text-lock locators correctly |
| [DS-008](DS-008.md) | P1 | Closed | Retain nested npm v2/v3 packages |
| [DS-009](DS-009.md) | P1 | Closed | Support Yarn Berry lockfiles |
| [DS-010](DS-010.md) | P1 | Closed | Scan all .NET projects and central package versions |
| [DS-011](DS-011.md) | P1 | Closed | Make Cargo manifest parsing workspace- and rename-aware |
| [DS-012](DS-012.md) | P1 | Closed | Preserve uv/Poetry source, directness, and group provenance |
| [DS-013](DS-013.md) | P1 | Closed | Fail closed on malformed OSV batch responses |
| [DS-014](DS-014.md) | P1 | Closed | Follow OSV per-query pagination |
| [DS-015](DS-015.md) | P1 | Closed | Revalidate OSV and registry caches |
| [DS-016](DS-016.md) | P1 | Closed | Make offline dump sync streaming and resilient |
| [DS-017](DS-017.md) | P1 | Closed | Contain recursive requirements includes to the scan root |
| [DS-018](DS-018.md) | P1 | Closed | Prevent sparse-index path panics on invalid crate names |
| [DS-019](DS-019.md) | P1 | Closed | Implement the specified exit-code taxonomy |
| [DS-020](DS-020.md) | P1 | Closed | Render included withdrawn advisories consistently |
| [DS-021](DS-021.md) | P1 | Closed | Preserve auditable suppression details |
| [DS-022](DS-022.md) | P1 | Closed | Support the full CLI surface in configuration |
| [DS-023](DS-023.md) | P1 | Open | Implement explicitly allowed Bun and dotnet tool fallbacks |
| [DS-024](DS-024.md) | P1 | Closed | Make workspace crates publishable |
| [DS-025](DS-025.md) | P1 | Closed | Modernize the Rust toolchain, edition, resolver, and MSRV policy |
| [DS-026](DS-026.md) | P1 | Closed | Upgrade direct dependencies to current stable releases |
| [DS-027](DS-027.md) | P1 | Closed | Replace unmaintained `serde_yaml` |
| [DS-028](DS-028.md) | P1 | Open | Build the required fixture, provider, version, and E2E test matrix |
| [DS-029](DS-029.md) | P1 | Closed | Resolve manifest ranges for `latest_matching` |
| [DS-030](DS-030.md) | P1 | Closed | Enforce offline dump age and use cached registry metadata |
| [DS-031](DS-031.md) | P1 | Closed | Implement exact retry and `Retry-After` semantics |
| [DS-032](DS-032.md) | P1 | Closed | Reject malformed offline advisory documents |
| [DS-033](DS-033.md) | P1 | Closed | Reject malformed crates.io sparse-index lines |
| [DS-034](DS-034.md) | P1 | Closed | Make cache clearing safe for arbitrary configured paths |
| [DS-035](DS-035.md) | P1 | Closed | Isolate partial OSV failures as per-package soft errors |
| [DS-036](DS-036.md) | P1 | Open | Parse Poetry constraints without inventing packages |
| [DS-037](DS-037.md) | P1 | Closed | Distinguish direct and transitive Pipfile.lock packages |
| [DS-038](DS-038.md) | P1 | Closed | Parse requirements options, includes, and extras correctly |
| [DS-039](DS-039.md) | P1 | Closed | Implement NuGet prerelease precedence correctly |
| [DS-040](DS-040.md) | P1 | Open | Reject malformed or unsupported lockfile schemas instead of returning empty |
| [DS-041](DS-041.md) | P1 | Closed | Error when an explicitly requested config file is missing |
| [DS-042](DS-042.md) | P1 | Closed | Make JSON output reproducible when requested |
| [DS-043](DS-043.md) | P1 | Closed | Show yanked installed versions even when otherwise current |
| [DS-044](DS-044.md) | P1 | Closed | Strengthen CLI help and typed value parsing |
| [DS-045](DS-045.md) | P2 | Open | Generate release automation and complete the target matrix |
| [DS-046](DS-046.md) | P2 | In progress | Deliver and verify genuinely static Linux artifacts |
| [DS-047](DS-047.md) | P1 | Open | Make offline sync publication capability-safe during directory swaps |
| [DS-048](DS-048.md) | P1 | In progress | Make configuration and report file access capability-safe |
