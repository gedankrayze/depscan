# depscan issue ledger

This directory is the authoritative ledger for defects and specification gaps found during the 2026-08-19 code, runtime, dependency, and release audit. Later reviews append new issues to the same ledger; DS-077 onward come from the 2026-08-21 code, async-runtime, API-surface, and CI-posture review.

## Workflow

1. Select or create one `Open` or `In progress` `DS-*` issue in the working tree.
2. Implement only the issue's bounded scope, including its tests and documentation.
3. Run every check named under **Verification**, plus the workspace quality gates where Rust changed:
   - `cargo fmt --all -- --check`
   - `cargo test --workspace --all-targets`
   - `cargo clippy --all-targets -- -D warnings`
4. Change **Status** to `Closed` only after recording concrete verification evidence in the issue.
5. Commit that completed issue separately; include its ID in the commit subject. The issue record and its bounded fix may land atomically after verification, so a standalone issue-only commit is optional. Do not combine unrelated issue fixes.

Allowed status values are `Open`, `In progress`, `Blocked`, and `Closed`. Do not delete closed issues or reuse their IDs.

## Index

| ID | Priority | Status | Finding |
|---|---|---|---|
| [DS-001](DS-001.md) | P1 | Closed | Repository hygiene and branch governance |
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
| [DS-023](DS-023.md) | P1 | Closed | Implement explicitly allowed Bun and dotnet tool fallbacks |
| [DS-024](DS-024.md) | P1 | Closed | Make workspace crates publishable |
| [DS-025](DS-025.md) | P1 | Closed | Modernize the Rust toolchain, edition, resolver, and MSRV policy |
| [DS-026](DS-026.md) | P1 | Closed | Upgrade direct dependencies to current stable releases |
| [DS-027](DS-027.md) | P1 | Closed | Replace unmaintained `serde_yaml` |
| [DS-028](DS-028.md) | P1 | Closed | Build the required fixture, provider, version, and E2E test matrix |
| [DS-029](DS-029.md) | P1 | Closed | Resolve manifest ranges for `latest_matching` |
| [DS-030](DS-030.md) | P1 | Closed | Enforce offline dump age and use cached registry metadata |
| [DS-031](DS-031.md) | P1 | Closed | Implement exact retry and `Retry-After` semantics |
| [DS-032](DS-032.md) | P1 | Closed | Reject malformed offline advisory documents |
| [DS-033](DS-033.md) | P1 | Closed | Reject malformed crates.io sparse-index lines |
| [DS-034](DS-034.md) | P1 | Closed | Make cache clearing safe for arbitrary configured paths |
| [DS-035](DS-035.md) | P1 | Closed | Isolate partial OSV failures as per-package soft errors |
| [DS-036](DS-036.md) | P1 | Closed | Parse Poetry constraints without inventing packages |
| [DS-037](DS-037.md) | P1 | Closed | Distinguish direct and transitive Pipfile.lock packages |
| [DS-038](DS-038.md) | P1 | Closed | Parse requirements options, includes, and extras correctly |
| [DS-039](DS-039.md) | P1 | Closed | Implement NuGet prerelease precedence correctly |
| [DS-040](DS-040.md) | P1 | Closed | Reject malformed or unsupported lockfile schemas instead of returning empty |
| [DS-041](DS-041.md) | P1 | Closed | Error when an explicitly requested config file is missing |
| [DS-042](DS-042.md) | P1 | Closed | Make JSON output reproducible when requested |
| [DS-043](DS-043.md) | P1 | Closed | Show yanked installed versions even when otherwise current |
| [DS-044](DS-044.md) | P1 | Closed | Strengthen CLI help and typed value parsing |
| [DS-045](DS-045.md) | P2 | In progress | Generate release automation and complete the target matrix |
| [DS-046](DS-046.md) | P2 | In progress | Deliver and verify genuinely static Linux artifacts |
| [DS-047](DS-047.md) | P1 | Closed | Make offline sync publication capability-safe during directory swaps |
| [DS-048](DS-048.md) | P1 | Closed | Make configuration and report file access capability-safe |
| [DS-049](DS-049.md) | P2 | In progress | Deliver the M6 composite GitHub Action |
| [DS-050](DS-050.md) | P1 | Closed | Scan registry-resolved manifest dependencies for vulnerabilities |
| [DS-051](DS-051.md) | P1 | Closed | Reject malformed OSV advisory shapes without false-clean results |
| [DS-052](DS-052.md) | P1 | Closed | Degrade unavailable Bun binary-lock extraction to manifests |
| [DS-053](DS-053.md) | P2 | Closed | Clarify atomic issue-and-fix commits |
| [DS-054](DS-054.md) | P0 | Closed | Resolve canonical NuGet identities from registration metadata |
| [DS-055](DS-055.md) | P1 | Closed | Fail hard when every manifest vulnerability coordinate is unresolved |
| [DS-056](DS-056.md) | P1 | Closed | Reject future-dated reusable provider-cache entries |
| [DS-057](DS-057.md) | P1 | Closed | Reject malformed npm v2/v3 package records |
| [DS-058](DS-058.md) | P1 | Closed | Do not classify unproven Node dependencies as known transitive |
| [DS-059](DS-059.md) | P1 | Closed | Bind Cargo direct and development metadata to exact locked identities |
| [DS-060](DS-060.md) | P1 | Closed | Make requirements include reads capability-safe |
| [DS-061](DS-061.md) | P1 | Closed | Preserve the verified GitHub Action executable identity |
| [DS-062](DS-062.md) | P2 | Closed | Remove direct use of maintenance-seeking `urlencoding` |
| [DS-063](DS-063.md) | P1 | Closed | Support suffix-aware npm extglobs safely |
| [DS-064](DS-064.md) | P1 | Closed | Use full-width held-handle identity at filesystem trust boundaries |
| [DS-065](DS-065.md) | P1 | Closed | Keep platform-gated CLI tests warning-free on Windows |
| [DS-066](DS-066.md) | P1 | Closed | Make CLI contract tests exact across native path conventions |
| [DS-067](DS-067.md) | P1 | Closed | Compare Cargo fixture provenance under one canonical root |
| [DS-068](DS-068.md) | P2 | Closed | Run pinned GitHub Actions on supported Node 24 runtimes |
| [DS-069](DS-069.md) | P1 | Closed | Classify Windows capability-lock swap denials exactly |
| [DS-070](DS-070.md) | P1 | Closed | Make transport retry tests platform-semantic |
| [DS-071](DS-071.md) | P1 | Closed | Synchronize dump streaming at the client-write boundary |
| [DS-072](DS-072.md) | P2 | Closed | Modularize provider architecture and isolate test suites |
| [DS-073](DS-073.md) | P2 | Closed | Modularize parser architecture and isolate parser tests |
| [DS-074](DS-074.md) | P2 | Closed | Modularize CLI architecture and isolate CLI tests |
| [DS-075](DS-075.md) | P2 | Closed | Enforce repository-wide Rust module boundaries |
| [DS-076](DS-076.md) | P2 | Closed | Add an auditable Markdown report format |
| [DS-077](DS-077.md) | P1 | Closed | Move blocking cache locks and IO off the async runtime |
| [DS-078](DS-078.md) | P1 | Closed | Exit cleanly instead of panicking when stdout closes early |
| [DS-079](DS-079.md) | P2 | Closed | Move remaining blocking filesystem IO in async provider paths off the runtime |
| [DS-080](DS-080.md) | P2 | Closed | Bound multiplicative retry amplification across cache and HTTP layers |
| [DS-081](DS-081.md) | P2 | Closed | Add a wall-clock deadline to OSV batch pagination |
| [DS-082](DS-082.md) | P2 | Closed | Remove the redundant enrichment concurrency limiter |
| [DS-083](DS-083.md) | P1 | Closed | Prepare the published API surface for growth before the next release |
| [DS-084](DS-084.md) | P2 | Closed | Consolidate duplicated OSV identity matching and package dedup |
| [DS-085](DS-085.md) | P2 | Closed | Replace panic-prone indexing with typed lookups |
| [DS-086](DS-086.md) | P2 | Closed | Prune unused and misplaced dependency declarations |
| [DS-087](DS-087.md) | P2 | Closed | Remove dead public API and the duplicate ecosystem alias table |
| [DS-088](DS-088.md) | P2 | Closed | Tighten numeric conversions and remove infallible expect noise |
| [DS-089](DS-089.md) | P2 | Open | Reduce test-only conditional compilation woven through the sync service |
| [DS-090](DS-090.md) | P2 | Closed | Initialize tracing before configuration resolution |
| [DS-091](DS-091.md) | P1 | Closed | Schedule advisory scanning of depscan's own dependency tree |
| [DS-092](DS-092.md) | P2 | Closed | Add a SECURITY.md vulnerability disclosure policy |
| [DS-093](DS-093.md) | P2 | Closed | Refresh the dist-pinned actions/checkout to the v7 line |
| [DS-094](DS-094.md) | P2 | Closed | Assert toolchain pin consistency across workflows |
