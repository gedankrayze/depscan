# Dependency freshness and post-push cleanup

## Clone setup and snapshot exclusions

The marked build artifact section in `.gitignore` is the source of truth for snapshot
exclusions. Every `scripts/dev-gate.sh` mode and the trusted Codex session-start hook run
`python3 scripts/setup-project.py`. Contributors can also run that command directly
after cloning; it needs only Python 3 and Git.

Git does not execute project setup during a clone. The checked-in `.gitignore` protects
the fresh checkout immediately; setup installs the same build patterns into Git's local
`info/exclude`, so they remain active across branch switches. Linked worktrees use the
common repository's exclusion file. Existing entries are preserved; repeated setup adds
only missing patterns under an exclusive lock and atomically replaces the file. It does
not change global Git configuration, install Git hooks, or modify the index or refs.

Git-based snapshot tools must respect ignore rules; already tracked files and explicit
force-add operations bypass ignores. Keep build outputs untracked and never force-add
them for snapshots. This prevents new captures; it does not prune old Git objects.

## Before every authorized push

Run `bash scripts/pre-push-check.sh` immediately before pushing. Process incoming
PRs first (the outgoing `develop` → `main` PR is excluded). The check then runs
`cargo upgrade --incompatible allow --locked`,
`cargo update --locked`, and `cargo audit --deny warnings`.
Install cargo-edit and cargo-audit when missing. Network/tool failures are failures,
not freshness evidence. Do not bypass the gate or suppress advisories to publish.
Do not add `--dry-run` to the locked update: Cargo otherwise succeeds even when
new lockfile resolutions are available. Real stale-file controls verify nonzero
failure without changing the candidate; freshness is not parsed from human tables.

Review newer releases, update manifests/lockfile, and qualify the changed candidate.
Keep incompatible upstream constraints and the MSRV explicit; do not force unsafe
global overrides or update intentionally vulnerable scanner fixtures.

## After a successful push

Wait for required CI and, for releases, public-artifact/native acceptance. Preserve
the exact commit, run IDs, audit database revision, and necessary evidence before
cleaning. A push alone does not make in-progress build outputs disposable.

1. Record branch/status, stash hashes, `git clean -ndX`, and task-owned resources.
   Never apply/drop stashes, discard changes, or remove unrelated `.idea/` state.
2. Resolve Cargo's target directory and verify it belongs to this checkout before
   `cargo clean --target-dir <verified-path>`. Remove only identified task-generated
   packaging overlays; retain shared crate downloads, toolchains, and user caches.
3. Remove unused task-owned images/build caches only after checking exact IDs,
   ownership labels, running containers, and other consumers. No blanket Docker
   prune, image removal by repository-name guess, or volume deletion. If Docker is
   unavailable, record that boundary instead of starting/changing the daemon.
4. Remove task-owned temporary downloads, reports, and artifacts after durable evidence
   exists. Prefer recoverable Trash for local files. Never delete immutable public
   release assets, attestations, or retained audit evidence. Remote run artifacts/caches
   need verified scope and existing cleanup permission, not broad repository deletion.
5. Inventory attached and Git worktrees. Archive unused managed worktrees through the
   app's recoverable archive operation only after verifying ownership, inactive status,
   uncommitted files, and ignored data. Do not remove primary/shared/pinned checkouts
   or another task's worktree. Prune metadata only after the checkout is safely archived.
6. Prove merged ticket ancestry before local branch deletion. Remote branch deletion
   still needs explicit permission. Recheck status, branch, and identical stash hashes;
   report removals, retained resources, and anything blocked.

These checks are scoped to resources created for DepScan work, not system-wide cleanup.

## Compact issues

Aim for at most 500 words per `docs/issues/DS-*.md` record. This is a soft cap, not
permission to delete evidence or omit a necessary security boundary. Keep the finding,
fix, verification, and links; move verbose logs to review notes or link immutable source
history. The index is a navigation table, not an individual issue. Run
`python3 scripts/check-issue-size.py`; oversized records produce review warnings.

## Windows MSI verification

On a Windows x64 test machine with MSVC C++ build tools, WiX 3 and an elevated
PowerShell session, build the CLI and run:

```powershell
cargo build --release --locked -p depscan-cli
./scripts/windows-msi/verify.ps1 -BinaryDirectory target/release -EvidenceDirectory target/msi-evidence
```

Set `WIX` or pass `-WixDirectory` for the toolset directory. The evidence directory
must be new and no existing DepScan installation may be present. The tests install
per-machine, repair a deliberately removed executable, upgrade, inject failures in
separate test-only packages, and uninstall. Test version increments are fixture
metadata; they do not change workspace versions or publish a release.

On a test host, add `-ExercisePathFixtures` to exercise `REG_SZ`, `REG_EXPAND_SZ`,
and a literal `%SystemRoot%` PATH entry. This temporarily changes machine PATH;
existing entries are retained and original text/type are restored under exact-value
guards. Concurrent edits cause failure rather than a snapshot overwrite. Isolated
HKCU registry fixtures also test Unicode, malformed data, missing values and raw
byte preservation. Retain verbose logs privately: they contain environment paths.

The helper is a native DLL with a static C runtime, embedded only in the MSI. It accepts
an original type scalar, reads/writes only the fixed machine PATH value, and never
uses shell commands or saved PATH text for restoration. MSI manages PATH entries.
Review its deferred/rollback actions and stable component identities when changing
upgrade scheduling. Cargo-dist's `ci`/`msi` generation overrides are intentional;
the source verifier checks identity/version bindings and the native build verifies
the compiled action types/order. Release assets remain immutable.
