# Dependency freshness and post-push cleanup

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
