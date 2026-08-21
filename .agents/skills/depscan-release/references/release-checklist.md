# Release checklist

## Before a tag

- Confirm the worktree is clean and local, `origin/develop`, and `origin/main` state is
  understood.
- Confirm the reviewed release commit is the current protected `main` tip.
- Confirm the intended semantic version is unused and matches every version surface.
- Confirm the active `v*` tag rules prevent update and deletion.
- Confirm immutable releases are enabled and the workflow publishes draft -> complete
  inventory -> public.
- Run `bash scripts/dev-gate.sh release` and the current release plan.
- Review the exact asset allowlist, workflow permissions, action pins, and runner matrix.

## Publication

- Create one annotated version tag at the reviewed commit only after explicit permission.
- Push that exact tag without moving any existing tag.
- Monitor the tag-bound release run through plan, quality, native builds, aggregation,
  attestation, draft creation, publication, and announcement.
- Stop on the first deterministic failure; do not retag a public version.

## Acceptance

- Re-peel the remote tag and compare it with protected `main` and the release commit.
- Verify the published release is immutable and its inventory exactly matches the contract.
- Download every target family; verify paired checksums, aggregate checksums, and
  signer/source/tag-bound attestations.
- Run the binary natively on each supported target family and exercise the documented
  offline fixture contract.
- Run the published composite action without `binary` override on every supported runner,
  and verify its report plus provider-failure exit behavior.
- Record exact run, job, artifact, release, and commit identifiers before closing release
  ledger items.
