# DepScan contributor guidance

## Working agreement

- Work from a `ticket/*` branch based on the current protected `main` tree.
- The integration path is `ticket/*` -> `develop` -> `main`. Do not push directly to `main`.
- Do not commit, push, merge, create or move tags, publish releases, or change remote
  repository settings without the user's explicit permission for that action.
- Preserve unrelated work. Inspect the worktree before editing and stage explicit paths.
- Treat release workflows, action installers, capability-safe filesystem code, frozen
  fixtures, snapshots, and security-boundary tests as sensitive review surfaces.

## Architecture

- Keep every Rust source file at or below 400 lines. Extract a cohesive module before
  adding another responsibility near that limit.
- Keep executable Rust tests in dedicated `tests.rs` or `tests/` modules, not beside
  production implementations.
- Prefer small modules with one owner and reusable helpers over locally duplicated logic.
- Run `bash scripts/check-rust-architecture.sh` after moving or adding Rust code.

## Validation

- During implementation, run the narrowest relevant test or verifier first.
- Use `bash scripts/dev-gate.sh quick` for a local checkpoint.
- On a frozen ordinary change, run `bash scripts/dev-gate.sh full` once. This includes the
  exact required lint command: `cargo clippy --all-targets -- -D warnings`.
- For release, installer, packaging, action, or artifact-contract changes, run
  `bash scripts/dev-gate.sh release` instead; release mode includes the full gate.
- Report skipped, environment-blocked, cross-compiled, and native runtime evidence
  separately. A cross-check is not native platform proof.

## Repository workflows

- Use the matching project skill under `.agents/skills/` for normal changes, PR triage,
  or releases.
- Project hooks are guardrails, not authorization or complete security boundaries.
- Keep GitHub Actions SHA-pinned and retain read-only permissions unless a reviewed job
  requires a narrower write grant.
- Prefer one canonical local full gate and one required PR run. Do not add duplicate
  workflow triggers merely to repeat the same evidence.
