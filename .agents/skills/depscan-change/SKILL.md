---
name: depscan-change
description: Implement, refactor, test, or review ordinary DepScan Rust, documentation, fixtures, and CI changes while preserving its modularity and evidence rules.
---

# DepScan change

Use this skill for normal product and maintenance work. Use `depscan-release` for tags,
artifacts, installers, or publication, and `depscan-pr-triage` for incoming pull requests.

1. Read the root `AGENTS.md`, inspect `git status`, and map the affected crate, tests,
   docs, fixtures, and workflow surfaces before editing.
2. Preserve unrelated changes. Work on a `ticket/*` branch and do not commit or publish
   unless the user separately authorizes it.
3. Keep Rust files at or below 400 lines and move executable tests to `tests.rs` or a
   `tests/` module. Extract cohesive responsibilities instead of raising the ceiling.
4. Run the narrowest relevant test or verifier while iterating.
5. Run `bash scripts/dev-gate.sh quick` at a checkpoint.
6. On the frozen tree, run `bash scripts/dev-gate.sh full` once and inspect
   `git diff --check`, `git status`, and the complete diff.
7. Report the outcome first, then changed files, verification evidence, and any native,
   cross-target, or external-state evidence still pending.
