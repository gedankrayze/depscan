---
name: depscan-release
description: Prepare, verify, publish, or audit a DepScan release, including version alignment, protected-main ancestry, immutable tags, artifacts, checksums, attestations, and native acceptance.
---

# DepScan release

Release work is high risk. Read `references/release-checklist.md` before changing release
configuration or creating a tag.

1. Keep release preparation separate from publication. Do not create or push a tag,
   publish a release, change repository controls, or move a release ref without explicit
   permission for that action.
2. Run focused installer/workflow verifiers while editing, then
   `bash scripts/dev-gate.sh release` on the frozen tree.
3. Verify version agreement across the workspace, CLI, action defaults, README examples,
   release plan, and intended tag.
4. Verify the tag target equals the reviewed protected `main` tip immediately before tag
   creation and again before publication.
5. Treat a green build as preparation evidence only. Close release acceptance only after
   verifying downloaded assets, paired and aggregate checksums, attestations, native
   startup/smoke behavior, and the published action without a binary override.
6. Record platform-native, cross-compiled, and untested targets separately. Never infer
   one from another.
