---
name: depscan-pr-triage
description: Inspect and process incoming DepScan pull requests and GitHub Actions efficiently, distinguishing required evidence, duplicate runs, fixture churn, and authorized remote mutations.
---

# DepScan pull-request triage

1. Begin read-only. Record the PR base, head, exact SHA, author, changed paths, merge
   state, required checks, reviews, and whether another PR supersedes it.
2. Treat `develop` -> `main` as the only allowed source for the protected-main PR.
3. Group duplicate push and pull-request workflow runs by head SHA. Use the required PR
   checks as canonical evidence and report redundant runs without waiting on both copies.
4. For a failure, identify the first deterministic failing command and separate product,
   test, workflow, runner, and external-service causes. Do not rerun blindly.
5. Reject automated changes to intentionally vulnerable or frozen fixtures unless the
   fixture contract itself is being changed deliberately.
6. Do not edit, close, merge, label, comment, rerun, or delete branches until the user
   authorizes those remote mutations.
7. Before an authorized merge, require current-head required checks, verify the source
   branch and review state again, and ensure the local worktree has no unpublished scope.
8. Before any later remote push, run `bash scripts/pre-push-check.sh`. Process every
   reported incoming PR first, then rerun the check until it passes. The outgoing
   `develop` -> `main` integration PR is excluded from the sweep.
9. Report one compact run inventory with exact run/job links or IDs, then the recommended
   disposition for each PR.
