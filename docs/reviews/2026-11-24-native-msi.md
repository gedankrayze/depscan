# Native Windows MSI verification — 2026-11-24

The published v3.0.0 MSI was exercised on a real Windows 11 Pro x64 machine
(10.0.26300) using an elevated, non-interactive PowerShell 5.1 session. There was
no pre-existing DepScan installation, executable resolution, default install
directory or running MSI transaction. Host connection details
and verbose installer logs remain private.

## Artifact identity

- Release: `455948224`, immutable `v3.0.0`.
- Source: `59aeb873baea3c32533a3b7df9e580bd72fb31fa`.
- MSI asset: `784405994`; SHA-256
  `d90ec3f9b94815549c7f487e97f1fa7fb5caa485d23ab694a40b2df45f2d0c20`.
- Reference ZIP asset: `784406009`; SHA-256
  `31739677851a287c4d67d8d90aae619cf5ed8708af6080db89496f4af8359e8f`.
- Installed/repaired executable SHA-256:
  `dca29a8b6bc387ab05bb8eb241285c8d545aa1df8eaa380915c1bb2bdbfe7122`.
- Product code: `{0A3A60DA-99CB-4DC2-981A-845A51511704}`.
- Upgrade code: `{B9B1BD89-A7D8-49C1-B38F-BBF45E691458}`.

Before execution, fresh downloads matched paired checksums, release API digests
and sizes. GitHub's signed release statement verified. MSI and ZIP attestations
verified the repository, release workflow, immutable tag ref, exact source digest,
and denial of self-hosted runners. Hashes were checked again on Windows after
transfer. Read-only MSI database inspection confirmed version 3.0.0 and
`ALLUSERS=1`; `Win32_Product` enumeration was avoided.

## Results

| Check | Result |
|---|---|
| Default per-machine quiet installation | Exit `0`; `C:\Program Files\depscan-cli\bin\depscan.exe` |
| Registration and PATH | HKLM product 3.0.0; one bin entry; unrelated entries and user PATH preserved |
| Published binary identity | Installed executable equals authenticated ZIP executable |
| Native version/help | Both passed; `depscan 3.0.0` |
| Offline Cargo fixture | Four packages, zero vulnerabilities, three expected registry soft failures |
| JSON/reproducibility | Schema 4; epoch 1700000000 emits `2023-11-14T22:13:20Z` |
| Missing offline advisory dump | Exit `30` with the typed provider-hard-failure diagnostic |
| Missing-executable repair | Exit `0`; exact executable restored; offline smoke passed; no duplicate PATH entry |
| Quiet uninstall | Exit `0`; registration, executable, default directory, command resolution and bin entry removed |
| PATH text/user environment | Machine PATH text restored exactly; user PATH unchanged |
| Machine PATH registry type | **Caveat:** `REG_EXPAND_SZ` became `REG_SZ` on install and stayed so after uninstall |
| Host restoration | Original registry type restored under an exact-text guard; MSI requested no reboot |

Installation, repair and uninstall used `/qn /norestart REBOOT=ReallySuppress`
with verbose logs. PATH resolution used a process environment refreshed from
registry values; no SSH service restart was performed. Repair deliberately removed
only the executable belonging to this temporary installation, then used `/fa`.

The registry-type caveat reproduced across clean installation cycles and is tracked
in [DS-127](../issues/DS-127.md). The tested baseline PATH had no expandable tokens;
effects on such tokens were not mutation-tested on the user's machine. Manual
restoration of the original type is cleanup, not proof of package reversibility.

Early fixture-helper attempts encountered PowerShell 5 assembly loading and
`Start-Process` exit-code capture differences. Those harness issues were corrected
and independently checked against the authenticated reference executable before
the final installed-binary lifecycle. Each attempt uninstalled its test product;
the final run, not the preliminary harness attempts, supplies functional evidence.

Interactive wizard UI, upgrades/downgrades, non-administrator installation, other
Windows versions, and machine PATH expansion behavior are not covered. No package,
tag, release asset, or Rust code changed during this verification.

Independent final checks compared machine/user PATH text, value presence and
registry types against the saved baseline, and confirmed the product, install
directory, command and process were absent. CBS and Windows Update reboot markers
were absent. Windows had queued printer-driver file operations without a DepScan
reference; their pre-test state was not captured, and they were left untouched.
No host-wide reboot claim is made from the MSI exit codes.

Cleanup retained 35 native log/receipt files privately, checking each transferred
file's length and SHA-256. The exact owned Windows temporary directory was then
removed (36,375,845 bytes); final environment and product-absence guards passed.
Local build cleanup removed 2.2 GiB. Unrelated IDE state and stashes were preserved.

The documentation-only candidate passed `bash scripts/dev-gate.sh full`, including
`cargo clippy --all-targets -- -D warnings`, workspace tests, architecture and
workflow verifiers. All 127 issue records remained within the 500-word soft cap.

## Unreleased DS-127 fix qualification

The user subsequently authorized a source fix. `wix/path-type.c` captures a scalar
registry type before the transaction. A deferred action restores that type over
the current raw PATH bytes after environment actions and old-product removal; the
paired rollback action restores the type after native rollback. Missing values
are not recreated. Only the fixed HKLM environment `Path` value is writable.
The DLL accepts no key name, PATH text or executable/command property, launches no
process, and links its C runtime statically. Invalid type scalars, non-string
current values and malformed retyped data fail closed; allocations are bounded.

Upgrades move to `afterInstallExecute`, retaining the binary and PATH component
identities required for component reference counting. Scheduling a rollback action
between initialization and early old-product removal produced ICE63, so that
prototype was rejected. The final definition passes WiX validation with warnings
as errors. Successful and failed upgrades cover both fixed local fixtures and
the authenticated original v3.0.0 MSI. The legacy fixture is explicitly type-repaired
before upgrade to model an already-corrected installed environment. If failed
upgrade recovery reinstalls that legacy product, its later uninstall still exhibits
the old defect and receives separately identified manual cleanup.

Native tests first failed against the published MSI on the actual type change.
Fixed-package installation, missing-file repair and uninstall retain both `REG_SZ`
and `REG_EXPAND_SZ`; a literal `%SystemRoot%` entry remains unexpanded in raw
registry text. Machine/user environment snapshots match after each case. Forced
installation rollback and failed-upgrade rollback restore registrations, executable,
PATH entries and type without fixed-package manual cleanup. Isolated HKCU fixtures
exercise exact bytes, Unicode, later-added entries, empty/missing values and invalid
data. Failure injection exists only in generated test packages.

`scripts/windows-msi/verify.ps1` provides the repeatable procedure used by the
existing Windows quality job. The release Windows builder compiles the helper into
the stable Cargo target directory before packaging; it is embedded in the MSI rather
than added to the public asset inventory. Compiled-MSI checks enforce action types
and sequencing. Cargo-dist 0.34.0 initially rejected the modified managed template;
the documented `msi` generation override plus independent identity/version checks
allow the reviewed definition. The resulting plan still matches all 16 assets.

The pinned cargo-dist source stages application executables in a separate MSI
package directory. The helper therefore uses `CargoTargetDir/msi-helper`, not the
overridden `CargoTargetBinDir`; local MSI tests deliberately separate these paths.

Local test MSIs use the authenticated v3.0.0 ZIP executable, unchanged. Incremented
MSI versions are upgrade-fixture metadata, not a released CLI version or a tag.
Published assets, source versions and repository settings are unchanged. Interactive
UI, non-admin behavior, alternate installation directories and other Windows builds
remain outside this local verification.

Final native qualification completed at `2026-11-24T08:51:27Z`. The retained local
candidate MSI SHA-256 is
`4588308575d9a77a265fa60088416945d32e131bc65f198105d6eef1aeadc50d`;
its helper DLL SHA-256 is
`db796cd4ac5e781722ec4130ad274a2b95d2a11f890b22b19caf10e918ad92ee`.
All nine native lifecycle/rollback/upgrade/PATH scenarios passed on the final source.
A copied package with an unsafe custom-action return policy was rejected by the
compiled contract verifier before installation. The frozen release gate passed
strict Clippy, 468 workspace tests (one opt-in live test ignored), all five package verifications and the optimized
CLI build; Actionlint and the 16-file cargo-dist plan also passed. Hosted CI has
not run for this uncommitted change; DS-127 stays open pending integration/release.

After copying and hash-verifying 409 native evidence files privately, final cleanup
removed the exact owned Windows temporary directory (480,966,403 bytes). Machine
and user PATH text/types still matched the original baseline; the product, default
directory and running command were absent. No reboot or service restart was
performed. Local `cargo clean` removed 20,277 files (3.9 GiB); four task-generated
packaging overlays and remaining temporary tools were moved to recoverable Trash.
Unrelated IDE state, user resources and stash state were preserved. A candidate
MSI, its DLL, source snapshot and verification logs remain in private evidence.

References: [cargo-dist unmanaged MSI definitions](https://axodotdev.github.io/cargo-dist/book/installers/msi.html#unmanaged-advanced-usage),
[MSI rollback actions](https://learn.microsoft.com/en-us/windows/win32/msi/rollback-custom-actions),
[WiX upgrade sequencing](https://docs.firegiant.com/wix3/xsd/wix/majorupgrade/).
