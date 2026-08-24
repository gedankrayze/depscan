# Development specification errata

This document records normative corrections to the version 0.1 development
specification. Where an entry below conflicts with the draft specification,
this erratum defines the repository's implemented contract.

## E-001: NuGet identity is provider-specific

The normalization summary in sections 3.3 and 3.5 must not be read as a rule
to lowercase NuGet names for every external API.

- Internal NuGet identity, deduplication, and registry cache lookup are
  case-insensitive and use a lowercase key. Online OSV request-cache keys use
  the validated canonical ID because they are request-specific.
- The spelling read from the project is retained unchanged for reports. It is
  not trusted as the canonical package ID because NuGet references are
  case-insensitive.
- Online OSV queries use the canonical `catalogEntry.id` from the NuGet
  registration leaf for the concrete queried version. If that identity cannot
  be validated, the coordinate remains visibly unresolved and no
  source-spelling fallback is sent.
- NuGet flat-container and registration lookup paths use the lowercase package
  ID, consistent with the registry's case-insensitive identity rules.
- Offline dump matching uses ecosystem-normalized identity and does not require
  registration metadata.

The original internal/display/provider separation was implemented under
[DS-003](issues/DS-003.md); [DS-054](issues/DS-054.md) corrects its assumption
that source-preserved casing is necessarily canonical.
The provider mapping is summarized in the repository
[README](../README.md#package-identity-and-provider-names).

## E-002: Bun text-lock versions and installer configuration are separate

Section 3.1's general reference to Bun text lockfiles is amended for
[Bun 1.4](https://bun.com/blog/bun-v1.4):

- DepScan accepts `lockfileVersion` 0, 1, 2, and 3. Version 2 adds strict
  off-registry npm integrity and Git-tag safety checks; version 3 retains those
  checks and represents nested or version-scoped overrides.
- The resolved `packages` object is authoritative. DepScan reads the concrete
  name and version from each locator, including multiple overridden resolutions
  of the same package, and does not apply the top-level overrides a second time.
- `configVersion` is optional installer-layout metadata. It is validated as a
  non-negative integer but does not select a dependency parser because DepScan
  does not inspect `node_modules` or Bun's isolated global virtual store.

The executable contract and Bun 1.4.0-generated fixtures are recorded under
[DS-099](issues/DS-099.md).
