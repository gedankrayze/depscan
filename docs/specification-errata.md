# Development specification errata

This document records normative corrections to the version 0.1 development
specification. Where an entry below conflicts with the draft specification,
this erratum defines the repository's implemented contract.

## E-001: NuGet identity is provider-specific

The normalization summary in sections 3.3 and 3.5 must not be read as a rule
to lowercase NuGet names for every external API.

- Internal NuGet identity, deduplication, and cache lookup are
  case-insensitive and use a lowercase key.
- The spelling read from the project is retained for display and for OSV
  queries. OSV matching is case-sensitive for some NuGet advisory records.
- NuGet flat-container registry paths use the lowercase package ID, consistent
  with the registry's case-insensitive identity rules.

This separation is implemented and tested under [DS-003](issues/DS-003.md).
The provider mapping is summarized in the repository
[README](../README.md#package-identity-and-provider-names).
