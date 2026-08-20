# depscan verification and traceability matrix

This document is the durable index from the version 0.1 development specification and the `DS-*` audit ledger to executable evidence. Issue files retain the detailed defect history and closing evidence; this index answers which test or release gate protects each contract now.

## Required gates

Run the deterministic suite without public network access:

```bash
cargo +1.97.1 fmt --all -- --check
cargo +1.97.1 test --workspace --all-targets --locked
cargo +1.97.1 clippy --all-targets -- -D warnings
cargo +1.95.0 test --workspace --all-targets --locked
```

The ignored live provider suite is deliberately opt-in and belongs in the scheduled workflow, not pull-request CI:

```bash
DEPSCAN_RUN_LIVE=1 cargo +1.97.1 test --locked -p depscan-cli \
  --test e2e_matrix live_provider_matrix_for_every_ecosystem \
  -- --exact --ignored --nocapture
```

Pull-request CI runs the complete deterministic suite on Linux, macOS, and Windows and then explicitly runs `offline_workspace_self_scan`. The weekly/manual `live-provider-smoke.yml` job records only package counts, vulnerability-record counts, and whether registry enrichment completed. It does not upload cache contents, response bodies, credentials, or secrets.

## Specification traceability

| Specification contract | Primary executable evidence |
|---|---|
| §1 four-ecosystem vulnerability/freshness pipeline | `e2e_matrix::offline_ecosystem_output_matrix`; `live_provider_matrix_for_every_ecosystem`; provider online/offline parity tests |
| §1 zero-auth/free public sources | `native_registry_http_mocks_cover_every_endpoint_and_header_contract`; ignored live matrix; no credential input exists in the CLI help snapshots |
| §1 single static binary | `static-linux.yml`; `scripts/verify-static-linux.sh`; scratch-container offline smoke |
| §1 CI-first reports and exit codes | `exit_codes.rs` process tests for `0`, `1`, `2`, `10`, `20`, and `30`; output-format matrix |
| §1 offline operation | `offline_ecosystem_output_matrix`; `offline_workspace_self_scan`; `offline_scan_uses_registry_cache_with_network_explicitly_denied` |
| §1.1 report-only/non-goals boundary | `offline_ecosystem_output_matrix` byte-snapshots each fixture before and after all scans; help snapshots expose no upgrade, lockfile-write, SBOM, or license command |
| §2.1 normalized model and conservative metadata merge | core `package_metadata_merge_preserves_unknown_classifications_conservatively`; JSON schema/report tests |
| §2.2 parser/provider traits and stage boundaries | workspace compilation plus parser fixture integrations, provider mocks, report unit tests, and process E2E; parsers receive no HTTP dependency |
| §2.3 Tokio, request budgets, retries, chunking, caps, soft/hard failures | `production_network_budgets_match_the_documented_contract`; retry test family; `failed_query_chunk_is_soft_when_another_chunk_completes`; report soft-error tests; CLI total-outage exit `30` |
| §3.1 npm/Bun formats, workspaces, direct/dev and SemVer | npm/Bun/pnpm/Yarn rows in the parser matrix below; npm E2E fixture; native version-constraint tests |
| §3.2 Python formats, sources, PEP 503/440 and groups | Python rows below; core PEP 440 tests; PyPI provider selectors; Python E2E fixture |
| §3.3 NuGet locks/projects/central/legacy, identity and ordering | .NET rows below; NuGet version tests; NuGet E2E fixture; authorized tool-fallback tests |
| §3.4 Cargo lock/manifest/workspace/source semantics | Cargo rows below; Cargo E2E fixture; workspace self-scan |
| §3.5 ecosystem name/version normalization | core `normalizes_pypi_names`, `nuget_identity_is_case_insensitive_but_display_case_is_preserved`, SemVer/PEP 440/NuGet tables, and E2E normalized package assertions |
| §4.1 OSV query, hydration, pagination, severity, withdrawn and fixed ranges | OSV provider matrix below; shared `fixtures/osv-range-cases.json`; document-shape/cache/offline parity tests; withdrawal process/report tests |
| §4.2 all native registries and request identity | `native_registry_http_mocks_cover_every_endpoint_and_header_contract`; malformed-document matrix; registry range fixtures; crates sparse-index tests |
| §4.3 sync/offline dumps and cached freshness | offline dump validation/age/resource tests; sync streaming/rollback/race tests; offline process tests |
| §5 complete CLI/config/filter/help surface | CLI unit merge tests plus `exit_codes.rs` typed-value, config, help, completion, filtering, and stream-contract process tests |
| §5 exit taxonomy and precedence | the exit-code table below |
| §6 table, JSON, SARIF 2.1.0 and summary | report unit tests plus all four formats for all four ecosystems in `offline_ecosystem_output_matrix` |
| §7 cache, ETag, TTL, retries, limits and explicit tools | controlled common-cache age boundaries; future registry/sparse revalidation and OSV hard/soft process tests; cache/revalidation/retry suites; capability-safe cache tests; `tool_fallbacks.rs`; implicit authorization denial process test |
| §8 workspace crate boundaries and packageability | `cargo check/test/clippy --workspace --all-targets`; `cargo package --list`/`cargo package` evidence in DS-024 |
| §9 required testing layers | parser, version, provider, deterministic E2E, ignored live, three-OS CI, MSRV, and dogfood rows in this document |
| §10 M1-M6 functional milestones | workspace suite and E2E/provider matrices; `uses: ./` composite-action smoke; artifact publication and real action downloads remain release-gated by DS-045/DS-049 rather than inferred from unit tests |
| §11 policy decisions | README/help snapshots protect best-effort `--no-dev` and MSRV policy; repository/release ownership remains in DS-001 and DS-045 |
| Appendix A endpoint/auth/limit reference | native endpoint/header mock; OSV pagination/chunk tests; ignored live matrix |

## Parser fixture matrix

| Source/variant | Meaningful tests |
|---|---|
| Bun text lock v0/v1/v2, JSONC, scoped names, aliases, workspaces, malformed locators | `bun_lock.rs::{parses_current_bun_lock_locators_without_leaking_locator_prefixes,parses_version_one_bun_lockfiles,parses_version_zero_workspace_tuple_shape,rejects_malformed_bun_locator_arrays_with_context}` |
| `bun.lockb` authorized extraction and manifest-only degradation | `tool_fallbacks.rs::{explicitly_selected_config_runs_bun_with_exact_sandboxed_invocation,malformed_outputs_are_actionable_for_both_tools,authorized_nonzero_bun_exit_is_not_hidden_by_manifest_fallback,missing_bun_executable_degrades_to_manifest_constraints,tools_are_never_started_without_effective_authorization,bun_manifest_fallback_fails_closed_without_a_usable_manifest}`; parser `tool_outputs.rs` and `bun_manifest_fallback.rs` |
| npm package-lock v1/v2/v3, nested/scoped/workspaces | parser nested/v1 snapshots plus `rejects_malformed_npm_v2_v3_package_records`, `npm_links_require_a_proven_workspace_identity`, `npm_non_root_registry_constraints_cannot_fall_back_to_an_incompatible_workspace`, `npm_sources_must_resolve_to_the_selected_link_target`, `npm_alias_records_require_the_declared_registry_identity`, `npm_installed_identity_selects_the_effective_duplicate_group_alias`, `npm_effective_dev_declaration_overrides_a_source_declaration`, `npm_workspace_sources_bind_to_their_concrete_installed_records`, `npm_workspace_patterns_follow_npm_negation_semantics`, `npm_minimatch::{matches_all_extglob_operators,follows_npm_empty_extglob_and_dot_boundaries,follows_component_local_utf16_and_unicode_regexp_modes,rejects_minimatch_invalid_unicode_escapes_and_empty_quantifiers,preserves_resource_bounds_after_extglob_lowering,matches_checked_in_npm11_differential_corpus}`, `lock_schema_validation::parses_npm11_mixed_negative_extglob_workspace_fixture`, `npm_external_link_descriptors_do_not_require_uninstalled_edges`, `npm_registry_declarations_coalesced_at_one_install_must_agree`, `npm_dedup_keeps_a_proven_public_occurrence_enrichable`, `npm_ambiguous_registry_origins_are_visible_but_not_enriched`, public-tarball identity, and v1/non-registry controls; `exit_codes::npm_extglob_workspace_fixture_accepts_real_link_and_rejects_forged_nonmatches`, strict-entry and source-redaction process regressions; npm process E2E |
| pnpm v6/v9 plus YAML safety | `lock_schema_validation::accepts_supported_numeric_pnpm_v6_schema`; `yaml_lock_safety::{preserves_current_pnpm_schema_and_manifest_provenance,permits_bounded_anchor_reuse_for_compatible_lockfiles,rejects_duplicate_keys_in_pnpm_and_yarn_berry,rejects_merge_keys_excessive_alias_expansion_and_deep_nesting}` |
| Yarn Classic v1 and Berry v4-v10 | `yarn_lock.rs::{preserves_yarn_classic_parsing_and_manifest_provenance,parses_current_yarn_berry_with_aliases_workspaces_and_protocols,rejects_unsupported_or_malformed_yarn_lockfiles_with_context}` |
| npm manifest-only ranges | parser `package_json_preserves_the_original_npm_range`; core constraint table; registry range fixtures |
| uv lock v1, sources, script locks, direct/dev/optional reachability | `python_locks.rs::{parses_current_uv_sources_directness_groups_and_transitive_scope,follows_uv_manifest_extras_from_script_locks,rejects_unsupported_and_malformed_uv_lockfiles_with_context}`; Python process E2E |
| Poetry lock v1.0/1.1/2.0/2.1 and provenance | `python_locks.rs::{parses_current_poetry_sources_manifest_directness_and_groups,parses_legacy_poetry_category_and_group_less_metadata,rejects_unsupported_and_malformed_poetry_lockfiles_with_context}` |
| Pipfile.lock default/develop/directness | `python_locks.rs::{pipfile_lock_joins_manifest_directness_by_normalized_name,pipfile_lock_keeps_directness_unknown_without_a_valid_manifest}`; corresponding CLI filter tests |
| requirements syntax, includes, constraints, hashes/options/URLs/markers and resource limits | `requirements.rs` fixture suite plus internal `requirements` include containment/depth/file-count/byte-limit tests |
| PEP 621, Poetry and PEP 735 manifests/sources/constraints | `python_manifest.rs` four fixture tests; normalized constraint/provider range tests |
| NuGet `packages.lock.json`, all target frameworks and direct/transitive | `dotnet::lockfiles_cover_all_frameworks_and_keep_resolved_metadata`; NuGet process E2E |
| csproj/fsproj/vbproj, central props, overrides, packages.config | `dotnet.rs::{detects_every_project_lock_and_legacy_manifest,merges_nearest_central_versions_and_project_overrides,preserves_legacy_development_dependency_metadata,rejects_unresolved_references_and_malformed_lock_entries}` |
| authorized dotnet tool fallback | `tool_fallbacks.rs::{allow_tools_runs_dotnet_with_exact_project_and_offline_arguments,online_dotnet_profile_does_not_disable_the_authorized_restore}`; parser `tool_outputs.rs` |
| Cargo lock and manifest-only workspaces | `cargo_manifest.rs` five tests covering globs/excludes/inheritance/renames/targets/path/git; Cargo process E2E and workspace self-scan |
| Every strict lock schema | `lock_schema_validation.rs` valid-empty, realistic, wrong-format, missing-section, malformed, and future-schema matrices for npm, Bun, pnpm, uv, Poetry, Pipfile, NuGet, and Cargo |

## Version and provider matrix

| Behavior | Meaningful tests |
|---|---|
| npm/Cargo SemVer and prereleases | core `classifies_semver`; constraint `selects_latest_matching_versions_with_native_ecosystem_semantics` and `handles_prereleases_according_to_each_constraint_language` |
| PEP 440 dotted, epoch, pre/dev/post/local and staleness | core `orders_pypi_versions_with_pep440`, `detects_stable_pypi_versions_with_pep440`, `classifies_pypi_staleness_from_parsed_release_segments`; PyPI selector tests |
| NuGet 1-4 part versions, numeric prerelease, metadata and invalid forms | `nuget.rs::{follows_nuget_precedence,normalizes_release_components_and_omits_metadata,rejects_malformed_versions_instead_of_inventing_zero_components,accepts_nuget_release_zeroes_and_large_numeric_prerelease_identifiers}` |
| OSV explicit versions/events/disjoint ranges/limits/all ecosystems | core `osv.rs` table and `hydrated_and_offline_range_fixture_results_are_identical` |
| CVSS v3/v4 precedence and malformed vectors | provider `scores_supported_cvss_versions_with_standard_formulas` through `rejects_malformed_mismatched_and_unscoped_scores` |
| Native registry success and exact headers/paths | `native_registry_http_mocks_cover_every_endpoint_and_header_contract` |
| Native registry malformed responses | `native_registry_http_mocks_reject_malformed_documents_for_every_ecosystem`; crates NDJSON malformed/size matrix |
| Retry budget, 429/5xx/connect/timeout, `Retry-After`, no final sleep | provider retry-status/date/JSON/bytes/transport tests and sync retry tests |
| OSV batch alignment, 1,000-item chunks, pagination and hydration | `paginates_queries_independently_and_caches_complete_deduplicated_ids`; malformed batch/document matrices; query-hit affected-entry validation; partial query/hydration tests |
| ETag/304/cache revalidation and racing writers | sparse and generic registry `stale_*`, `future_*`, `late_*`, changed/missing ETag tests; OSV revision/CAS tests |
| Common and offline cache age/integrity | `common_cache_freshness_rejects_future_timestamps_and_honors_boundaries`; future online OSV/registry/hydration regressions; offline registry fresh/stale/missing/corrupt/future tests; CLI offline tests |
| Provider soft versus hard failure | report `soft_provider_errors_are_visible_in_every_report_format`; CLI partial/total outage tests, future empty-query hard/soft cases, and malformed cached OSV hard/soft cases |
| Resource bounds | streamed dump peak-memory test; dump entry/aggregate/count limits; sparse response/line limits; requirements depth/read/byte limits; tool timeout/output-limit tests |

## Process-level output and exit matrix

| Contract | Process evidence |
|---|---|
| Every ecosystem × table/JSON/SARIF/summary | `e2e_matrix::offline_ecosystem_output_matrix` |
| Real workspace dogfood without network | `e2e_matrix::offline_workspace_self_scan`, explicitly rerun by every `quality` OS job |
| Live OSV plus every registry | ignored `live_provider_matrix_for_every_ecosystem`, weekly/manual workflow only |
| Exit `0` | `clean_scan_exits_zero_and_writes_report_to_stdout` and E2E matrix |
| Exit `1` | `vulnerability_threshold_exits_one_and_writes_report_to_stdout` |
| Exit `2` | `outdated_threshold_exits_two_and_writes_report_to_stdout` and yanked process tests |
| Exit precedence `1 > 2` | `vulnerability_exit_takes_precedence_over_outdated_exit` |
| Exit `10` | unknown/typed argument, config, output, malformed project, and unsupported schema process tests |
| Exit `20` | `unsupported_project_exits_twenty` |
| Exit `30` | `provider_hard_failure_exits_thirty`, total OSV outage, future empty OSV cache with denied network, malformed offline advisory |
| stdout report / stderr diagnostics | success/finding helpers and usage/config/provider process assertions throughout `exit_codes.rs` |

## Audit issue traceability

| Issue | Regression test or gate |
|---|---|
| DS-001 | `git check-ignore`, Renovate config validation, PR-policy positive/negative probes, and required-ruleset evidence recorded in the issue |
| DS-002 | provider CVSS table plus CLI vulnerability exit `1` |
| DS-003 | core NuGet identity, canonical-case OSV mock, lowercase registry-coordinate test |
| DS-004 | core PEP 440 tables and PyPI selector tests |
| DS-005 | shared core OSV table plus hydrated/offline identical fixture test |
| DS-006 | duplicate-attribute/namespace XML regressions, `cargo audit`, `cargo tree -i quick-xml` |
| DS-007 | `bun_lock.rs` version/locator fixture matrix |
| DS-008 | npm v1/v2/v3 nested package snapshots |
| DS-009 | Yarn Classic/Berry fixtures and YAML safety matrix |
| DS-010 | `dotnet.rs` multi-project/central/legacy matrix |
| DS-011 | `cargo_manifest.rs` workspace fixture matrix |
| DS-012 | `python_locks.rs` uv/Poetry provenance matrix and CLI filters |
| DS-013 | `malformed_osv_batch_responses_fail_closed_without_query_cache_entries`, `malformed_result_is_soft_when_an_aligned_package_result_is_complete`, and valid-empty alignment/cache regression |
| DS-014 | `paginates_queries_independently_and_caches_complete_deduplicated_ids` and repeated-token rejection |
| DS-015 | registry/OSV ETag, revision and racing-writer tests |
| DS-016 | sync streaming, interruption, retry, validation, atomic replacement and rollback tests |
| DS-017 | requirements symlink/escape/cycle/resource tests and process exit `10` |
| DS-018 | crates.io path boundary/character tests and zero-request invalid-name mock |
| DS-019 | complete process exit matrix above |
| DS-020 | withdrawn renderer and all-format process tests |
| DS-021 | active/expired suppression renderer and process audit-metadata tests |
| DS-022 | CLI/config merge unit tests and complete config process tests |
| DS-023 | `tool_fallbacks.rs` nine sandbox/authorization/failure tests plus parser `tool_outputs.rs` |
| DS-024 | `cargo metadata`, package-list/package-build checks for every workspace crate |
| DS-025 | pinned 1.97.1 quality matrix and 1.95.0 MSRV job/tests |
| DS-026 | locked workspace gates, direct-version audit, `cargo audit` |
| DS-027 | pnpm/Yarn YAML anchor/duplicate/merge/depth/scalar safety tests |
| DS-028 | this inventory, native registry mocks, four-ecosystem process E2E, offline dogfood, ignored live suite |
| DS-029 | native constraint tables, `registry-ranges.json`, manifest-resolution report test |
| DS-030 | offline dump-age/cache-integrity unit tests and offline process tests |
| DS-031 | deterministic retry status/date/attempt/jitter/transport tests |
| DS-032 | offline malformed UTF-8/JSON/schema/truncation/limit tests and process hard failure |
| DS-033 | complete/malformed/duplicate/oversized crates sparse-index mock suite |
| DS-034 | owned-cache initialization/clear/sentinel/symlink tests plus cache-clear process test |
| DS-035 | multi-chunk/page/result/hydration/evaluation/cache-publication partial-failure mocks and CLI partial outage |
| DS-036 | Poetry manifest constraint/group/source fixtures and normalized constraint assertions |
| DS-037 | Pipfile lock directness unit and CLI filter tests |
| DS-038 | requirements grammar/options/includes/constraints/resource fixture suites |
| DS-039 | NuGet precedence tables, OSV NuGet range test, latest-stable selector |
| DS-040 | strict eight-format schema fixture matrix plus process pre-provider exit `10` |
| DS-041 | missing/directory/read-failure/symlink/valid explicit-config process matrix |
| DS-042 | controlled clock/canonical ordering plus repeated byte-identical process JSON |
| DS-043 | yanked-current/outdated/partial-file renderer and process matrices |
| DS-044 | typed-value/conflict/repeat/inference process tests plus help/completion byte snapshots |
| DS-045 | release-plan/dry-run, tag ancestry, per-target artifact/checksum/provenance/download/startup/scan acceptance in the issue; this cannot be replaced by a unit test |
| DS-046 | `verify-static-linux.sh`, native musl artifact matrix, scratch-container offline smoke |
| DS-047 | capability-relative sync race tests at acquisition, lock, cleanup, staging, archive/marker publication, rollback and error boundaries |
| DS-048 | `secure_fs.rs` config/root/parent/final swap, symlink, atomic creation/replacement and permission-preservation tests plus CLI process checks |
| DS-049 | `verify-github-action.sh`, typed argument-vector probes, and the Linux `uses: ./` CI smoke; real per-runner release download remains recorded in the issue |
| DS-050 | online cached-registry and offline-dump manifest-to-OSV process tests, including exact/ranged constraints, shared-coordinate mapping, vulnerability exit `1`, and unresolved-cache errors |
| DS-051 | consumed-field document validator, query-hit match/evaluability tests, hydration cache bypass/non-publication, offline shape parity, and CLI hard/soft malformed-record tests |
| DS-052 | strict root/workspace manifest fallback fixtures plus unauthorized, missing-executable, provenance, and post-start hard-failure process tests |
| DS-053 | ledger numbering/index/traceability and issue-tagged commit-history completion audit |
| DS-054 | bounded inline/linked NuGet registration metadata, canonical-ID/mismatch and URL-confinement provider tests; online/offline query-plan identity controls; lowercase exact/range canonical-only OSV process regression |
| DS-055 | online/offline total manifest-resolution failure, partial-resolution, and report-only process controls |
| DS-056 | controlled common-cache time boundaries; future OSV query/hydration, generic registry, sparse-index, cache-bypass, and process hard/soft regressions |
| DS-057 | strict npm v2/v3 entry table; link/alias/group-precedence/concrete-hoist/workspace-pattern/source/v1 controls; npm 11 fixtures; mixed-record exit `10`; source-redaction process test |
| DS-058 | `npm_v2_lock_edges_prove_exact_directness_without_external_manifest`; `npm_v3_lock_edges_prove_exact_directness_without_external_manifests`; `bun_manifest_fallback::rejects_workspace_manifest_symlinks_to_inside_and_outside_targets`; `yarn_lock::{deep_declared_yarn_workspaces_are_direct_but_arbitrary_manifests_are_ignored,missing_and_malformed_yarn_manifests_keep_directness_unknown,proven_yarn_directness_survives_an_unreadable_workspace_manifest,symlinked_root_manifest_cannot_prove_yarn_directness}`; `yaml_lock_safety::{pnpm_v9_importers_bind_exact_alias_peer_and_version_coordinates,pnpm_v6_importers_bind_only_exact_resolved_coordinates,pnpm_without_importer_evidence_does_not_guess_from_manifests,pnpm_dev_scope_requires_a_package_field_or_exact_importer_evidence}`; process `{npm_direct_only_uses_lock_edges_and_retains_unbound_unknowns,no_dev_retains_pnpm_packages_with_unknown_scope}` |
| DS-059 | `cargo_manifest::{binds_cargo_directness_and_scope_to_exact_locked_graph_identities,parses_legacy_root_and_compact_cargo_dependency_references,incomplete_project_identity_keeps_the_aggregate_graph_unknown,unverified_path_declaration_cannot_assign_known_development_scope,duplicate_workspace_member_identity_fails_before_graph_classification,replacement_edges_keep_scope_unknown_and_reach_replacement_children,normalizes_lock_sources_with_cargo_url_semantics,rejects_ambiguous_dangling_duplicate_and_malformed_cargo_lock_graphs,prefers_lockfile_and_marks_renamed_workspace_dependencies_direct}`; process `cargo_filters_use_exact_locked_identities_and_retain_unknowns`; repaired Cargo config/E2E graph controls |
| DS-060 | `requirements::{root_and_parent_replacements_cannot_redirect_capability_reads,final_file_replacements_at_open_and_read_boundaries_fail_closed,detects_hardlink_alias_cycles_by_open_file_identity,preserves_absolute_includes_spelled_through_the_scan_root_alias,follows_only_intermediate_symlinks_that_remain_inside_the_root_capability,resolves_nested_contained_symlink_to_sibling_through_root_capability,rejects_intermediate_symlink_escape_without_reading_outside_bytes}` plus process `requirements_file_swap_exits_ten_before_cache_or_provider_access`; native Linux/Windows runtime remains pending |
| DS-061 | installer environment-handoff guards, installed/override argument-vector probes, PATH decoy rejection, and a native Windows workspace-executable decoy regression |
| DS-062 | provider `registry_path_segment_encoding_preserves_only_rfc3986_unreserved_bytes`, `registry_request_paths_encode_scoped_npm_and_pypi_names_exactly`, `nuget_flat_and_registration_request_paths_encode_package_names_exactly`, `nuget_registration_page_prefix_encodes_the_package_segment_exactly`, and existing registration origin/prefix confinement; stable/MSRV 418-pass suites; reverse-tree proof that only transitive `pep508_rs` retains `urlencoding` while providers directly use `percent-encoding`; five-crate package verification |
| DS-063 | `npm_minimatch::{matches_all_extglob_operators,follows_npm_empty_extglob_and_dot_boundaries,follows_component_local_utf16_and_unicode_regexp_modes,rejects_minimatch_invalid_unicode_escapes_and_empty_quantifiers,preserves_resource_bounds_after_extglob_lowering,matches_checked_in_npm11_differential_corpus}`; 1,794 checked npm booleans plus 38 rejection classifications; `lock_schema_validation::parses_npm11_mixed_negative_extglob_workspace_fixture`; process `npm_extglob_workspace_fixture_accepts_real_link_and_rejects_forged_nonmatches`; optional npm 11 verifier |
| DS-064 | core `file_identity::{retained_handle_identity_distinguishes_replacement_files,retained_handle_identity_matches_a_hard_link_alias,borrowed_and_owned_constructors_identify_the_same_handle,windows_identity_compares_all_file_id_bytes,unsupported_platform_fails_closed}`; CLI `secure_fs::{config_regular_file_replacement_is_denied_or_detected,output_regular_file_replacement_is_denied_or_detected_before_publication}`; provider `cache_sentinel_regular_replacement_is_denied_or_detected` plus `capability_relative_offline_reads_reject_root_child_and_final_name_swaps`; native Linux/Windows runtime remains pending |

## Platform and external evidence boundary

The Rust tests are portable and the `quality` job executes them on Ubuntu, macOS, and Windows. A local run on one operating system proves only that native host. Likewise, the ignored live suite and tag/release acceptance prove external service and artifact state only when their GitHub jobs actually run. Closing evidence must name the hosts/jobs that executed; workflow presence alone is not recorded as a successful Windows, Linux, scheduled-live, or release run.
