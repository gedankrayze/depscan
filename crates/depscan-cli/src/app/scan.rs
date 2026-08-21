use super::*;

fn bun_manifest_only(path: &Path, reason: &str) -> Result<Vec<Package>, CliError> {
    let packages = parse_bun_manifest_fallback(path).map_err(|manifest_error| {
        CliError::usage(format!(
            "cannot extract dependencies from binary Bun lockfile {} ({reason}); manifest-only fallback also failed: {manifest_error}",
            path.display()
        ))
    })?;
    warn!(
        lockfile = %path.display(),
        reason,
        "Bun lockfile extraction unavailable; scanning package.json constraints in degraded manifest-only mode"
    );
    Ok(packages)
}

async fn parse_bun_source(path: &Path, allow_tools: bool) -> Result<Vec<Package>, CliError> {
    if !allow_tools {
        return bun_manifest_only(path, "external tool execution was not authorized");
    }
    match external_tools::parse_bun_binary_lock(path).await {
        Ok(packages) => Ok(packages),
        Err(error) if error.is_pre_execution_failure() => {
            bun_manifest_only(path, &error.to_string())
        }
        Err(error) => Err(CliError::usage(error.to_string())),
    }
}

pub(super) async fn scan(prepared: PreparedScan) -> Result<AppExit, CliError> {
    let PreparedScan {
        args,
        format,
        fail_on,
        fail_on_outdated,
        configured_ignores,
        config_origin: _,
        implicit_config_output: _,
        confined_output,
    } = prepared;
    let generated_at = scan_timestamp()?;
    let max_cache_age = args.max_cache_age.map(|age| age.0);
    let mut suppression_rules = args
        .ignore
        .iter()
        .map(|id| SuppressionRule {
            id: id.clone(),
            source: SuppressionSource::Cli,
            reason: None,
            expires: None,
            state: SuppressionState::Active,
        })
        .collect::<Vec<_>>();
    for ignored in configured_ignores {
        let state = if ignored
            .expires
            .is_some_and(|date| date < generated_at.date_naive())
        {
            warn!(id = %ignored.id, reason = ?ignored.reason, "ignore has expired and will not be applied");
            SuppressionState::Expired
        } else {
            SuppressionState::Active
        };
        suppression_rules.push(SuppressionRule {
            id: ignored.id,
            source: SuppressionSource::Config,
            reason: ignored.reason,
            expires: ignored.expires,
            state,
        });
    }
    suppression_rules.sort();
    suppression_rules.dedup();
    let allowed = parse_ecosystems(&args.ecosystems);
    let parsers = ParserSet::default();
    let sources = parsers.detect(&args.path, &allowed);
    if sources.is_empty() {
        return Err(CliError::NoSupportedProject(args.path));
    }
    let mut packages = Vec::new();
    for source in sources {
        let mut parsed = match &source.kind {
            depscan_core::SourceKind::BunLockBinary => {
                parse_bun_source(&source.path, args.allow_tools).await?
            }
            depscan_core::SourceKind::ProjectFile if args.allow_tools => {
                external_tools::parse_dotnet_project(&source.path, args.offline)
                    .await
                    .map_err(|error| CliError::usage(error.to_string()))?
            }
            _ => parsers
                .parse(&source)
                .map_err(|error| CliError::usage(error.to_string()))?,
        };
        packages.append(&mut parsed);
    }
    packages = consolidate_packages(packages, args.no_dev, args.direct_only);
    if packages.is_empty() {
        return Err(CliError::NoSupportedProject(args.path));
    }
    let cache = Cache::new(CachePolicy {
        read: !args.no_cache,
        max_age: max_cache_age,
    })
    .map_err(CliError::provider)?;
    let (vulnerability_outcome, freshness) = if args.offline {
        let registry = RegistryOffline::new(cache.clone());
        let freshness = fetch_latest(&registry, &packages, true).await;
        let plan = VulnerabilityQueryPlan::new(&packages, &freshness, OsvIdentityPolicy::Offline);
        reject_totally_unresolved_plan(&plan)?;
        let vulnerabilities = OsvOffline::new(cache)
            .query(plan.packages())
            .await
            .map_err(CliError::provider)?;
        (plan.remap(vulnerabilities), freshness)
    } else {
        let http = HttpClient::new().map_err(CliError::provider)?;
        let registry = RegistryClient::new(http.clone(), cache.clone());
        let freshness = fetch_latest(&registry, &packages, false).await;
        let plan = VulnerabilityQueryPlan::new(&packages, &freshness, OsvIdentityPolicy::Online);
        reject_totally_unresolved_plan(&plan)?;
        let vulnerabilities = OsvClient::new(http, cache)
            .query(plan.packages())
            .await
            .map_err(CliError::provider)?;
        (plan.remap(vulnerabilities), freshness)
    };
    let vulnerabilities = vulnerability_outcome.vulnerabilities;
    let mut vulnerability_errors = vulnerability_outcome.errors;
    let mut results = Vec::new();
    for package in packages {
        let package_key = package.key();
        let mut vulns = vulnerabilities
            .get(&package_key)
            .cloned()
            .unwrap_or_default();
        if !args.include_withdrawn {
            vulns.retain(|v| !v.withdrawn);
        }
        let mut suppressed = Vec::new();
        vulns.retain(|v| {
            let matches = suppression_matches(v, &suppression_rules);
            if matches.is_empty() {
                return true;
            }
            let active = matches
                .iter()
                .any(|matched| matched.state == SuppressionState::Active);
            suppressed.push(SuppressedFinding {
                vulnerability: v.clone(),
                active,
                matches,
            });
            !active
        });
        let (enrichment, mut errors) = freshness
            .get(&package_key)
            .cloned()
            .unwrap_or((None, Vec::new()));
        let latest = enrichment.map(|enrichment| enrichment.latest);
        errors.extend(
            vulnerability_errors
                .remove(&package_key)
                .unwrap_or_default(),
        );
        results.push(ScanResult {
            package,
            vulns,
            latest,
            errors,
            suppressed,
        });
    }
    let document = ScanDocument::at(results, generated_at);
    let use_color = matches!(format, OutputFormat::Table)
        && std::env::var_os("NO_COLOR").is_none()
        && args.output.is_none();
    let content = render(&document, format, use_color)
        .map_err(|e| CliError::usage(format!("rendering report: {e}")))?;
    if let Some(destination) = confined_output {
        destination
            .write(content.as_bytes())
            .map_err(|error| CliError::usage(error.to_string()))?;
    } else if let Some(path) = args.output {
        fs::write(&path, content)
            .map_err(|e| CliError::usage(format!("writing {}: {e}", path.display())))?;
    } else {
        write_stdout(content.as_bytes())?;
    }
    if has_vulnerability_failure(&document, fail_on) {
        Ok(AppExit::Vulnerabilities)
    } else if has_outdated_failure(&document, fail_on_outdated) {
        Ok(AppExit::Outdated)
    } else {
        Ok(AppExit::Clean)
    }
}

fn reject_totally_unresolved_plan(plan: &VulnerabilityQueryPlan) -> Result<(), CliError> {
    let Some(count) = plan.totally_unresolved_count() else {
        return Ok(());
    };
    Err(CliError::provider(format!(
        "registry metadata did not resolve any of {count} enrichable manifest dependencies to a concrete version for OSV"
    )))
}

fn suppression_matches(
    vulnerability: &Vulnerability,
    rules: &[SuppressionRule],
) -> Vec<SuppressionMatch> {
    let mut matches = rules
        .iter()
        .filter_map(|rule| {
            let matched_id = if rule.id == vulnerability.id {
                vulnerability.id.as_str()
            } else {
                vulnerability
                    .aliases
                    .iter()
                    .find(|alias| alias.as_str() == rule.id)?
            };
            Some(SuppressionMatch {
                matched_id: matched_id.to_owned(),
                source: rule.source,
                reason: rule.reason.clone(),
                expires: rule.expires,
                state: rule.state,
            })
        })
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    matches
}

fn scan_timestamp() -> Result<DateTime<Utc>, CliError> {
    let value = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(Utc::now()),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(CliError::usage(
                "SOURCE_DATE_EPOCH must be a UTF-8 integer number of seconds since the Unix epoch",
            ));
        }
    };
    let seconds = value.parse::<i64>().map_err(|_| {
        CliError::usage(
            "SOURCE_DATE_EPOCH must be an integer number of seconds since the Unix epoch",
        )
    })?;
    let timestamp = DateTime::<Utc>::from_timestamp(seconds, 0).ok_or_else(|| {
        CliError::usage("SOURCE_DATE_EPOCH is outside the supported UTC timestamp range")
    })?;
    debug!(%timestamp, "reproducible scan timestamp selected from SOURCE_DATE_EPOCH");
    Ok(timestamp)
}

// Scan-level enrichment concurrency; per-ecosystem provider semaphores throttle further below.
const MAX_CONCURRENT_ENRICHMENTS: usize = 64;

async fn fetch_latest<P>(
    registry: &P,
    packages: &[Package],
    unknown_on_error: bool,
) -> std::collections::HashMap<String, (Option<RegistryEnrichment>, Vec<EnrichError>)>
where
    P: VersionProvider + Clone,
{
    stream::iter(
        packages
            .iter()
            .filter(|p| p.enrichable)
            .cloned()
            .map(|package| {
                let registry = (*registry).clone();
                async move {
                    let key = package.key();
                    match registry.latest(&package).await {
                        Ok(latest) => (key, (Some(latest), vec![])),
                        Err(error) => (
                            key,
                            (
                                unknown_on_error.then(|| {
                                    RegistryEnrichment::versions_only(LatestVersions::unknown())
                                }),
                                vec![EnrichError {
                                    provider: "registry".to_owned(),
                                    message: error.to_string(),
                                }],
                            ),
                        ),
                    }
                }
            }),
    )
    .buffer_unordered(MAX_CONCURRENT_ENRICHMENTS)
    .collect()
    .await
}
