mod secure_fs;

use chrono::{DateTime, Duration, NaiveDate, Utc};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum, error::ErrorKind};
use clap_complete::{generate, shells};
use depscan_core::{
    Ecosystem, EnrichError, LatestVersions, Package, ScanDocument, ScanResult, Severity, Staleness,
    SuppressedFinding, SuppressionMatch, SuppressionSource, SuppressionState, VersionProvider,
    VulnProvider, Vulnerability,
};
use depscan_parsers::ParserSet;
use depscan_providers::{
    Cache, CachePolicy, HttpClient, OsvClient, OsvOffline, OsvSyncOptions, RegistryClient,
    RegistryOffline, sync_osv_dumps_with_options,
};
use depscan_report::{OutputFormat, render};
use futures::{StreamExt, stream};
use secure_fs::{ConfinedOutput, ScanRoot, read_config_nofollow};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashSet},
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    time::Duration as StdDuration,
};
use tokio::sync::Semaphore;
use tracing::{debug, error, warn};
use tracing_subscriber::EnvFilter;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum AppExit {
    Clean = 0,
    Vulnerabilities = 1,
    Outdated = 2,
}

impl From<AppExit> for ExitCode {
    fn from(value: AppExit) -> Self {
        ExitCode::from(value as u8)
    }
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("usage/config error: {0}")]
    Usage(String),
    #[error("no supported project detected at {0}")]
    NoSupportedProject(PathBuf),
    #[error("provider hard failure: {0}")]
    Provider(String),
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self::Usage(message.into())
    }

    fn provider(error: impl ToString) -> Self {
        Self::Provider(error.to_string())
    }

    fn exit_code(&self) -> ExitCode {
        ExitCode::from(match self {
            Self::Usage(_) => 10,
            Self::NoSupportedProject(_) => 20,
            Self::Provider(_) => 30,
        })
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "depscan",
    version,
    about = "Scan dependency lockfiles for known vulnerabilities and version freshness",
    long_about = "Scan dependency lockfiles and manifests for OSV vulnerabilities, yanked releases, and newer stable versions. By default depscan auto-detects every supported ecosystem in the current directory, writes a human summary to non-interactive stdout, and uses the network plus its local cache.",
    after_long_help = "Configuration:\n  PATH/depscan.toml is loaded by default; --config selects another regular file.\n  CLI scalar values win; present enable-only switches set true. CLI --ecosystem values replace\n  the configured list; CLI --ignore values combine with configured ignore rules. Configured\n  relative output paths resolve from PATH, and implicit config output is validated inside PATH.\n  An implicit project config cannot self-enable allow-tools; pass --allow-tools or explicitly\n  select a trusted config containing allow-tools=true.\n\nExit status:\n  0  scan completed below both failure thresholds\n  1  vulnerability at or above --fail-on (takes precedence over 2)\n  2  outdated or yanked dependency at or above --fail-on-outdated\n 10  command-line or configuration error\n 20  no supported project or dependency was detected\n 30  provider hard failure without a usable fallback",
    arg_required_else_help = false
)]
struct Cli {
    /// Run an explicit command. With no command, the scan options below scan PATH.
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    default_scan: ScanArgs,
}
#[derive(Subcommand, Debug)]
enum Command {
    /// Scan one project directory (the default command).
    #[command(
        after_long_help = "Configuration:\n  PATH/depscan.toml is loaded by default; --config selects another regular file.\n  CLI scalar values win; present enable-only switches set true. CLI --ecosystem values replace\n  the configured list; CLI --ignore values combine with configured ignore rules. Configured\n  relative output paths resolve from PATH, and implicit config output is validated inside PATH.\n  An implicit project config cannot self-enable allow-tools; pass --allow-tools or explicitly\n  select a trusted config containing allow-tools=true.\n\nExit status:\n  0  scan completed below both failure thresholds\n  1  vulnerability at or above --fail-on (takes precedence over 2)\n  2  outdated or yanked dependency at or above --fail-on-outdated\n 10  command-line or configuration error\n 20  no supported project or dependency was detected\n 30  provider hard failure without a usable fallback"
    )]
    Scan(ScanArgs),
    /// Download or refresh OSV dumps used by offline scans.
    Sync(SyncArgs),
    /// Inspect or safely clear the depscan-owned cache.
    Cache(CacheArgs),
    /// Generate a shell completion script on stdout.
    Completions {
        /// Shell whose completion syntax should be generated.
        #[arg(value_enum)]
        shell: CompletionShell,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum EcosystemArg {
    #[value(aliases(["node", "bun"]))]
    Npm,
    #[value(name = "pypi", aliases(["python"]))]
    PyPi,
    #[value(name = "nuget", aliases(["dotnet", ".net"]))]
    NuGet,
    #[value(name = "cargo", aliases(["crates", "crates.io", "rust"]))]
    Cargo,
}

impl From<EcosystemArg> for Ecosystem {
    fn from(value: EcosystemArg) -> Self {
        match value {
            EcosystemArg::Npm => Self::Npm,
            EcosystemArg::PyPi => Self::PyPI,
            EcosystemArg::NuGet => Self::NuGet,
            EcosystemArg::Cargo => Self::CratesIo,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ReportFormat {
    Table,
    Json,
    Sarif,
    Summary,
}

impl From<ReportFormat> for OutputFormat {
    fn from(value: ReportFormat) -> Self {
        match value {
            ReportFormat::Table => Self::Table,
            ReportFormat::Json => Self::Json,
            ReportFormat::Sarif => Self::Sarif,
            ReportFormat::Summary => Self::Summary,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum VulnerabilityThreshold {
    Critical,
    High,
    Medium,
    Low,
    Any,
    Never,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutdatedThreshold {
    Major,
    Minor,
    Patch,
    Never,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CacheAge(Duration);

impl FromStr for CacheAge {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let split = value
            .find(|character: char| !character.is_ascii_digit())
            .ok_or_else(|| format!("duration {value:?} requires one of s, m, h, or d"))?;
        if split == 0 {
            return Err(format!(
                "duration {value:?} must start with a non-negative integer"
            ));
        }
        let amount = value[..split]
            .parse::<i64>()
            .map_err(|_| format!("duration {value:?} is outside the supported range"))?;
        let duration = match &value[split..] {
            "s" => Duration::try_seconds(amount),
            "m" => Duration::try_minutes(amount),
            "h" => Duration::try_hours(amount),
            "d" => Duration::try_days(amount),
            _ => {
                return Err(format!(
                    "duration {value:?} has an invalid unit; use values such as 30m, 24h, or 7d"
                ));
            }
        }
        .ok_or_else(|| format!("duration {value:?} is outside the supported range"))?;
        Ok(Self(duration))
    }
}

#[derive(Clone, Debug, Args)]
struct ScanArgs {
    /// Project directory to inspect recursively.
    #[arg(value_name = "PATH", default_value = ".")]
    path: PathBuf,
    /// Limit detection to one ecosystem. Repeat the option to select several.
    #[arg(
        short = 'e',
        long = "ecosystem",
        value_name = "ECOSYSTEM",
        value_enum,
        ignore_case = true,
        action = clap::ArgAction::Append
    )]
    ecosystems: Vec<EcosystemArg>,
    /// Exclude known development/test dependencies; entries with unknown scope are retained.
    #[arg(long)]
    no_dev: bool,
    /// Exclude known transitive dependencies; entries with unknown directness are retained.
    #[arg(long)]
    direct_only: bool,
    /// Report format. If omitted, infer from --output, then use table on a TTY or summary otherwise.
    #[arg(short = 'f', long, value_name = "FORMAT", value_enum)]
    format: Option<ReportFormat>,
    /// Write the report to FILE instead of stdout. The extension selects a format when -f is absent.
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Exit 1 when an actionable vulnerability meets this threshold. CLI overrides config; default: high.
    #[arg(long, value_name = "SEVERITY", value_enum)]
    fail_on: Option<VulnerabilityThreshold>,
    /// Exit 2 for this degree of staleness or a yanked release. CLI overrides config; default: never.
    #[arg(long, value_name = "CLASS", value_enum)]
    fail_on_outdated: Option<OutdatedThreshold>,
    /// Disable network access; require synced OSV dumps and use only acceptable cached registry data.
    #[arg(long)]
    offline: bool,
    /// Bypass reusable JSON cache reads but continue writing fresh responses. Synced offline dumps remain inputs.
    #[arg(long)]
    no_cache: bool,
    /// Set the maximum accepted cache-data age (examples: 30m, 24h, 7d).
    #[arg(long, value_name = "DURATION")]
    max_cache_age: Option<CacheAge>,
    /// Include withdrawn OSV advisories in reports and failure evaluation.
    #[arg(long)]
    include_withdrawn: bool,
    /// Suppress an advisory ID or alias. Repeat for multiple IDs; configuration ignores are combined.
    #[arg(long, value_name = "ID", action = clap::ArgAction::Append)]
    ignore: Vec<String>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Read configuration from FILE; CLI settings win and ignore lists combine",
        long_help = "Read configuration from FILE instead of PATH/depscan.toml. FILE must be a readable regular file; symbolic links are rejected. Command-line scalar values take precedence; a present enable-only switch sets true. Command-line ecosystem values replace the configured list, while ignore rules are combined. Relative configured output paths resolve from PATH; implicit config output must remain within PATH. Ignore reasons are included in reports, so they must not contain secrets. Explicitly selecting a trusted config containing allow-tools=true authorizes package-manager execution; an implicit project config cannot self-authorize it."
    )]
    config: Option<PathBuf>,
    /// Permit explicitly supported package-manager fallbacks.
    #[arg(
        long,
        long_help = "Permit explicitly supported package-manager fallbacks. This may execute bun or dotnet while scanning an attacker-controlled checkout; leave disabled for untrusted projects unless that execution is acceptable."
    )]
    allow_tools: bool,
    /// Reduce diagnostics. Repeatable; conflicts with --verbose. Reports still use stdout or --output.
    #[arg(
        short = 'q',
        long,
        action = clap::ArgAction::Count,
        conflicts_with = "verbose"
    )]
    quiet: u8,
    /// Increase diagnostic detail. Repeatable; conflicts with --quiet. Logs always use stderr.
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}
#[derive(Debug, Args)]
struct SyncArgs {
    /// Limit synchronization to one ecosystem. Repeat to select several; default: all ecosystems.
    #[arg(
        short = 'e',
        long = "ecosystem",
        value_name = "ECOSYSTEM",
        value_enum,
        ignore_case = true,
        action = clap::ArgAction::Append
    )]
    ecosystems: Vec<EcosystemArg>,
    /// Bound each dump transfer attempt while retaining the 10-second connect/read-idle deadline.
    #[arg(
        long,
        value_name = "DURATION",
        default_value = "15m",
        value_parser = parse_sync_timeout
    )]
    transfer_timeout: StdDuration,
    /// Bypass reusable JSON cache reads; selected OSV dumps are always downloaded and written.
    #[arg(long)]
    no_cache: bool,
}
#[derive(Debug, Args)]
struct CacheArgs {
    #[command(subcommand)]
    command: CacheCommand,
}
#[derive(Debug, Subcommand)]
enum CacheCommand {
    /// Remove only known content from a validated depscan-owned cache.
    Clear,
    /// Show the number and total size of cached files.
    Stats,
    /// Print the canonical cache directory path.
    Path,
}
#[derive(Clone, Copy, ValueEnum, Debug)]
enum CompletionShell {
    Bash,
    Elvish,
    Fish,
    #[value(name = "powershell", alias = "power-shell")]
    PowerShell,
    Zsh,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct Config {
    #[serde(rename = "ecosystem")]
    ecosystems: Option<Vec<String>>,
    no_dev: Option<bool>,
    direct_only: Option<bool>,
    format: Option<String>,
    output: Option<PathBuf>,
    fail_on: Option<String>,
    fail_on_outdated: Option<String>,
    offline: Option<bool>,
    no_cache: Option<bool>,
    max_cache_age: Option<String>,
    include_withdrawn: Option<bool>,
    #[serde(default, rename = "ignore")]
    ignores: Vec<IgnoreConfig>,
    allow_tools: Option<bool>,
    quiet: Option<u8>,
    verbose: Option<u8>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IgnoreConfig {
    id: String,
    reason: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_date")]
    expires: Option<NaiveDate>,
}

#[derive(Debug)]
struct ConfigOrigin {
    path: PathBuf,
    origin: &'static str,
    loaded: bool,
}

impl ConfigOrigin {
    fn log(&self) {
        if self.loaded {
            debug!(path = %self.path.display(), origin = self.origin, "configuration loaded");
        } else {
            debug!(
                path = %self.path.display(),
                origin = self.origin,
                "configuration file not found; using defaults"
            );
        }
    }
}

#[derive(Debug)]
struct LoadedConfig {
    value: Config,
    origin: ConfigOrigin,
}

#[derive(Debug)]
struct PreparedScan {
    args: ScanArgs,
    format: OutputFormat,
    fail_on: VulnerabilityThreshold,
    fail_on_outdated: OutdatedThreshold,
    configured_ignores: Vec<IgnoreConfig>,
    config_origin: ConfigOrigin,
    implicit_config_output: Option<PathBuf>,
    confined_output: Option<ConfinedOutput>,
}

fn deserialize_optional_date<'de, D>(deserializer: D) -> Result<Option<NaiveDate>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<toml::Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    let raw = match value {
        toml::Value::String(value) => value,
        toml::Value::Datetime(value) => value.to_string(),
        other => {
            return Err(serde::de::Error::custom(format!(
                "expected a TOML date or YYYY-MM-DD string, found {other}"
            )));
        }
    };
    NaiveDate::parse_from_str(&raw, "%Y-%m-%d")
        .map(Some)
        .map_err(|_| serde::de::Error::custom(format!("invalid suppression expiry date {raw:?}")))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SuppressionRule {
    id: String,
    source: SuppressionSource,
    reason: Option<String>,
    expires: Option<NaiveDate>,
    state: SuppressionState,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(parse_error) => {
            let informational = matches!(
                parse_error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            let _ = parse_error.print();
            return if informational {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(10)
            };
        }
    };
    match cli.command {
        Some(Command::Scan(args)) => run_scan(args).await,
        None => run_scan(cli.default_scan).await,
        Some(command) => run_non_scan(command).await,
    }
}

async fn run_scan(args: ScanArgs) -> ExitCode {
    let prepared = match prepare_scan(args) {
        Ok(prepared) => prepared,
        Err(error) => {
            eprintln!("{error}");
            return error.exit_code();
        }
    };
    initialize_tracing(log_level(prepared.args.quiet, prepared.args.verbose));
    prepared.config_origin.log();
    finish(scan(prepared).await)
}

async fn run_non_scan(command: Command) -> ExitCode {
    initialize_tracing("warn");
    let code = match command {
        Command::Scan(_) => {
            unreachable!("scan commands are prepared before tracing initialization")
        }
        Command::Sync(args) => sync(args).await,
        Command::Cache(args) => cache_command(args),
        Command::Completions { shell } => {
            completions(shell);
            Ok(AppExit::Clean)
        }
    };
    finish(code)
}

fn initialize_tracing(level: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(level))
        .with_writer(io::stderr)
        .init();
}

fn finish(code: Result<AppExit, CliError>) -> ExitCode {
    match code {
        Ok(exit) => exit.into(),
        Err(error) => {
            error!("{error}");
            error.exit_code()
        }
    }
}

fn log_level(quiet: u8, verbose: u8) -> &'static str {
    if quiet > 0 {
        "error"
    } else if verbose > 0 {
        "debug"
    } else {
        "warn"
    }
}

async fn scan(prepared: PreparedScan) -> Result<AppExit, CliError> {
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
        match parsers.parse(&source) {
            Ok(mut parsed) => packages.append(&mut parsed),
            Err(error)
                if args.allow_tools
                    && matches!(source.kind, depscan_core::SourceKind::BunLockBinary) =>
            {
                warn!(
                    "{}; automatic binary lockfile extraction is not currently available",
                    error
                );
            }
            Err(error) => return Err(CliError::usage(error.to_string())),
        }
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
    let (vulnerabilities, freshness) = if args.offline {
        let vulnerabilities = OsvOffline::new(cache.clone())
            .query(&packages)
            .await
            .map_err(CliError::provider)?;
        let registry = RegistryOffline::new(cache);
        let freshness = fetch_latest(&registry, &packages, true).await;
        (vulnerabilities, freshness)
    } else {
        let http = HttpClient::new().map_err(CliError::provider)?;
        let vulnerabilities = OsvClient::new(http.clone(), cache.clone())
            .query(&packages)
            .await
            .map_err(CliError::provider)?;
        let registry = RegistryClient::new(http, cache);
        let freshness = fetch_latest(&registry, &packages, false).await;
        (vulnerabilities, freshness)
    };
    let mut results = Vec::new();
    for package in packages {
        let mut vulns = vulnerabilities
            .get(&package.key())
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
        let (latest, errors) = freshness
            .get(&package.key())
            .cloned()
            .unwrap_or((None, Vec::new()));
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
        print!("{content}");
    }
    if has_vulnerability_failure(&document, fail_on) {
        Ok(AppExit::Vulnerabilities)
    } else if has_outdated_failure(&document, fail_on_outdated) {
        Ok(AppExit::Outdated)
    } else {
        Ok(AppExit::Clean)
    }
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

async fn fetch_latest<P>(
    registry: &P,
    packages: &[Package],
    unknown_on_error: bool,
) -> std::collections::HashMap<String, (Option<LatestVersions>, Vec<EnrichError>)>
where
    P: VersionProvider + Clone,
{
    let sem = std::sync::Arc::new(Semaphore::new(64));
    stream::iter(
        packages
            .iter()
            .filter(|p| p.enrichable)
            .cloned()
            .map(|package| {
                let registry = (*registry).clone();
                let sem = sem.clone();
                async move {
                    let _permit = sem.acquire().await.expect("semaphore closes only on drop");
                    let key = package.key();
                    match registry.latest(&package).await {
                        Ok(latest) => (key, (Some(latest), vec![])),
                        Err(error) => (
                            key,
                            (
                                unknown_on_error.then(LatestVersions::unknown),
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
    .buffer_unordered(64)
    .collect()
    .await
}

fn prepare_scan(args: ScanArgs) -> Result<PreparedScan, CliError> {
    let scan_root = ScanRoot::open(&args.path).map_err(|error| {
        CliError::usage(format!(
            "{} is not a directory: {error}",
            args.path.display()
        ))
    })?;
    let loaded = load_config(&scan_root, args.config.as_deref())?;
    let mut prepared = merge_scan_config(args, loaded)?;
    if let Some(configured) = prepared.implicit_config_output.as_deref() {
        let output = prepared
            .args
            .output
            .as_deref()
            .expect("implicit configured output has an effective output path");
        prepared.confined_output = Some(
            ConfinedOutput::prepare(scan_root, configured, output)
                .map_err(|error| CliError::usage(error.to_string()))?,
        );
    } else {
        validate_output_path(prepared.args.output.as_deref())?;
    }
    Ok(prepared)
}

fn merge_scan_config(mut args: ScanArgs, loaded: LoadedConfig) -> Result<PreparedScan, CliError> {
    let explicit_config = args.config.is_some();
    let Config {
        ecosystems,
        no_dev,
        direct_only,
        format,
        output,
        fail_on,
        fail_on_outdated,
        offline,
        no_cache,
        max_cache_age,
        include_withdrawn,
        ignores,
        allow_tools,
        quiet,
        verbose,
    } = loaded.value;

    let configured_ecosystems = ecosystems
        .map(|values| parse_config_values::<EcosystemArg>(&values, "ecosystem", true))
        .transpose()?;
    let configured_format = format
        .as_deref()
        .map(|value| parse_config_value::<ReportFormat>(value, "format", false))
        .transpose()?;
    let configured_fail_on = fail_on
        .as_deref()
        .map(|value| parse_config_threshold(value, "fail-on"))
        .transpose()?;
    let configured_fail_on_outdated = fail_on_outdated
        .as_deref()
        .map(|value| parse_config_threshold(value, "fail-on-outdated"))
        .transpose()?;
    let configured_max_cache_age = max_cache_age
        .as_deref()
        .map(|value| {
            value.parse::<CacheAge>().map_err(|error| {
                CliError::usage(format!(
                    "invalid config value {value:?} for max-cache-age: {error}"
                ))
            })
        })
        .transpose()?;

    let configured_quiet = quiet.unwrap_or(0);
    let configured_verbose = verbose.unwrap_or(0);
    if configured_quiet > 0 && configured_verbose > 0 {
        return Err(CliError::usage(
            "config quiet and verbose cannot both be greater than zero",
        ));
    }

    if args.ecosystems.is_empty()
        && let Some(values) = configured_ecosystems
    {
        args.ecosystems = values;
    }
    args.no_dev = args.no_dev || no_dev.unwrap_or(false);
    args.direct_only = args.direct_only || direct_only.unwrap_or(false);
    if args.format.is_none() {
        args.format = configured_format;
    }
    let configured_output_selected = args.output.is_none() && output.is_some();
    let configured_output = output.clone();
    if args.output.is_none()
        && let Some(configured) = output
    {
        args.output = Some(if configured.is_absolute() {
            configured
        } else {
            args.path.join(configured)
        });
    }
    let fail_on = args
        .fail_on
        .or(configured_fail_on)
        .unwrap_or(VulnerabilityThreshold::High);
    let fail_on_outdated = args
        .fail_on_outdated
        .or(configured_fail_on_outdated)
        .unwrap_or(OutdatedThreshold::Never);
    args.offline = args.offline || offline.unwrap_or(false);
    args.no_cache = args.no_cache || no_cache.unwrap_or(false);
    if args.max_cache_age.is_none() {
        args.max_cache_age = configured_max_cache_age;
    }
    args.include_withdrawn = args.include_withdrawn || include_withdrawn.unwrap_or(false);
    let configured_allow_tools = allow_tools.unwrap_or(false);
    if configured_allow_tools && !args.allow_tools && !explicit_config {
        return Err(CliError::usage(
            "implicit project config cannot enable allow-tools; pass --allow-tools or select a trusted file with --config",
        ));
    }
    args.allow_tools = args.allow_tools || (explicit_config && configured_allow_tools);
    if args.quiet == 0 && args.verbose == 0 {
        args.quiet = configured_quiet;
        args.verbose = configured_verbose;
    }
    let format = determine_format(&args).map_err(CliError::usage)?;

    Ok(PreparedScan {
        args,
        format,
        fail_on,
        fail_on_outdated,
        configured_ignores: ignores,
        config_origin: loaded.origin,
        implicit_config_output: if configured_output_selected && !explicit_config {
            configured_output
        } else {
            None
        },
        confined_output: None,
    })
}

fn load_config(root: &ScanRoot, explicit: Option<&Path>) -> Result<LoadedConfig, CliError> {
    let (path, origin, text) = if let Some(path) = explicit {
        let path = path.to_path_buf();
        let text = read_config_nofollow(&path, false)
            .map_err(|error| CliError::usage(error.to_string()))?;
        (path, "explicit", text)
    } else {
        let path = root.path().join("depscan.toml");
        let text = root
            .read_optional_config(OsStr::new("depscan.toml"), &path)
            .map_err(|error| CliError::usage(error.to_string()))?;
        (path, "implicit-default", text)
    };
    let Some(text) = text else {
        return Ok(LoadedConfig {
            value: Config::default(),
            origin: ConfigOrigin {
                path,
                origin,
                loaded: false,
            },
        });
    };
    let config = toml::from_str(&text)
        .map_err(|e| CliError::usage(format!("invalid config {}: {e}", path.display())))?;
    Ok(LoadedConfig {
        value: config,
        origin: ConfigOrigin {
            path,
            origin,
            loaded: true,
        },
    })
}
fn parse_ecosystems(values: &[EcosystemArg]) -> HashSet<Ecosystem> {
    values.iter().copied().map(Ecosystem::from).collect()
}

fn parse_config_values<T>(
    values: &[String],
    setting: &str,
    ignore_case: bool,
) -> Result<Vec<T>, CliError>
where
    T: ValueEnum + Clone,
{
    values
        .iter()
        .map(|value| parse_config_value(value, setting, ignore_case))
        .collect()
}

fn parse_config_value<T>(value: &str, setting: &str, ignore_case: bool) -> Result<T, CliError>
where
    T: ValueEnum + Clone,
{
    <T as ValueEnum>::from_str(value, ignore_case).map_err(|_| {
        let allowed = T::value_variants()
            .iter()
            .filter_map(ValueEnum::to_possible_value)
            .map(|possible| possible.get_name().to_owned())
            .collect::<Vec<_>>()
            .join("|");
        CliError::usage(format!(
            "invalid config value {value:?} for {setting}; expected {allowed}"
        ))
    })
}

fn parse_config_threshold<T>(value: &str, setting: &str) -> Result<T, CliError>
where
    T: ValueEnum + Clone,
{
    <T as ValueEnum>::from_str(value, false).map_err(|_| {
        let allowed = T::value_variants()
            .iter()
            .filter_map(ValueEnum::to_possible_value)
            .map(|possible| possible.get_name().to_owned())
            .collect::<Vec<_>>()
            .join("|");
        CliError::usage(format!(
            "invalid threshold {value:?} for {setting}; expected {allowed}"
        ))
    })
}

fn parse_sync_timeout(value: &str) -> Result<StdDuration, String> {
    let CacheAge(timeout) = value.parse()?;
    if timeout == Duration::zero() {
        return Err("sync transfer timeout must be greater than zero".to_owned());
    }
    timeout
        .to_std()
        .map_err(|_| format!("sync transfer timeout {value:?} is outside the supported range"))
}
fn determine_format(args: &ScanArgs) -> Result<OutputFormat, String> {
    if let Some(format) = args.format {
        return Ok(format.into());
    }
    if let Some(path) = args.output.as_deref() {
        return OutputFormat::infer(path).ok_or_else(|| {
            format!(
                "could not infer output format from {}; use --format table|json|sarif|summary",
                path.display()
            )
        });
    }
    Ok(if std::io::IsTerminal::is_terminal(&io::stdout()) {
        OutputFormat::Table
    } else {
        OutputFormat::Summary
    })
}
fn validate_output_path(path: Option<&Path>) -> Result<(), CliError> {
    let Some(path) = path else {
        return Ok(());
    };
    if path.is_dir() {
        return Err(CliError::usage(format!(
            "output {} is a directory",
            path.display()
        )));
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        && !parent.is_dir()
    {
        return Err(CliError::usage(format!(
            "output directory {} does not exist or is not a directory",
            parent.display()
        )));
    }
    Ok(())
}

fn has_vulnerability_failure(document: &ScanDocument, threshold: VulnerabilityThreshold) -> bool {
    let min = match threshold {
        VulnerabilityThreshold::Never => return false,
        VulnerabilityThreshold::Any => Severity::Unknown,
        VulnerabilityThreshold::Low => Severity::Low,
        VulnerabilityThreshold::Medium => Severity::Medium,
        VulnerabilityThreshold::High => Severity::High,
        VulnerabilityThreshold::Critical => Severity::Critical,
    };
    document
        .results
        .iter()
        .flat_map(|r| &r.vulns)
        .any(|v| v.severity.unwrap_or(Severity::Unknown) >= min)
}
fn has_outdated_failure(document: &ScanDocument, threshold: OutdatedThreshold) -> bool {
    let min = match threshold {
        OutdatedThreshold::Never => return false,
        OutdatedThreshold::Patch => Staleness::Patch,
        OutdatedThreshold::Minor => Staleness::Minor,
        OutdatedThreshold::Major => Staleness::Major,
    };
    document
        .results
        .iter()
        .filter_map(|r| r.latest.as_ref())
        .any(|latest| latest.yanked || latest.staleness >= min)
}
fn filter_packages(packages: &mut Vec<Package>, no_dev: bool, direct_only: bool) {
    packages.retain(|package| {
        (!no_dev || !package.dev_known || !package.dev)
            && (!direct_only || !package.direct_known || package.direct)
    });
}

fn consolidate_packages(packages: Vec<Package>, no_dev: bool, direct_only: bool) -> Vec<Package> {
    let mut packages = dedup_packages(packages);
    filter_packages(&mut packages, no_dev, direct_only);
    packages
}

fn dedup_packages(packages: Vec<Package>) -> Vec<Package> {
    let mut merged = BTreeMap::<String, Package>::new();
    for package in packages {
        merged
            .entry(package.key())
            .and_modify(|existing| existing.merge_metadata(&package))
            .or_insert(package);
    }
    merged.into_values().collect()
}

async fn sync(args: SyncArgs) -> Result<AppExit, CliError> {
    let ecosystems = parse_ecosystems(&args.ecosystems);
    let cache = Cache::new(CachePolicy {
        read: !args.no_cache,
        max_age: None,
    })
    .map_err(CliError::provider)?;
    let http = HttpClient::new().map_err(CliError::provider)?;
    let paths = sync_osv_dumps_with_options(
        &http,
        &cache,
        &ecosystems.into_iter().collect::<Vec<_>>(),
        OsvSyncOptions {
            transfer_timeout: args.transfer_timeout,
        },
    )
    .await
    .map_err(CliError::provider)?;
    for path in paths {
        println!("synced {}", path.display());
    }
    Ok(AppExit::Clean)
}
fn cache_command(args: CacheArgs) -> Result<AppExit, CliError> {
    let cache = Cache::new(CachePolicy::default()).map_err(CliError::provider)?;
    match args.command {
        CacheCommand::Clear => {
            cache.clear().map_err(CliError::provider)?;
            println!("cache cleared: {}", cache.root().display());
        }
        CacheCommand::Stats => {
            let stats = cache.stats().map_err(CliError::provider)?;
            println!(
                "cache: {} files, {} bytes ({})",
                stats.files,
                stats.bytes,
                cache.root().display()
            );
        }
        CacheCommand::Path => println!("{}", cache.root().display()),
    }
    Ok(AppExit::Clean)
}
fn completions(shell: CompletionShell) {
    let mut command = Cli::command();
    match shell {
        CompletionShell::Bash => generate(shells::Bash, &mut command, "depscan", &mut io::stdout()),
        CompletionShell::Elvish => {
            generate(shells::Elvish, &mut command, "depscan", &mut io::stdout())
        }
        CompletionShell::Fish => generate(shells::Fish, &mut command, "depscan", &mut io::stdout()),
        CompletionShell::PowerShell => generate(
            shells::PowerShell,
            &mut command,
            "depscan",
            &mut io::stdout(),
        ),
        CompletionShell::Zsh => generate(shells::Zsh, &mut command, "depscan", &mut io::stdout()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_args(arguments: &[&str]) -> ScanArgs {
        let cli = Cli::try_parse_from(
            std::iter::once("depscan")
                .chain(std::iter::once("scan"))
                .chain(arguments.iter().copied()),
        )
        .expect("parse scan arguments");
        match cli.command {
            Some(Command::Scan(args)) => args,
            _ => panic!("expected explicit scan command"),
        }
    }

    fn loaded_config(contents: &str, explicit: bool) -> LoadedConfig {
        LoadedConfig {
            value: toml::from_str(contents).expect("parse test config"),
            origin: ConfigOrigin {
                path: PathBuf::from("policy.toml"),
                origin: if explicit {
                    "explicit"
                } else {
                    "implicit-default"
                },
                loaded: true,
            },
        }
    }

    #[test]
    fn configuration_can_populate_the_complete_scan_surface() {
        let args = scan_args(&["--config", "policy.toml", "scan-root"]);
        let prepared = merge_scan_config(
            args,
            loaded_config(
                r#"
ecosystem = ["Cargo", "rust"]
no-dev = true
direct-only = true
format = "json"
output = "reports/audit.json"
fail-on = "medium"
fail-on-outdated = "minor"
offline = true
no-cache = true
max-cache-age = "7d"
include-withdrawn = true
allow-tools = true
quiet = 0
verbose = 2

[[ignore]]
id = "RUSTSEC-TEST"
reason = "fixture"
expires = 2099-01-01
"#,
                true,
            ),
        )
        .expect("merge complete config");

        assert_eq!(
            prepared.args.ecosystems,
            vec![EcosystemArg::Cargo, EcosystemArg::Cargo]
        );
        assert!(prepared.args.no_dev);
        assert!(prepared.args.direct_only);
        assert_eq!(prepared.args.format, Some(ReportFormat::Json));
        assert_eq!(
            prepared.args.output,
            Some(PathBuf::from("scan-root/reports/audit.json"))
        );
        assert_eq!(prepared.fail_on, VulnerabilityThreshold::Medium);
        assert_eq!(prepared.fail_on_outdated, OutdatedThreshold::Minor);
        assert!(prepared.args.offline);
        assert!(prepared.args.no_cache);
        assert_eq!(
            prepared.args.max_cache_age.map(|age| age.0),
            Duration::try_days(7)
        );
        assert!(prepared.args.include_withdrawn);
        assert!(prepared.args.allow_tools);
        assert_eq!(prepared.args.quiet, 0);
        assert_eq!(prepared.args.verbose, 2);
        assert_eq!(prepared.configured_ignores.len(), 1);
    }

    #[test]
    fn cli_groups_override_config_fieldwise() {
        let args = scan_args(&[
            "--ecosystem",
            "npm",
            "--no-dev",
            "--output",
            "cli.sarif",
            "--fail-on",
            "high",
            "--fail-on-outdated",
            "patch",
            "--offline",
            "--no-cache",
            "--max-cache-age",
            "2h",
            "--include-withdrawn",
            "--allow-tools",
            "--quiet",
            "--ignore",
            "CLI-ID",
            "scan-root",
        ]);
        let prepared = merge_scan_config(
            args,
            loaded_config(
                r#"
ecosystem = ["pypi"]
no-dev = false
direct-only = true
format = "json"
output = "configured.json"
fail-on = "never"
fail-on-outdated = "never"
offline = false
no-cache = false
max-cache-age = "30m"
include-withdrawn = false
allow-tools = false
quiet = 0
verbose = 2

[[ignore]]
id = "CONFIG-ID"
"#,
                false,
            ),
        )
        .expect("merge CLI overrides");

        assert_eq!(prepared.args.ecosystems, vec![EcosystemArg::Npm]);
        assert!(prepared.args.no_dev);
        assert!(prepared.args.direct_only);
        assert_eq!(prepared.args.format, Some(ReportFormat::Json));
        assert_eq!(prepared.format, OutputFormat::Json);
        assert_eq!(prepared.args.output, Some(PathBuf::from("cli.sarif")));
        assert_eq!(prepared.fail_on, VulnerabilityThreshold::High);
        assert_eq!(prepared.fail_on_outdated, OutdatedThreshold::Patch);
        assert!(prepared.args.offline);
        assert!(prepared.args.no_cache);
        assert_eq!(
            prepared.args.max_cache_age.map(|age| age.0),
            Duration::try_hours(2)
        );
        assert!(prepared.args.include_withdrawn);
        assert!(prepared.args.allow_tools);
        assert_eq!(prepared.args.quiet, 1);
        assert_eq!(prepared.args.verbose, 0);
        assert_eq!(prepared.args.ignore, vec!["CLI-ID"]);
        assert_eq!(prepared.configured_ignores.len(), 1);
    }

    #[test]
    fn implicit_configuration_cannot_self_authorize_external_tools() {
        let error = merge_scan_config(
            scan_args(&["scan-root"]),
            loaded_config("allow-tools = true", false),
        )
        .expect_err("implicit allow-tools must fail closed");
        assert!(error.to_string().contains("cannot enable allow-tools"));

        let prepared = merge_scan_config(
            scan_args(&["--allow-tools", "scan-root"]),
            loaded_config("allow-tools = true", false),
        )
        .expect("explicit CLI permission wins");
        assert!(prepared.args.allow_tools);
    }

    #[test]
    fn format_output_precedence_and_empty_ecosystem_policy_are_explicit() {
        let configured_output = merge_scan_config(
            scan_args(&["scan-root"]),
            loaded_config("ecosystem = []\noutput = \"report.sarif\"", false),
        )
        .expect("infer format from configured output");
        assert!(configured_output.args.ecosystems.is_empty());
        assert_eq!(configured_output.format, OutputFormat::Sarif);

        let cli_format = merge_scan_config(
            scan_args(&["--format", "summary", "scan-root"]),
            loaded_config("format = \"json\"\noutput = \"report.json\"", false),
        )
        .expect("CLI format must override configured format and output inference");
        assert_eq!(cli_format.format, OutputFormat::Summary);
        assert_eq!(
            cli_format.args.output,
            Some(PathBuf::from("scan-root/report.json"))
        );
    }

    #[test]
    fn conflicting_configured_log_settings_are_rejected_even_when_cli_is_set() {
        let error = merge_scan_config(
            scan_args(&["--quiet", "scan-root"]),
            loaded_config("quiet = 1\nverbose = 1", false),
        )
        .expect_err("conflicting config must not be silently overridden");
        assert!(error.to_string().contains("cannot both"));
    }

    #[test]
    fn package_filters_run_after_conservative_coordinate_merge() {
        let mut direct_development = Package::new(
            Ecosystem::PyPI,
            "shared",
            "1.0.0",
            PathBuf::from("development.lock"),
        );
        direct_development.direct = true;
        direct_development.dev = true;

        let transitive_production = Package::new(
            Ecosystem::PyPI,
            "shared",
            "1.0.0",
            PathBuf::from("production.lock"),
        );

        let packages =
            consolidate_packages(vec![direct_development, transitive_production], true, true);

        assert_eq!(packages.len(), 1);
        assert!(packages[0].direct);
        assert!(packages[0].direct_known);
        assert!(!packages[0].dev);
        assert!(packages[0].dev_known);
    }
}
