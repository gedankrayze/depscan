use chrono::{DateTime, Duration, NaiveDate, Utc};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum, error::ErrorKind};
use clap_complete::{generate, shells};
use depscan_core::{
    Ecosystem, EnrichError, Package, ScanDocument, ScanResult, Severity, Staleness,
    SuppressedFinding, SuppressionMatch, SuppressionSource, SuppressionState, VersionProvider,
    VulnProvider, Vulnerability,
};
use depscan_parsers::ParserSet;
use depscan_providers::{
    Cache, CachePolicy, HttpClient, OsvClient, OsvOffline, OsvSyncOptions, RegistryClient,
    sync_osv_dumps_with_options,
};
use depscan_report::{OutputFormat, render};
use futures::{StreamExt, stream};
use serde::Deserialize;
use std::{
    collections::HashSet,
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
    after_long_help = "Exit status:\n  0  scan completed below both failure thresholds\n  1  vulnerability at or above --fail-on (takes precedence over 2)\n  2  outdated or yanked dependency at or above --fail-on-outdated\n 10  command-line or configuration error\n 20  no supported project or dependency was detected\n 30  provider hard failure without a usable fallback",
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
        after_long_help = "Exit status:\n  0  scan completed below both failure thresholds\n  1  vulnerability at or above --fail-on (takes precedence over 2)\n  2  outdated or yanked dependency at or above --fail-on-outdated\n 10  command-line or configuration error\n 20  no supported project or dependency was detected\n 30  provider hard failure without a usable fallback"
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
    /// Disable network access; require locally synced OSV dumps and skip registry freshness lookups.
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
        help = "Read configuration from FILE; CLI failure thresholds win and ignore lists combine",
        long_help = "Read configuration from FILE instead of PATH/depscan.toml. FILE must be a readable regular file; symbolic links are rejected. Command-line failure thresholds take precedence over configured thresholds, while ignore rules are combined. Ignore reasons are included in reports, so they must not contain secrets."
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
struct Config {
    #[serde(rename = "fail-on")]
    fail_on: Option<String>,
    #[serde(rename = "fail-on-outdated")]
    fail_on_outdated: Option<String>,
    #[serde(default, rename = "ignore")]
    ignores: Vec<IgnoreConfig>,
}
#[derive(Debug, Deserialize)]
struct IgnoreConfig {
    id: String,
    reason: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_date")]
    expires: Option<NaiveDate>,
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
    let level = match &cli.command {
        Some(Command::Scan(args)) => log_level(args),
        None => log_level(&cli.default_scan),
        _ => "warn",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(level))
        .with_writer(io::stderr)
        .init();
    let code = match cli.command {
        Some(Command::Scan(args)) => scan(args).await,
        Some(Command::Sync(args)) => sync(args).await,
        Some(Command::Cache(args)) => cache_command(args),
        Some(Command::Completions { shell }) => {
            completions(shell);
            Ok(AppExit::Clean)
        }
        None => scan(cli.default_scan).await,
    };
    match code {
        Ok(exit) => exit.into(),
        Err(error) => {
            error!("{error}");
            error.exit_code()
        }
    }
}
fn log_level(args: &ScanArgs) -> &'static str {
    if args.quiet > 0 {
        "error"
    } else if args.verbose > 0 {
        "debug"
    } else {
        "warn"
    }
}

async fn scan(args: ScanArgs) -> Result<AppExit, CliError> {
    if !args.path.is_dir() {
        return Err(CliError::usage(format!(
            "{} is not a directory",
            args.path.display()
        )));
    }
    let generated_at = scan_timestamp()?;
    let config = load_config(&args.path, args.config.as_deref())?;
    let fail_on = args.fail_on.map_or_else(
        || {
            config
                .fail_on
                .as_deref()
                .map_or(Ok(VulnerabilityThreshold::High), |value| {
                    parse_config_threshold(value, "fail-on")
                })
        },
        Ok,
    )?;
    let fail_outdated = args.fail_on_outdated.map_or_else(
        || {
            config
                .fail_on_outdated
                .as_deref()
                .map_or(Ok(OutdatedThreshold::Never), |value| {
                    parse_config_threshold(value, "fail-on-outdated")
                })
        },
        Ok,
    )?;
    let max_cache_age = args.max_cache_age.map(|age| age.0);
    let format = determine_format(&args).map_err(CliError::usage)?;
    validate_output_path(args.output.as_deref())?;
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
    for ignored in config.ignores {
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
    packages.retain(|p| (!args.no_dev || !p.dev) && (!args.direct_only || p.direct));
    packages = dedup_packages(packages);
    if packages.is_empty() {
        return Err(CliError::NoSupportedProject(args.path));
    }
    let cache = Cache::new(CachePolicy {
        read: !args.no_cache,
        max_age: max_cache_age,
    })
    .map_err(CliError::provider)?;
    let http = HttpClient::new().map_err(CliError::provider)?;
    let vulnerabilities = if args.offline {
        OsvOffline::new(cache.clone())
            .query(&packages)
            .await
            .map_err(CliError::provider)?
    } else {
        OsvClient::new(http.clone(), cache.clone())
            .query(&packages)
            .await
            .map_err(CliError::provider)?
    };
    let registry = RegistryClient::new(http, cache);
    let freshness = if args.offline {
        std::collections::HashMap::new()
    } else {
        fetch_latest(&registry, &packages).await
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
    if let Some(path) = args.output {
        fs::write(&path, content)
            .map_err(|e| CliError::usage(format!("writing {}: {e}", path.display())))?;
    } else {
        print!("{content}");
    }
    if has_vulnerability_failure(&document, fail_on) {
        Ok(AppExit::Vulnerabilities)
    } else if has_outdated_failure(&document, fail_outdated) {
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

async fn fetch_latest(
    registry: &RegistryClient,
    packages: &[Package],
) -> std::collections::HashMap<String, (Option<depscan_core::LatestVersions>, Vec<EnrichError>)> {
    let sem = std::sync::Arc::new(Semaphore::new(64));
    stream::iter(
        packages
            .iter()
            .filter(|p| p.enrichable)
            .cloned()
            .map(|package| {
                let registry = registry.clone();
                let sem = sem.clone();
                async move {
                    let _permit = sem.acquire().await.expect("semaphore closes only on drop");
                    let key = package.key();
                    match registry.latest(&package).await {
                        Ok(latest) => (key, (Some(latest), vec![])),
                        Err(error) => (
                            key,
                            (
                                None,
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

fn load_config(root: &Path, explicit: Option<&Path>) -> Result<Config, CliError> {
    let (path, origin) = explicit.map_or_else(
        || (root.join("depscan.toml"), "implicit-default"),
        |path| (path.to_path_buf(), "explicit"),
    );
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound && explicit.is_none() => {
            debug!(
                path = %path.display(),
                origin,
                "configuration file not found; using defaults"
            );
            return Ok(Config::default());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(CliError::usage(format!(
                "config {} does not exist",
                path.display()
            )));
        }
        Err(error) => {
            return Err(CliError::usage(format!(
                "inspecting config {}: {error}",
                path.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(CliError::usage(format!(
            "config {} is a symbolic link; configuration symlinks are not allowed",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(CliError::usage(format!(
            "config {} is not a regular file",
            path.display()
        )));
    }
    let text = fs::read_to_string(&path)
        .map_err(|e| CliError::usage(format!("reading config {}: {e}", path.display())))?;
    let config = toml::from_str(&text)
        .map_err(|e| CliError::usage(format!("invalid config {}: {e}", path.display())))?;
    debug!(path = %path.display(), origin, "configuration loaded");
    Ok(config)
}
fn parse_ecosystems(values: &[EcosystemArg]) -> HashSet<Ecosystem> {
    values.iter().copied().map(Ecosystem::from).collect()
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
fn dedup_packages(mut packages: Vec<Package>) -> Vec<Package> {
    packages.sort_by_key(Package::key);
    packages.dedup_by(|a, b| a.key() == b.key());
    packages
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
