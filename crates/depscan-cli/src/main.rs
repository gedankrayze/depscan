use chrono::{DateTime, NaiveDate, Utc};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum, error::ErrorKind};
use clap_complete::{generate, shells};
use depscan_core::{
    Ecosystem, EnrichError, Package, ScanDocument, ScanResult, Severity, Staleness,
    SuppressedFinding, SuppressionMatch, SuppressionSource, SuppressionState, VersionProvider,
    VulnProvider, Vulnerability,
};
use depscan_parsers::ParserSet;
use depscan_providers::{
    Cache, CachePolicy, HttpClient, OsvClient, OsvOffline, RegistryClient, sync_osv_dumps,
};
use depscan_report::{OutputFormat, render};
use futures::{StreamExt, stream};
use serde::Deserialize;
use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
    process::ExitCode,
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
    arg_required_else_help = false
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    default_scan: ScanArgs,
}
#[derive(Subcommand, Debug)]
enum Command {
    Scan(ScanArgs),
    Sync(SyncArgs),
    Cache(CacheArgs),
    Completions {
        #[arg(value_enum)]
        shell: CompletionShell,
    },
}
#[derive(Clone, Debug, Args)]
struct ScanArgs {
    #[arg(value_name = "PATH", default_value = ".")]
    path: PathBuf,
    #[arg(short = 'e', long = "ecosystem", value_name = "ECOSYSTEM")]
    ecosystems: Vec<String>,
    #[arg(long)]
    no_dev: bool,
    #[arg(long)]
    direct_only: bool,
    #[arg(short = 'f', long, value_name = "FORMAT")]
    format: Option<String>,
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
    #[arg(long)]
    fail_on: Option<String>,
    #[arg(long)]
    fail_on_outdated: Option<String>,
    #[arg(long)]
    offline: bool,
    #[arg(long)]
    no_cache: bool,
    #[arg(long)]
    max_cache_age: Option<String>,
    #[arg(long)]
    include_withdrawn: bool,
    #[arg(long)]
    ignore: Vec<String>,
    #[arg(
        long,
        value_name = "FILE",
        help = "Configuration file (must be a readable regular file; symbolic links are rejected)"
    )]
    config: Option<PathBuf>,
    #[arg(long)]
    allow_tools: bool,
    #[arg(short = 'q', long, action = clap::ArgAction::Count)]
    quiet: u8,
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}
#[derive(Debug, Args)]
struct SyncArgs {
    #[arg(short = 'e', long = "ecosystem")]
    ecosystems: Vec<String>,
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
    Clear,
    Stats,
    Path,
}
#[derive(Clone, ValueEnum, Debug)]
enum CompletionShell {
    Bash,
    Elvish,
    Fish,
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
    let fail_on = args
        .fail_on
        .as_deref()
        .or(config.fail_on.as_deref())
        .unwrap_or("high");
    let fail_outdated = args
        .fail_on_outdated
        .as_deref()
        .or(config.fail_on_outdated.as_deref())
        .unwrap_or("never");
    validate_threshold(fail_on, true).map_err(CliError::usage)?;
    validate_threshold(fail_outdated, false).map_err(CliError::usage)?;
    let max_cache_age = args
        .max_cache_age
        .as_deref()
        .map(parse_duration)
        .transpose()
        .map_err(CliError::usage)?;
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
    let allowed = parse_ecosystems(&args.ecosystems).map_err(CliError::usage)?;
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
fn parse_ecosystems(values: &[String]) -> Result<HashSet<Ecosystem>, String> {
    values
        .iter()
        .map(|v| {
            Ecosystem::from_cli(v)
                .ok_or_else(|| format!("unknown ecosystem '{v}'; expected npm|pypi|nuget|cargo"))
        })
        .collect()
}
fn validate_threshold(value: &str, vulnerability: bool) -> Result<(), String> {
    let valid = if vulnerability {
        ["critical", "high", "medium", "low", "any", "never"].contains(&value)
    } else {
        ["major", "minor", "patch", "never"].contains(&value)
    };
    valid
        .then_some(())
        .ok_or_else(|| format!("invalid threshold '{value}'"))
}
fn parse_duration(value: &str) -> Result<chrono::Duration, String> {
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| format!("duration '{value}' requires a unit"))?;
    let amount: i64 = value[..split]
        .parse()
        .map_err(|_| format!("invalid duration '{value}'"))?;
    match &value[split..] {
        "s" => Ok(chrono::Duration::seconds(amount)),
        "m" => Ok(chrono::Duration::minutes(amount)),
        "h" => Ok(chrono::Duration::hours(amount)),
        "d" => Ok(chrono::Duration::days(amount)),
        _ => Err(format!("invalid duration unit in '{value}'; use s|m|h|d")),
    }
}
fn determine_format(args: &ScanArgs) -> Result<OutputFormat, String> {
    args.format
        .as_deref()
        .map(|v| OutputFormat::parse(v).ok_or_else(|| format!("unknown format '{v}'")))
        .transpose()?
        .or_else(|| args.output.as_deref().and_then(OutputFormat::infer))
        .or_else(|| {
            if std::io::IsTerminal::is_terminal(&io::stdout()) {
                Some(OutputFormat::Table)
            } else {
                Some(OutputFormat::Summary)
            }
        })
        .ok_or_else(|| "could not infer output format".to_owned())
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
fn has_vulnerability_failure(document: &ScanDocument, threshold: &str) -> bool {
    let min = match threshold {
        "never" => return false,
        "any" => Severity::Unknown,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => return false,
    };
    document
        .results
        .iter()
        .flat_map(|r| &r.vulns)
        .any(|v| v.severity.unwrap_or(Severity::Unknown) >= min)
}
fn has_outdated_failure(document: &ScanDocument, threshold: &str) -> bool {
    let min = match threshold {
        "never" => return false,
        "patch" => Staleness::Patch,
        "minor" => Staleness::Minor,
        "major" => Staleness::Major,
        _ => return false,
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
    let ecosystems = parse_ecosystems(&args.ecosystems).map_err(CliError::usage)?;
    let cache = Cache::new(CachePolicy {
        read: !args.no_cache,
        max_age: None,
    })
    .map_err(CliError::provider)?;
    let http = HttpClient::new().map_err(CliError::provider)?;
    let paths = sync_osv_dumps(&http, &cache, &ecosystems.into_iter().collect::<Vec<_>>())
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
