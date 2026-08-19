use chrono::{NaiveDate, Utc};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, shells};
use depscan_core::{
    Ecosystem, EnrichError, Package, ScanDocument, ScanResult, Severity, Staleness,
    VersionProvider, VulnProvider,
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
use tracing::{error, warn};
use tracing_subscriber::EnvFilter;

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
    #[arg(long)]
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
    expires: Option<NaiveDate>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
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
            Ok(0)
        }
        None => scan(cli.default_scan).await,
    };
    match code {
        Ok(0) => ExitCode::SUCCESS,
        Ok(value) => ExitCode::from(value as u8),
        Err(error) => {
            error!("{error}");
            ExitCode::from(30)
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

async fn scan(args: ScanArgs) -> Result<i32, String> {
    if !args.path.is_dir() {
        return Err(format!("{} is not a directory", args.path.display()));
    }
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
    validate_threshold(fail_on, true)?;
    validate_threshold(fail_outdated, false)?;
    let cli_ignores: HashSet<String> = args.ignore.iter().cloned().collect();
    let mut configured_ignores = HashSet::new();
    for ignored in config.ignores {
        if ignored
            .expires
            .is_some_and(|date| date < Utc::now().date_naive())
        {
            warn!(id = %ignored.id, reason = ?ignored.reason, "ignore has expired and will not be applied");
        } else {
            configured_ignores.insert(ignored.id);
        }
    }
    let allowed = parse_ecosystems(&args.ecosystems)?;
    let parsers = ParserSet::default();
    let sources = parsers.detect(&args.path, &allowed);
    if sources.is_empty() {
        return Ok(20);
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
            Err(error) => return Err(error.to_string()),
        }
    }
    packages.retain(|p| (!args.no_dev || !p.dev) && (!args.direct_only || p.direct));
    packages = dedup_packages(packages);
    if packages.is_empty() {
        return Ok(20);
    }
    let cache = Cache::new(CachePolicy {
        read: !args.no_cache,
        max_age: args
            .max_cache_age
            .as_deref()
            .map(parse_duration)
            .transpose()?,
    })
    .map_err(|e| e.to_string())?;
    let http = HttpClient::new().map_err(|e| e.to_string())?;
    let vulnerabilities = if args.offline {
        OsvOffline::new(cache.clone())
            .query(&packages)
            .await
            .map_err(|e| e.to_string())?
    } else {
        OsvClient::new(http.clone(), cache.clone())
            .query(&packages)
            .await
            .map_err(|e| e.to_string())?
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
            let ignored = cli_ignores.contains(&v.id)
                || configured_ignores.contains(&v.id)
                || v.aliases
                    .iter()
                    .any(|id| cli_ignores.contains(id) || configured_ignores.contains(id));
            if ignored {
                suppressed.push(v.id.clone());
                false
            } else {
                true
            }
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
    let document = ScanDocument::new(results);
    let format = determine_format(&args)?;
    let use_color = matches!(format, OutputFormat::Table)
        && std::env::var_os("NO_COLOR").is_none()
        && args.output.is_none();
    let content = render(&document, format, use_color).map_err(|e| e.to_string())?;
    if let Some(path) = args.output {
        fs::write(&path, content).map_err(|e| format!("writing {}: {e}", path.display()))?;
    } else {
        print!("{content}");
    }
    if has_vulnerability_failure(&document, fail_on) {
        Ok(1)
    } else if has_outdated_failure(&document, fail_outdated) {
        Ok(2)
    } else {
        Ok(0)
    }
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

fn load_config(root: &Path, explicit: Option<&Path>) -> Result<Config, String> {
    let path = explicit
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join("depscan.toml"));
    if !path.exists() {
        return Ok(Config::default());
    }
    let text =
        fs::read_to_string(&path).map_err(|e| format!("reading config {}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("invalid config {}: {e}", path.display()))
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
        .any(|l| l.staleness >= min)
}
fn dedup_packages(mut packages: Vec<Package>) -> Vec<Package> {
    packages.sort_by_key(Package::key);
    packages.dedup_by(|a, b| a.key() == b.key());
    packages
}

async fn sync(args: SyncArgs) -> Result<i32, String> {
    let ecosystems = parse_ecosystems(&args.ecosystems)?;
    let cache = Cache::new(CachePolicy {
        read: !args.no_cache,
        max_age: None,
    })
    .map_err(|e| e.to_string())?;
    let http = HttpClient::new().map_err(|e| e.to_string())?;
    let paths = sync_osv_dumps(&http, &cache, &ecosystems.into_iter().collect::<Vec<_>>())
        .await
        .map_err(|e| e.to_string())?;
    for path in paths {
        println!("synced {}", path.display());
    }
    Ok(0)
}
fn cache_command(args: CacheArgs) -> Result<i32, String> {
    let cache = Cache::new(CachePolicy::default()).map_err(|e| e.to_string())?;
    match args.command {
        CacheCommand::Clear => {
            cache.clear().map_err(|e| e.to_string())?;
            println!("cache cleared: {}", cache.root().display());
        }
        CacheCommand::Stats => {
            let stats = cache.stats().map_err(|e| e.to_string())?;
            println!(
                "cache: {} files, {} bytes ({})",
                stats.files,
                stats.bytes,
                cache.root().display()
            );
        }
        CacheCommand::Path => println!("{}", cache.root().display()),
    }
    Ok(0)
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
