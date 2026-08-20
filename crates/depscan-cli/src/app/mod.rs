use crate::{
    external_tools,
    secure_fs::{ConfinedOutput, ScanRoot, read_config_nofollow},
    vulnerability_resolution::{OsvIdentityPolicy, VulnerabilityQueryPlan},
};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum, error::ErrorKind};
use clap_complete::{generate, shells};
use depscan_core::{
    Ecosystem, EnrichError, LatestVersions, Package, RegistryEnrichment, ScanDocument, ScanResult,
    Severity, Staleness, SuppressedFinding, SuppressionMatch, SuppressionSource, SuppressionState,
    VersionProvider, VulnProvider, Vulnerability,
};
use depscan_parsers::{ParserSet, parse_bun_manifest_fallback};
use depscan_providers::{
    Cache, CachePolicy, HttpClient, OsvClient, OsvOffline, OsvSyncOptions, RegistryClient,
    RegistryOffline, sync_osv_dumps_with_options,
};
use depscan_report::{OutputFormat, render};
use futures::{StreamExt, stream};
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
mod commands;
mod config;
mod policy;
mod scan;

use commands::*;
use config::*;
use policy::*;
use scan::*;

#[cfg(test)]
mod tests;

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
    Markdown,
    Json,
    Sarif,
    Summary,
}

impl From<ReportFormat> for OutputFormat {
    fn from(value: ReportFormat) -> Self {
        match value {
            ReportFormat::Table => Self::Table,
            ReportFormat::Markdown => Self::Markdown,
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
        long_help = "Permit Bun binary-lock extraction and .NET transitive JSON enumeration. Without authorization, a legacy bun.lockb degrades to root/workspace package.json constraints with a warning; --allow-tools attempts to recover its resolved versions. This may execute bun or dotnet with fixed arguments in an attacker-controlled checkout; commands use a minimized environment, bounded output, and a 10-second timeout. Offline dotnet enumeration disables restore. Leave this disabled unless that execution is acceptable."
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

pub(crate) async fn run() -> ExitCode {
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
