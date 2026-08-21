use super::*;

pub(super) async fn run_scan(args: ScanArgs) -> ExitCode {
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

pub(super) async fn run_non_scan(command: Command) -> ExitCode {
    initialize_tracing("warn");
    let code = match command {
        Command::Scan(_) => {
            unreachable!("scan commands are prepared before tracing initialization")
        }
        Command::Sync(args) => sync(args).await,
        Command::Cache(args) => cache_command(args),
        Command::Completions { shell } => completions(shell).map(|()| AppExit::Clean),
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

// Rust ignores SIGPIPE, so a closed stdout consumer (for example `depscan | head`) surfaces as
// a BrokenPipe write error. Suppress it and keep the scan's own exit code instead of aborting.
pub(super) fn write_stdout(bytes: &[u8]) -> Result<(), CliError> {
    use io::Write as _;
    let mut stdout = io::stdout().lock();
    match stdout.write_all(bytes).and_then(|()| stdout.flush()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
            debug!("stdout consumer closed the pipe; suppressing remaining output");
            Ok(())
        }
        Err(error) => Err(CliError::usage(format!("writing to stdout: {error}"))),
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
        write_stdout(format!("synced {}\n", path.display()).as_bytes())?;
    }
    Ok(AppExit::Clean)
}
fn cache_command(args: CacheArgs) -> Result<AppExit, CliError> {
    let cache = Cache::new(CachePolicy::default()).map_err(CliError::provider)?;
    match args.command {
        CacheCommand::Clear => {
            cache.clear().map_err(CliError::provider)?;
            write_stdout(format!("cache cleared: {}\n", cache.root().display()).as_bytes())?;
        }
        CacheCommand::Stats => {
            let stats = cache.stats().map_err(CliError::provider)?;
            write_stdout(
                format!(
                    "cache: {} files, {} bytes ({})\n",
                    stats.files,
                    stats.bytes,
                    cache.root().display()
                )
                .as_bytes(),
            )?;
        }
        CacheCommand::Path => {
            write_stdout(format!("{}\n", cache.root().display()).as_bytes())?;
        }
    }
    Ok(AppExit::Clean)
}
fn completions(shell: CompletionShell) -> Result<(), CliError> {
    let mut command = Cli::command();
    let mut script = Vec::new();
    match shell {
        CompletionShell::Bash => generate(shells::Bash, &mut command, "depscan", &mut script),
        CompletionShell::Elvish => generate(shells::Elvish, &mut command, "depscan", &mut script),
        CompletionShell::Fish => generate(shells::Fish, &mut command, "depscan", &mut script),
        CompletionShell::PowerShell => {
            generate(shells::PowerShell, &mut command, "depscan", &mut script)
        }
        CompletionShell::Zsh => generate(shells::Zsh, &mut command, "depscan", &mut script),
    }
    write_stdout(&script)
}
