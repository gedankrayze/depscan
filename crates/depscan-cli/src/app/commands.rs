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
