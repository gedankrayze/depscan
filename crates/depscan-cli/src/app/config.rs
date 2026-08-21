use super::*;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(super) struct Config {
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
pub(super) struct IgnoreConfig {
    pub(super) id: String,
    pub(super) reason: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_date")]
    pub(super) expires: Option<NaiveDate>,
}

#[derive(Debug)]
pub(super) struct ConfigOrigin {
    pub(super) path: PathBuf,
    pub(super) origin: &'static str,
    pub(super) loaded: bool,
}

impl ConfigOrigin {
    pub(super) fn log(&self) {
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
pub(super) struct LoadedConfig {
    pub(super) value: Config,
    pub(super) origin: ConfigOrigin,
}

#[derive(Debug)]
pub(super) struct PreparedScan {
    pub(super) args: ScanArgs,
    pub(super) format: OutputFormat,
    pub(super) fail_on: VulnerabilityThreshold,
    pub(super) fail_on_outdated: OutdatedThreshold,
    pub(super) configured_ignores: Vec<IgnoreConfig>,
    pub(super) config_origin: ConfigOrigin,
    pub(super) implicit_config_output: Option<PathBuf>,
    pub(super) confined_output: Option<ConfinedOutput>,
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
pub(super) struct SuppressionRule {
    pub(super) id: String,
    pub(super) source: SuppressionSource,
    pub(super) reason: Option<String>,
    pub(super) expires: Option<NaiveDate>,
    pub(super) state: SuppressionState,
}

pub(super) fn prepare_scan(args: ScanArgs) -> Result<PreparedScan, CliError> {
    let scan_root = ScanRoot::open(&args.path).map_err(|error| {
        CliError::usage(format!(
            "{} is not a directory: {error}",
            args.path.display()
        ))
    })?;
    let loaded = load_config(&scan_root, args.config.as_deref())?;
    // Emitted while resolution happens; visible when the CLI itself asked for verbosity.
    // Config-set verbosity takes effect from the scan phase onward via the filter reload.
    loaded.origin.log();
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

pub(super) fn merge_scan_config(
    mut args: ScanArgs,
    loaded: LoadedConfig,
) -> Result<PreparedScan, CliError> {
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
pub(super) fn parse_ecosystems(values: &[EcosystemArg]) -> HashSet<Ecosystem> {
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

pub(super) fn parse_sync_timeout(value: &str) -> Result<StdDuration, String> {
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
                "could not infer output format from {}; use --format table|markdown|json|sarif|summary",
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
