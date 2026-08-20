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
    let markdown_output = merge_scan_config(
        scan_args(&["scan-root"]),
        loaded_config("output = \"report.md\"", false),
    )
    .expect("infer Markdown format from configured output");
    assert_eq!(markdown_output.format, OutputFormat::Markdown);

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
