use depscan_core::{
    LatestVersions, ScanResult, Severity, Staleness, SuppressionMatch, SuppressionSource,
};

pub(crate) fn result_sort_key(result: &ScanResult) -> (Severity, bool, Staleness) {
    (
        result
            .vulns
            .iter()
            .map(|v| v.severity.unwrap_or(Severity::Unknown))
            .max()
            .unwrap_or(Severity::Unknown),
        result.latest.as_ref().is_some_and(|latest| latest.yanked),
        result
            .latest
            .as_ref()
            .map(|l| l.staleness)
            .unwrap_or(Staleness::Unknown),
    )
}

pub(crate) fn latest_requires_action(latest: &LatestVersions) -> bool {
    latest.yanked || latest.staleness > Staleness::Current
}
pub(crate) fn severity_label(severity: Severity, color: bool) -> String {
    let raw = match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Unknown => "UNKNOWN",
    };
    paint(
        raw,
        match severity {
            Severity::Critical | Severity::High => 31,
            Severity::Medium => 33,
            Severity::Low => 36,
            Severity::Unknown => 37,
        },
        color,
    )
}
pub(crate) fn staleness_label(staleness: Staleness, color: bool) -> String {
    let raw = match staleness {
        Staleness::Major => "MAJOR",
        Staleness::Minor => "MINOR",
        Staleness::Patch => "PATCH",
        Staleness::Current => "CURRENT",
        Staleness::Unknown => "UNKNOWN",
    };
    paint(
        raw,
        match staleness {
            Staleness::Major => 35,
            Staleness::Minor => 33,
            Staleness::Patch => 36,
            _ => 37,
        },
        color,
    )
}
pub(crate) fn paint(input: &str, code: u8, enabled: bool) -> String {
    if enabled {
        format!("\x1b[{code}m{input}\x1b[0m")
    } else {
        input.to_owned()
    }
}

fn suppression_source_label(source: SuppressionSource) -> &'static str {
    match source {
        SuppressionSource::Cli => "cli",
        SuppressionSource::Config => "config",
    }
}

pub(crate) fn suppression_match_details(matched: &SuppressionMatch) -> String {
    let mut details = vec![format!(
        "source: {}",
        suppression_source_label(matched.source)
    )];
    if let Some(reason) = &matched.reason {
        details.push(format!("reason: {reason}"));
    }
    if let Some(expires) = matched.expires {
        details.push(format!("expires: {expires}"));
    }
    details.join(", ")
}
