use crate::{
    Totals,
    formatting::{
        latest_requires_action, result_sort_key, severity_label, staleness_label,
        suppression_source_label,
    },
};
use depscan_core::{ScanDocument, ScanResult, SuppressionState};
use std::{cmp::Reverse, fmt::Write};

pub fn render_markdown(document: &ScanDocument) -> String {
    let totals = Totals::from_document(document);
    let mut text = format!(
        "# depscan report\n\n_Gedank Rayze DepScan, v{}, [{}]({})_\n\n",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_REPOSITORY"),
        env!("CARGO_PKG_REPOSITORY"),
    );
    writeln!(
        text,
        "Generated: `{}`\n",
        document.generated_at.to_rfc3339()
    )
    .expect("write Markdown heading");
    write_summary(&mut text, &totals);
    write_vulnerabilities(&mut text, document);
    write_dependency_status(&mut text, document);
    write_suppressions(&mut text, document);
    write_soft_failures(&mut text, document);
    text
}

fn write_summary(text: &mut String, totals: &Totals) {
    text.push_str("## Summary\n\n| Metric | Count |\n|---|---:|\n");
    for (label, count) in [
        ("Packages", totals.packages),
        ("Vulnerable packages", totals.vulnerable),
        ("Vulnerabilities", totals.vulns),
        ("Withdrawn advisories", totals.withdrawn),
        ("Outdated packages", totals.outdated),
        ("Yanked packages", totals.yanked),
        ("Suppressed findings", totals.suppressed),
        ("Expired ignores", totals.expired_ignores),
        ("Soft failures", totals.errors),
    ] {
        writeln!(text, "| {label} | {count} |").expect("write Markdown summary");
    }
    text.push('\n');
}

fn write_vulnerabilities(text: &mut String, document: &ScanDocument) {
    text.push_str("## Vulnerabilities\n\n");
    let results = risk_order(document);
    if !results.iter().any(|result| !result.vulns.is_empty()) {
        text.push_str("_None._\n\n");
        return;
    }
    text.push_str(
        "| Ecosystem | Package | Installed | Severity | Advisory | Aliases | Fixed in | Status | Summary |\n\
         |---|---|---|---|---|---|---|---|---|\n",
    );
    for result in results {
        for vulnerability in &result.vulns {
            let severity = severity_label(
                vulnerability
                    .severity
                    .unwrap_or(depscan_core::Severity::Unknown),
                false,
            );
            let status = if vulnerability.withdrawn {
                "Withdrawn"
            } else {
                "Active"
            };
            writeln!(
                text,
                "| {} | {} | {} | {} | {} | {} | {} | {status} | {} |",
                cell(result.package.ecosystem.display_name()),
                cell(&result.package.display_name),
                cell(&result.package.version),
                cell(&severity),
                cell(&vulnerability.id),
                cell_list(&vulnerability.aliases),
                cell_list(&vulnerability.fixed_in),
                cell(&vulnerability.summary),
            )
            .expect("write Markdown vulnerability");
        }
    }
    text.push('\n');
}

fn write_dependency_status(text: &mut String, document: &ScanDocument) {
    text.push_str("## Dependency status\n\n");
    let results = risk_order(document);
    let relevant = results.into_iter().filter(|result| {
        result.package.manifest_constraint.is_some()
            || result.latest.as_ref().is_some_and(latest_requires_action)
    });
    let mut wrote_header = false;
    for result in relevant {
        let latest = result.latest.as_ref();
        if !wrote_header {
            text.push_str(
                "| Ecosystem | Package | Declared or installed | Matching release | Latest stable | Status |\n\
                 |---|---|---|---|---|---|\n",
            );
            wrote_header = true;
        }
        let declared = result
            .package
            .manifest_constraint
            .as_ref()
            .map_or(result.package.version.as_str(), |constraint| {
                constraint.raw()
            });
        let matching = match (&result.package.manifest_constraint, latest) {
            (Some(_), Some(latest)) => latest.latest_matching.as_deref().unwrap_or("None"),
            (Some(_), None) => "Unknown",
            (None, _) => "—",
        };
        let latest_stable = latest.map_or("Unknown", |latest| latest.latest_stable.as_str());
        let status = dependency_status(result);
        writeln!(
            text,
            "| {} | {} | {} | {} | {} | {} |",
            cell(result.package.ecosystem.display_name()),
            cell(&result.package.display_name),
            cell(declared),
            cell(matching),
            cell(latest_stable),
            cell(&status),
        )
        .expect("write Markdown dependency status");
    }
    if !wrote_header {
        text.push_str("_None._\n");
    }
    text.push('\n');
}

fn dependency_status(result: &ScanResult) -> String {
    let Some(latest) = result.latest.as_ref() else {
        return "Unresolved".to_owned();
    };
    let mut status = Vec::new();
    if latest.yanked {
        status.push("Yanked".to_owned());
    }
    if latest.staleness > depscan_core::Staleness::Current {
        status.push(format!(
            "{} update",
            staleness_label(latest.staleness, false).to_ascii_lowercase()
        ));
    }
    if result.package.manifest_constraint.is_some() {
        status.push(
            if latest.latest_matching.is_some() {
                "Resolved"
            } else {
                "No matching release"
            }
            .to_owned(),
        );
    }
    status.join(", ")
}

fn write_suppressions(text: &mut String, document: &ScanDocument) {
    text.push_str("## Suppressions\n\n");
    if !document
        .results
        .iter()
        .any(|result| !result.suppressed.is_empty())
    {
        text.push_str("_None._\n\n");
        return;
    }
    text.push_str(
        "| State | Package | Advisory | Matched ID | Source | Reason | Expires |\n\
         |---|---|---|---|---|---|---|\n",
    );
    for result in &document.results {
        for finding in &result.suppressed {
            for matched in &finding.matches {
                let state = match matched.state {
                    SuppressionState::Active => "Active",
                    SuppressionState::Expired => "Expired",
                };
                writeln!(
                    text,
                    "| {state} | {} | {} | {} | {} | {} | {} |",
                    cell(&result.package.display_name),
                    cell(&finding.vulnerability.id),
                    cell(&matched.matched_id),
                    cell(suppression_source_label(matched.source)),
                    cell(matched.reason.as_deref().unwrap_or("—")),
                    cell(
                        &matched
                            .expires
                            .map_or_else(|| "—".to_owned(), |date| date.to_string())
                    ),
                )
                .expect("write Markdown suppression");
            }
        }
    }
    text.push('\n');
}

fn write_soft_failures(text: &mut String, document: &ScanDocument) {
    text.push_str("## Soft failures\n\n");
    if !document
        .results
        .iter()
        .any(|result| !result.errors.is_empty())
    {
        text.push_str("_None._\n");
        return;
    }
    text.push_str("| Provider | Package | Message |\n|---|---|---|\n");
    for result in &document.results {
        for error in &result.errors {
            writeln!(
                text,
                "| {} | {} | {} |",
                cell(&error.provider),
                cell(&result.package.display_name),
                cell(&error.message),
            )
            .expect("write Markdown soft failure");
        }
    }
}

fn risk_order(document: &ScanDocument) -> Vec<&ScanResult> {
    let mut results = document.results.iter().collect::<Vec<_>>();
    results.sort_by_key(|result| Reverse(result_sort_key(result)));
    results
}

fn cell_list(values: &[String]) -> String {
    if values.is_empty() {
        "—".to_owned()
    } else {
        cell(&values.join(", "))
    }
}

fn cell(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '|' => escaped.push_str("&#124;"),
            '\\' => escaped.push_str("&#92;"),
            '`' => escaped.push_str("&#96;"),
            '*' => escaped.push_str("&#42;"),
            '_' => escaped.push_str("&#95;"),
            '[' => escaped.push_str("&#91;"),
            ']' => escaped.push_str("&#93;"),
            '(' => escaped.push_str("&#40;"),
            ')' => escaped.push_str("&#41;"),
            '!' => escaped.push_str("&#33;"),
            '#' => escaped.push_str("&#35;"),
            '~' => escaped.push_str("&#126;"),
            '\n' => escaped.push_str("<br>"),
            '\r' => {}
            '\t' => escaped.push_str("&#9;"),
            control if control.is_control() => escaped.push('\u{fffd}'),
            safe => escaped.push(safe),
        }
    }
    escaped
}

#[cfg(test)]
mod tests;
