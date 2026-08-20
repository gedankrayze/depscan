use crate::formatting::suppression_match_details;
use depscan_core::{ScanDocument, ScanResult, Severity, SuppressionState, Vulnerability};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub fn render_sarif(document: &ScanDocument) -> Value {
    let mut rules = BTreeMap::<String, Value>::new();
    let mut results = Vec::new();
    for result in &document.results {
        for vuln in &result.vulns {
            insert_vulnerability_rule(&mut rules, vuln);
            results.push(sarif_vulnerability_result(result, vuln));
        }
        for finding in &result.suppressed {
            if finding.active {
                insert_vulnerability_rule(&mut rules, &finding.vulnerability);
                let mut sarif_result = sarif_vulnerability_result(result, &finding.vulnerability);
                let active_matches = finding
                    .matches
                    .iter()
                    .filter(|matched| matched.state == SuppressionState::Active)
                    .collect::<Vec<_>>();
                sarif_result
                    .as_object_mut()
                    .expect("result is an object")
                    .insert(
                        "suppressions".to_owned(),
                        json!([{
                            "kind": "external",
                            "status": "accepted",
                            "justification": active_matches
                                .iter()
                                .map(|matched| suppression_match_details(matched))
                                .collect::<Vec<_>>()
                                .join("; ")
                        }]),
                    );
                sarif_result
                    .get_mut("properties")
                    .and_then(Value::as_object_mut)
                    .expect("result properties are an object")
                    .extend([
                        ("suppressed".to_owned(), json!(true)),
                        ("suppression_matches".to_owned(), json!(finding.matches)),
                    ]);
                results.push(sarif_result);
            }
            for matched in finding
                .matches
                .iter()
                .filter(|matched| matched.state == SuppressionState::Expired)
            {
                let rule_id = "DEPSCAN-EXPIRED-SUPPRESSION";
                rules.entry(rule_id.to_owned()).or_insert_with(|| {
                    json!({
                        "id": rule_id,
                        "shortDescription": {
                            "text": "Expired dependency suppression no longer applies"
                        }
                    })
                });
                results.push(json!({
                    "ruleId": rule_id,
                    "level": "warning",
                    "message": {"text": format!(
                        "Expired suppression {} did not suppress {} {} affected by {} ({})",
                        matched.matched_id,
                        result.package.display_name,
                        result.package.version,
                        finding.vulnerability.id,
                        suppression_match_details(matched)
                    )},
                    "locations": [{"physicalLocation": {"artifactLocation": {
                        "uri": result.package.source_file.to_string_lossy()
                    }}}],
                    "properties": {
                        "ecosystem": result.package.ecosystem.osv_name(),
                        "package": result.package.name,
                        "version": result.package.version,
                        "vulnerability": finding.vulnerability.id,
                        "suppression_match": matched
                    }
                }));
            }
        }
        if let Some(latest) = &result.latest
            && latest.yanked
        {
            let rule_id = "DEPSCAN-YANKED";
            rules.entry(rule_id.to_owned()).or_insert_with(|| json!({
                "id": rule_id,
                "shortDescription": {"text": "Installed dependency version is yanked or deprecated"}
            }));
            results.push(json!({
                "ruleId": rule_id,
                "level": "warning",
                "message": {"text": format!(
                    "{} {} is yanked or deprecated; latest non-yanked stable version is {}",
                    result.package.display_name,
                    result.package.version,
                    latest.latest_stable
                )},
                "locations": [{"physicalLocation": {"artifactLocation": {
                    "uri": result.package.source_file.to_string_lossy()
                }}}],
                "properties": {
                    "ecosystem": result.package.ecosystem.osv_name(),
                    "package": result.package.name,
                    "version": result.package.version,
                    "latest_stable": latest.latest_stable,
                    "staleness": latest.staleness,
                    "yanked": true
                }
            }));
        }
        for error in &result.errors {
            let rule_id = "DEPSCAN-PROVIDER-ERROR";
            rules.entry(rule_id.to_owned()).or_insert_with(|| {
                json!({
                    "id": rule_id,
                    "shortDescription": {
                        "text": "Dependency enrichment was incomplete"
                    }
                })
            });
            results.push(json!({
                "ruleId": rule_id,
                "level": "warning",
                "message": {"text": format!(
                    "{} {} could not be fully enriched by {}: {}",
                    result.package.display_name,
                    result.package.version,
                    error.provider,
                    error.message
                )},
                "locations": [{"physicalLocation": {"artifactLocation": {
                    "uri": result.package.source_file.to_string_lossy()
                }}}],
                "properties": {
                    "ecosystem": result.package.ecosystem.osv_name(),
                    "package": result.package.name,
                    "version": result.package.version,
                    "provider": error.provider,
                    "soft_failure": true
                }
            }));
        }
    }
    json!({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "depscan", "informationUri": "https://github.com/gedankrayze/depscan", "rules": rules.into_values().collect::<Vec<_>>() }}, "results": results}]})
}

fn insert_vulnerability_rule(rules: &mut BTreeMap<String, Value>, vulnerability: &Vulnerability) {
    rules.entry(vulnerability.id.clone()).or_insert_with(|| {
        json!({
            "id": vulnerability.id,
            "shortDescription": {"text": vulnerability.summary},
            "helpUri": vulnerability.references.first()
        })
    });
}

fn sarif_vulnerability_result(result: &ScanResult, vulnerability: &Vulnerability) -> Value {
    let withdrawn = if vulnerability.withdrawn {
        " (withdrawn advisory)"
    } else {
        ""
    };
    json!({
        "ruleId": vulnerability.id,
        "level": vulnerability.severity.unwrap_or(Severity::Unknown).sarif_level(),
        "message": {"text": format!(
            "{} {} is affected by {}{withdrawn}: {}",
            result.package.display_name,
            result.package.version,
            vulnerability.id,
            vulnerability.summary
        )},
        "locations": [{"physicalLocation": {"artifactLocation": {
            "uri": result.package.source_file.to_string_lossy()
        }}}],
        "properties": {
            "ecosystem": result.package.ecosystem.osv_name(),
            "package": result.package.name,
            "version": result.package.version,
            "fixed_in": vulnerability.fixed_in,
            "withdrawn": vulnerability.withdrawn
        }
    })
}
