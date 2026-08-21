use super::*;

#[cfg(test)]
pub(crate) fn vulnerability_from_osv(
    doc: &Value,
    package: Option<&Package>,
) -> Result<Option<Vulnerability>, ProviderError> {
    vulnerability_from_osv_with_match_policy(doc, package, false)
}

pub(crate) fn vulnerability_from_osv_query_hit(
    doc: &Value,
    package: &Package,
) -> Result<Option<Vulnerability>, ProviderError> {
    vulnerability_from_osv_with_match_policy(doc, Some(package), true)
}

pub(crate) fn vulnerability_from_osv_with_match_policy(
    doc: &Value,
    package: Option<&Package>,
    require_matching_affected: bool,
) -> Result<Option<Vulnerability>, ProviderError> {
    let document = validate_osv_document(doc, None)?;
    vulnerability_from_validated_osv(doc, &document, package, require_matching_affected)
}

pub(crate) fn vulnerability_from_validated_osv(
    doc: &Value,
    document: &ValidatedOsvDocument<'_>,
    package: Option<&Package>,
    require_matching_affected: bool,
) -> Result<Option<Vulnerability>, ProviderError> {
    if let Some(package) = package {
        let mut matching = document
            .affected
            .iter()
            .filter(|affected| affected_matches_package(affected, package));
        let first = matching.next();
        let evaluable = first
            .into_iter()
            .chain(matching)
            .any(affected_entry_is_evaluable);
        if !evaluable && (require_matching_affected || first.is_some()) {
            let source = if require_matching_affected {
                "OSV query hit"
            } else {
                "OSV advisory"
            };
            return Err(ProviderError::InvalidResponse(format!(
                "{source} {} has no matching evaluable affected entry for {} {}",
                document.id, package.display_name, package.version
            )));
        }
    }
    let score = osv_cvss_score(doc, package);
    let evaluation = package
        .map(|package| {
            evaluate_osv_affected(package, document.affected).map_err(|error| {
                ProviderError::InvalidResponse(format!(
                    "OSV advisory {} cannot be evaluated for {} {}: {error}",
                    document.id, package.display_name, package.version
                ))
            })
        })
        .transpose()?;
    if evaluation.as_ref().is_some_and(|result| !result.affected) {
        return Ok(None);
    }
    let fixed_in = evaluation
        .map(|result| result.fixed_versions)
        .unwrap_or_default();
    Ok(Some(Vulnerability {
        id: document.id.to_owned(),
        aliases: doc
            .get("aliases")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        summary: doc
            .get("summary")
            .and_then(Value::as_str)
            .or_else(|| doc.get("details").and_then(Value::as_str))
            .unwrap_or("No summary supplied")
            .to_owned(),
        severity: score.map(Severity::from_cvss),
        cvss_score: score,
        fixed_in,
        references: doc
            .get("references")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.get("url").and_then(Value::as_str).map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        withdrawn: document.withdrawn,
    }))
}

#[derive(Clone, Copy)]
pub(crate) enum OsvCvssVersion {
    V3,
    V4,
}

impl OsvCvssVersion {
    pub(crate) fn osv_type(self) -> &'static str {
        match self {
            Self::V3 => "CVSS_V3",
            Self::V4 => "CVSS_V4",
        }
    }

    pub(crate) fn accepts(self, vector: &Cvss) -> bool {
        matches!(
            (self, vector),
            (Self::V3, Cvss::CvssV30(_) | Cvss::CvssV31(_)) | (Self::V4, Cvss::CvssV40(_))
        )
    }
}

/// OSV top-level severity takes precedence over affected-entry severity. Within either source,
/// prefer a valid CVSS v4 vector and then fall back to a valid CVSS v3 vector.
pub(crate) fn osv_cvss_score(doc: &Value, package: Option<&Package>) -> Option<f64> {
    doc.get("severity")
        .and_then(Value::as_array)
        .and_then(|severity| cvss_score_from_severity_lists(&[severity.as_slice()]))
        .or_else(|| matching_affected_cvss_score(doc, package?))
}

pub(crate) fn matching_affected_cvss_score(doc: &Value, package: &Package) -> Option<f64> {
    let severity_lists = doc
        .get("affected")
        .and_then(Value::as_array)?
        .iter()
        .filter(|affected| affected_matches_package(affected, package))
        .filter_map(|affected| affected.get("severity").and_then(Value::as_array))
        .map(Vec::as_slice)
        .collect::<Vec<_>>();

    cvss_score_from_severity_lists(&severity_lists)
}

pub(crate) fn affected_matches_package(affected: &Value, package: &Package) -> bool {
    let Some(affected_package) = affected.get("package") else {
        return false;
    };
    let Some(ecosystem) = affected_package.get("ecosystem").and_then(Value::as_str) else {
        return false;
    };
    let Some(name) = affected_package.get("name").and_then(Value::as_str) else {
        return false;
    };

    ecosystem == package.ecosystem.osv_name()
        && (name == "*" || normalize_name(package.ecosystem, name) == package.name)
}

pub(crate) fn cvss_score_from_severity_lists(severity_lists: &[&[Value]]) -> Option<f64> {
    [OsvCvssVersion::V4, OsvCvssVersion::V3]
        .into_iter()
        .find_map(|version| {
            severity_lists
                .iter()
                .flat_map(|severity| severity.iter())
                .filter(|entry| {
                    entry.get("type").and_then(Value::as_str) == Some(version.osv_type())
                })
                .filter_map(|entry| entry.get("score").and_then(Value::as_str))
                .filter_map(|vector| vector.parse::<Cvss>().ok())
                .filter(|vector| version.accepts(vector))
                .map(|vector| vector.score())
                .max_by(f64::total_cmp)
        })
}
