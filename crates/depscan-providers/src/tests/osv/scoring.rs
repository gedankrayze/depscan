use super::*;

#[test]
fn scores_supported_cvss_versions_with_standard_formulas() {
    let cases = [
        (
            "CVSS_V3",
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            9.8,
            Severity::Critical,
        ),
        (
            "CVSS_V3",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            7.5,
            Severity::High,
        ),
        (
            "CVSS_V4",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/V:C",
            8.7,
            Severity::High,
        ),
    ];

    for (severity_type, vector, expected_score, expected_severity) in cases {
        let document = json!({
            "id": "TEST-1",
            "modified": TEST_OSV_MODIFIED,
            "affected": [],
            "severity": [{"type": severity_type, "score": vector}]
        });
        let vulnerability = vulnerability_from_osv(&document, None).unwrap().unwrap();

        assert_eq!(vulnerability.cvss_score, Some(expected_score), "{vector}");
        assert_eq!(vulnerability.severity, Some(expected_severity), "{vector}");
    }
}

#[test]
fn prefers_cvss_v4_and_falls_back_to_valid_cvss_v3() {
    let v3_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H";
    let v4_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/V:C";
    let document = json!({
        "severity": [
            {"type": "CVSS_V3", "score": v3_vector},
            {"type": "CVSS_V4", "score": v4_vector}
        ]
    });
    assert_eq!(osv_cvss_score(&document, None), Some(8.7));

    let document = json!({
        "severity": [
            {"type": "CVSS_V4", "score": "CVSS:4.0/not-a-vector"},
            {"type": "CVSS_V3", "score": v3_vector}
        ]
    });
    assert_eq!(osv_cvss_score(&document, None), Some(7.5));
}

#[test]
fn selects_the_highest_score_independent_of_source_order() {
    let high = json!({
        "type": "CVSS_V3",
        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    });
    let critical = json!({
        "type": "CVSS_V3",
        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    });

    for severity in [vec![high.clone(), critical.clone()], vec![critical, high]] {
        let document = json!({"severity": severity});
        assert_eq!(osv_cvss_score(&document, None), Some(9.8));
    }
}

#[test]
fn top_level_severity_precedes_matching_affected_severity() {
    let package = Package::new(
        Ecosystem::CratesIo,
        "quick-xml",
        "0.36.2",
        PathBuf::from("Cargo.lock"),
    );
    let document = json!({
        "severity": [{
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        }],
        "affected": [{
            "package": {"ecosystem": "crates.io", "name": "quick-xml"},
            "severity": [{
                "type": "CVSS_V4",
                "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/V:C"
            }]
        }]
    });

    assert_eq!(osv_cvss_score(&document, Some(&package)), Some(7.5));
}

#[test]
fn affected_severity_is_restricted_to_the_matching_package() {
    let package = Package::new(
        Ecosystem::CratesIo,
        "quick-xml",
        "0.36.2",
        PathBuf::from("Cargo.lock"),
    );
    let document = json!({
        "id": "TEST-AFFECTED-SEVERITY",
        "modified": TEST_OSV_MODIFIED,
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "quick-xml"},
                "severity": [{
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
                }]
            },
            {
                "package": {"ecosystem": "crates.io", "name": "another-crate"},
                "severity": [{
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
                }]
            },
            {
                "package": {"ecosystem": "crates.io", "name": "quick-xml"},
                "versions": ["0.36.2"],
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                    },
                    {
                        "type": "CVSS_V4",
                        "score": "CVSS:4.0/not-a-vector"
                    }
                ]
            }
        ]
    });

    let vulnerability = vulnerability_from_osv(&document, Some(&package))
        .unwrap()
        .unwrap();
    assert_eq!(vulnerability.cvss_score, Some(7.5));
    assert_eq!(vulnerability.severity, Some(Severity::High));
    assert_eq!(osv_cvss_score(&document, None), None);
}

#[test]
fn rejects_malformed_mismatched_and_unscoped_scores() {
    let cases = [
        json!({"severity": [{"type": "CVSS_V3", "score": "6.5"}]}),
        json!({"severity": [{
            "type": "CVSS_V4",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        }]}),
        json!({"severity": [{"type": "CVSS_V3", "score": "not-a-vector"}]}),
        json!({"severity": [{
            "type": "CVSS_V2",
            "score": "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"
        }]}),
    ];

    for document in cases {
        let document = json!({
            "id": "TEST-MALFORMED-SCORE",
            "modified": TEST_OSV_MODIFIED,
            "affected": [],
            "severity": document["severity"].clone()
        });
        let vulnerability = vulnerability_from_osv(&document, None).unwrap().unwrap();
        assert_eq!(vulnerability.cvss_score, None);
        assert_eq!(vulnerability.severity, None);
    }
}
