use super::*;
use serde_json::json;

const MODIFIED: &str = "2026-08-19T00:00:00Z";

fn valid_document() -> Value {
    json!({
        "schema_version": "1.7.4",
        "id": "TEST-SHAPE-ACTIVE",
        "modified": MODIFIED,
        "published": "2026-08-18T00:00:00Z",
        "aliases": ["CVE-2026-1234"],
        "related": ["TEST-RELATED-1"],
        "upstream": ["TEST-UPSTREAM-1"],
        "summary": "validated advisory",
        "details": "validation fixture",
        "severity": [{
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "source": "SELF"
        }],
        "affected": [{
            "package": {
                "ecosystem": "npm",
                "name": "shape-validation",
                "purl": "pkg:npm/shape-validation@1.0.0"
            },
            "versions": ["1.0.0"],
            "ecosystem_specific": {},
            "database_specific": {}
        }],
        "references": [{
            "type": "ADVISORY",
            "url": "https://example.invalid/advisory"
        }],
        "database_specific": {}
    })
}

#[test]
fn accepts_active_and_rfc3339_withdrawn_documents() {
    let active = valid_document();
    assert!(
        !validate_osv_document(&active, Some("TEST-SHAPE-ACTIVE"))
            .unwrap()
            .withdrawn
    );

    let mut withdrawn = active;
    withdrawn["id"] = json!("TEST-SHAPE-WITHDRAWN");
    withdrawn["withdrawn"] = json!(MODIFIED);
    assert!(
        validate_osv_document(&withdrawn, Some("TEST-SHAPE-WITHDRAWN"))
            .unwrap()
            .withdrawn
    );
}

#[test]
fn rejects_consumed_field_shape_corruption() {
    let base = valid_document();
    let mut cases = Vec::new();
    let mut document = base.clone();
    document.as_object_mut().unwrap().remove("affected");
    cases.push((
        "missing affected",
        document,
        "affected must be a present array",
    ));
    let mut document = base.clone();
    document["affected"] = Value::Null;
    cases.push((
        "null affected",
        document,
        "affected must be a present array",
    ));
    let mut document = base.clone();
    document["affected"][0]["package"] = json!("npm:shape-validation");
    cases.push(("non-object package", document, "package must be an object"));
    let mut document = base.clone();
    document["affected"][0]["package"]
        .as_object_mut()
        .unwrap()
        .remove("name");
    cases.push((
        "missing package name",
        document,
        "package.name must be a string",
    ));
    let mut document = base.clone();
    document["affected"][0]["versions"] = json!(["1.0.0", false]);
    cases.push((
        "non-string version",
        document,
        "versions[1] must be a string",
    ));
    let mut document = base.clone();
    document["affected"][0]["versions"] = json!([""]);
    cases.push(("empty version", document, "versions[0] must not be empty"));
    let mut document = base.clone();
    document["withdrawn"] = Value::Null;
    cases.push((
        "null withdrawn",
        document,
        "withdrawn must be an RFC 3339 string",
    ));
    let mut document = base.clone();
    document["withdrawn"] = json!(false);
    cases.push((
        "boolean withdrawn",
        document,
        "withdrawn must be an RFC 3339 string",
    ));
    let mut document = base.clone();
    document["withdrawn"] = json!("not-a-timestamp");
    cases.push((
        "invalid withdrawn",
        document,
        "withdrawn must be a valid RFC 3339",
    ));
    let mut document = base.clone();
    document["aliases"] = json!(["CVE-2026-1234", 42]);
    cases.push(("malformed aliases", document, "aliases[1] must be a string"));
    let mut document = base.clone();
    document["severity"][0]["score"] = json!(9.8);
    cases.push((
        "malformed severity",
        document,
        "severity[0].score must be a string",
    ));
    let mut document = base.clone();
    document["references"][0]
        .as_object_mut()
        .unwrap()
        .remove("url");
    cases.push((
        "malformed reference",
        document,
        "references[0].url must be a string",
    ));
    let mut document = base;
    document["schema_version"] = json!("2.0.0");
    cases.push(("unsupported schema", document, "unsupported major version"));

    for (case, document, expected) in cases {
        let error = validate_osv_document(&document, None).unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "{case}: expected {expected:?}, got {error}"
        );
    }
}
