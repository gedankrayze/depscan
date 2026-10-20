use super::support::*;

#[test]
fn report_epoch_cannot_reactivate_an_expired_suppression() {
    let project = TestProject::rust("suppression-wall-clock");
    project.seed_clean("1.0.0");
    project.seed_vulnerability();
    let yesterday = chrono::Utc::now().date_naive().pred_opt().unwrap();
    let config = project.directory.path().join("policy.toml");
    fs::write(
        &config,
        format!("[[ignore]]\nid = \"RUSTSEC-TEST\"\nexpires = {yesterday}\n"),
    )
    .unwrap();
    let output = project.run_reproducible(
        "0",
        &[
            "scan",
            "--format",
            "json",
            "--config",
            config.to_str().unwrap(),
            project.directory.path().to_str().unwrap(),
        ],
    );
    assert_exit(&output, 1);
    let report = json_report(&output);
    assert_eq!(report["generated_at"], "1970-01-01T00:00:00Z");
    assert_eq!(report["results"][0]["vulns"][0]["id"], "RUSTSEC-TEST");
    assert_eq!(report["results"][0]["suppressed"][0]["active"], false);
}

#[test]
fn future_report_epoch_does_not_expire_an_active_suppression() {
    let project = TestProject::rust("suppression-future-report");
    project.seed_clean("1.0.0");
    project.seed_vulnerability();
    let tomorrow = chrono::Utc::now().date_naive().succ_opt().unwrap();
    let config = project.directory.path().join("policy.toml");
    fs::write(
        &config,
        format!("[[ignore]]\nid = \"RUSTSEC-TEST\"\nexpires = {tomorrow}\n"),
    )
    .unwrap();
    let output = project.run_reproducible(
        "4102444800",
        &[
            "scan",
            "--format",
            "json",
            "--config",
            config.to_str().unwrap(),
            project.directory.path().to_str().unwrap(),
        ],
    );
    assert_exit(&output, 0);
    let report = json_report(&output);
    assert_eq!(report["generated_at"], "2100-01-01T00:00:00Z");
    assert!(report["results"][0]["vulns"].as_array().unwrap().is_empty());
    assert_eq!(report["results"][0]["suppressed"][0]["active"], true);
}
