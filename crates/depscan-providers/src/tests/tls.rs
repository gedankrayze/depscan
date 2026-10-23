use rustls_pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fmt::Write, time::Duration};

#[derive(Deserialize)]
struct Fixtures {
    roots: Vec<Root>,
    chains: Vec<Chain>,
    control: Control,
}

#[derive(Deserialize)]
struct Root {
    name: String,
    pem: String,
    sha256: String,
}

#[derive(Deserialize)]
struct Chain {
    name: String,
    pem: String,
}

#[derive(Deserialize)]
struct Control {
    root: String,
    intermediate: String,
    leaf: String,
}

fn fixtures() -> Fixtures {
    serde_json::from_str(include_str!("fixtures/tls/emudhra.json")).unwrap()
}

fn certificates(pem: &str) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn verification_time() -> UnixTime {
    let seconds = chrono::DateTime::parse_from_rfc3339("2026-10-23T12:00:00Z")
        .unwrap()
        .timestamp();
    UnixTime::since_unix_epoch(Duration::from_secs(seconds.try_into().unwrap()))
}

fn fingerprint(certificate: &CertificateDer<'_>) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(certificate.as_ref()) {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

#[test]
fn emudhra_direct_cross_signed_and_no_ct_chains_are_explicitly_distrusted() {
    let fixtures = fixtures();
    assert_eq!(fixtures.chains.len(), 14);
    let roots: Vec<_> = fixtures
        .roots
        .iter()
        .flat_map(|root| certificates(&root.pem))
        .collect();
    let anchors: Vec<_> = roots
        .iter()
        .map(|root| webpki::anchor_from_trusted_cert(root).unwrap())
        .collect();
    assert_eq!(anchors.len(), 4);

    // Deliberately trust all old roots: rejection must come from the intermediate
    // public-key block, not an absent system CA bundle or a root-store update.
    for chain in fixtures.chains {
        let certificates = certificates(&chain.pem);
        let (leaf, intermediates) = certificates.split_first().unwrap();
        let certificate = webpki::EndEntityCert::try_from(leaf).unwrap();
        let hostname = chain.name.strip_suffix(".pem").unwrap();
        certificate
            .verify_is_valid_for_subject_name(&ServerName::try_from(hostname).unwrap())
            .unwrap();
        let error = certificate
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &anchors,
                intermediates,
                verification_time(),
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .err()
            .expect("a compromised chain must not verify");
        assert_eq!(error, webpki::Error::CertDistrusted, "{}", chain.name);
    }
}

#[test]
fn bundled_roots_omit_every_incident_root_by_certificate_fingerprint() {
    let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS;
    assert!(roots.len() > 100);
    for root in roots {
        webpki::anchor_from_trusted_cert(root).unwrap();
    }
    for root in fixtures().roots {
        let certificates = certificates(&root.pem);
        assert_eq!(certificates.len(), 1);
        let certificate = certificates.first().unwrap();
        let expected = fingerprint(certificate);
        assert_eq!(expected, root.sha256.replace(':', "").to_lowercase());
        assert!(
            !roots
                .iter()
                .any(|candidate| fingerprint(candidate) == expected),
            "incident root is still trusted: {}",
            root.name
        );
    }
}

#[test]
fn unrelated_valid_chain_still_verifies_with_a_trusted_anchor() {
    let control = fixtures().control;
    // Upstream's fixed control time lies within all three control validity windows.
    let control_time = UnixTime::since_unix_epoch(Duration::from_secs(1_775_649_786));
    let roots = certificates(&control.root);
    let anchors: Vec<_> = roots
        .iter()
        .map(|root| webpki::anchor_from_trusted_cert(root).unwrap())
        .collect();
    let leaf = certificates(&control.leaf);
    let intermediates = certificates(&control.intermediate);
    let certificate = webpki::EndEntityCert::try_from(leaf.first().unwrap()).unwrap();
    certificate
        .verify_is_valid_for_subject_name(&ServerName::try_from("example.com").unwrap())
        .unwrap();
    certificate
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            control_time,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .unwrap();
    assert_eq!(
        certificate
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &[],
                &intermediates,
                control_time,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .err()
            .expect("an untrusted control chain must not verify"),
        webpki::Error::UnknownIssuer
    );
}
