# Offline eMudhra certificate regression data

`emudhra.json` contains only public X.509 certificates; no private keys, live
requests, runtime trust-store modifications, or executable fixture content.

## Incident chains and roots

Source: <https://github.com/galadran/we-have-a-problem.com/tree/49cdacf57b39f2c2feb52ffa6388c0dabace3846>

The `chains/*.pem` files and `roots.json` were imported at that exact commit on
2026-10-23. The upstream README describes leaf-first direct/cross-signed DV, OV,
and EV chains for G3B/G3C, plus two DV chains without CT entries: 14 chains and
four roots total. Root certificate SHA-256 fingerprints are retained verbatim.

Tests explicitly trust all four old roots and require `CertDistrusted`, rather
than accepting expiration, missing issuers, or OS revocation as sufficient proof.
The incident verification time is 2026-10-23T12:00:00Z, independent of the wall clock.

## Accepted control

The root, intermediate, and valid `example.com` leaf are public test certificates
from `rustls/rustls-platform-verifier`, commit
`996b1c903491641b17b3c9afb65d1352f6fc6b76`, directory
`rustls-platform-verifier/src/tests/verification_mock/`:

- `root1.crt`
- `root1-int1.crt`
- `root1-int1-ee_example.com-good.crt`

Upstream is licensed MIT OR Apache-2.0. DER certificates were converted to PEM
without changing certificate bytes. The control must verify with its anchor and
fail without it, preventing an always-rejecting verifier from passing the suite.
The control uses upstream's fixed Unix timestamp `1775649786`, within the validity
windows of its root, intermediate, and leaf (not the later incident timestamp).

These tests exercise the WebPKI backend used on Linux even when run on macOS.
They are not native Linux/Windows or published-binary acceptance evidence.
