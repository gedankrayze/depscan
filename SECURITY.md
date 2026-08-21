# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's private vulnerability
reporting: open the repository's **Security** tab and choose **Report a vulnerability**
(https://github.com/gedankrayze/depscan/security/advisories/new). Do not open a public issue
for an unpatched vulnerability.

Reports are acknowledged within seven days. Fix timelines depend on severity and are
coordinated with the reporter before any public disclosure.

## Scope

depscan parses attacker-controllable project checkouts (lockfiles, manifests, configuration)
and talks to public registry and OSV endpoints. Of particular interest are:

- parser memory-safety or resource-exhaustion issues on untrusted input,
- scans writing or deleting files outside their documented cache and output locations,
- command execution beyond the documented, explicitly authorized `--allow-tools` surface,
- false-clean results: a scan reporting a dependency clean when the advisory data says
  otherwise,
- release-pipeline integrity issues (checksums, attestations, installer bootstrap).

## Supported versions

Security fixes target the latest released minor version. Older releases receive fixes only
when the latest release cannot be adopted, decided case by case with the reporter.
