# Security Policy

## Supported Versions

Security fixes are provided for the most recent minor release line published
under the npm `latest` dist-tag.

| Release line                          | Security support |
| ------------------------------------- | ---------------- |
| Latest minor line (currently `0.3.x`) | Supported        |
| Earlier minor lines                   | Not supported    |

Pre-release versions are provided for evaluation and do not receive separate
security support. Upgrade to the latest patch before reporting a problem that
may already have been fixed. Release changes are recorded in
[CHANGELOG.md](./CHANGELOG.md).

## Reporting a Vulnerability

Report suspected vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/nestarc/api-keys/security/advisories/new).
Do not open a public issue, discussion, or pull request for an undisclosed
vulnerability.

Include, when available:

- the affected package version and relevant runtime or adapter versions;
- the security impact and affected authentication or authorization boundary;
- minimal reproduction steps using synthetic data;
- any conditions required to reach the vulnerable path; and
- suggested mitigations or fixes.

## What to Expect

Maintainers will review the report, may request additional information, and
will coordinate remediation and disclosure when the issue is accepted. This
project does not promise a fixed acknowledgement or remediation SLA.

Please allow maintainers a reasonable opportunity to investigate and publish
a fix before public disclosure.

## Credentials and Proofs of Concept

Never include real API keys, peppers, hashes, production tenant data, or other
secrets. Use generated credentials and the smallest proof of concept needed to
demonstrate impact. Redact logs and screenshots before attaching them.

Do not access or modify data that you do not own, disrupt services, or expand
testing beyond the minimum needed to confirm the issue. If testing exposes a
real credential or third-party data, stop and report it privately.

## Security Scope

Reports are especially relevant when they demonstrate a realistic failure of
credential verification, key lifecycle controls, tenant isolation, environment
binding, scope or IP authorization, secret handling, or published package and
release integrity.

Consumer misconfiguration, unsupported release lines, third-party deployment
issues, and dependency advisories without a reachable impact in this package
are not treated as package vulnerabilities.
