# Security Policy

## This repository is intentionally vulnerable

`ticketdesk` is a **security training fixture**. It exists to exercise an automated
SAST triage-and-remediation pipeline: the planted vulnerabilities must be genuinely
present at the lines cited in the accompanying scan report, so that triage, fixing
and validation can be tested end to end.

**Please do not report the planted vulnerabilities.** They are deliberate, they are
documented, and each one is marked in the source with a `# VULNERABLE:` comment
naming its CWE. A list is in the README.

## Do not deploy this

Do not run this service on a reachable network, and do not copy code out of:

- `app/api/v1/reports.py` — SQL injection, `eval`
- `app/api/v1/attachments.py` — path traversal, command injection
- `app/api/v1/integrations.py` — SSRF, hard-coded credential, unsafe deserialization
- `app/api/v1/admin.py` — missing authorization, debug exposure, error disclosure
- `app/core/security.py` — weak hash, predictable token

## About the credential in this repo

`UPSTREAM_API_TOKEN` in `app/api/v1/integrations.py` is a **fabricated string**. It
has never been a live credential for any system and there is nothing to rotate. It is
present so that secret-detection rules have something to find.

## Reporting a real problem

If you find a vulnerability that is *not* one of the documented planted ones — for
example in the build tooling or dependencies — please open an issue.
