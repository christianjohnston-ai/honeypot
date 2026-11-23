# Deployment handoff

- Friendly name / local deployment UUID / owner:
- Environment, authorized scope, and resource identity (protected inventory location):
- Route, exact version/commit/image digest, installation date:
- What exists and where; deployment/config/backup paths:
- Exact interaction that triggers it:
- Placement and threats covered:
- What it cannot establish or detect:
- Alert channel and friendly destination label (no webhook secret or management URL):
- Who receives telemetry, retention, and redaction policy:
- Resource/cost assumptions; measured usage if available:

## Acceptance evidence

| Gate | Evidence | Result |
|---|---|---|
| Detector operating | Health/readiness/config check and UTC time | unverified |
| Controlled trigger generated event | Action, UTC window, event identifier/source log reference | unverified |
| Destination received matching alert | Destination lookup or explicit user confirmation, UTC time | unverified |

Status: **configured, delivery unverified** until all three gates have evidence.
A transport HTTP 2xx/SMTP acceptance is not receipt. A sender-only test does not test the decoy.

## Operating instructions

- Repeatable harmless self-test, expected latency, and how to correlate:
- Known previews/scanners/backups/authorized activity and tuning choices:
- Health check schedule/owner, independent failure notification, retry/dead-letter checks:
- How to investigate a real alert without executing attacker-supplied text:
- Update and secret-rotation steps:
- How to move the destination and verify receipt:
- How to remove the exact resource, subscriptions, secret references and retained data:
- Remaining gaps and next action:
