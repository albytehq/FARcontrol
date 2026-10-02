# ADR-0014: `frtrol panic` + `frtrol doctor`

Date: 2026-10-02 · Status: ACCEPTED

## Decision
- **panic (SE-11)**: one admin call revokes ALL active sessions, expires ALL
  pending requests, kills ALL terminals, rotates the agent token. CLI is
  positional: `frtrol panic [reason]`.
- **doctor (§46)**: local checks (config, token perms, cert, db) + remote
  checks via admin plane (db quick_check, audit hash chain, schema, clock,
  live state). Each check: name + verdict + fix action. Exit 0 = all green.

## Consequences
Emergency response is one command, not a runbook. Health is self-testable —
tampered audit.jsonl turns doctor red (proven in e2e §12).
