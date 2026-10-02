# ADR-0021: Observability + crash recovery v0.7 (App B / §73 / §35)

Date: 2026-10-02
Status: accepted

## Context

Spec Appendix B ("Local health: GET /healthz, GET /readyz"), Phase 5
("crash recovery", "production observability"), §73 (incident response
procedure). SC-08: "Incident response and recovery documented."

## Decision

**Health/readiness probes** ride the ADMIN plane (loopback + TLS):
- `GET /healthz` — unauthenticated liveness ("ok"). Loopback-only plane
  means an unauthenticated probe leaks nothing to the network.
- `GET /readyz` — unauthenticated readiness: state DB answers AND schema
  version is current; 503 otherwise.

**Metrics** (`GET /admin/metrics`, admin-token auth, Prometheus text
format v0.0.4): up, version_info, uptime_seconds, active_sessions,
pending_requests, open_terminals, ui_sessions, audit_events_total,
auth_failures_window, schema_version. Single-tenant scope: exactly what the
owner sees on the console, zero secret values.

**Crash recovery** = verified behavior, not new machinery:
- SQLite WAL means a SIGKILL cannot tear writes — replay on restart.
- e2e §23 SIGKILLs the daemon mid-life and proves: restart succeeds,
  healthz green, a session approved BEFORE the crash still executes, and
  the audit trail survived.
- systemd unit (deb) hardened: `Restart=always`, `RestartSec=2`,
  `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
  `ReadWritePaths=~/.farcontrol`.

**Incident response runbook** (`docs/incident-response.md`): the §73
eight-step procedure (detect → contain → revoke → preserve → rotate →
patch → validate → restore) mapped to concrete, already-tested commands
(panic, revoke, backup, doctor, audit). Every command in the runbook
points at the e2e section that verifies it — the document is tested, not
aspirational.

## Evidence

e2e §23 (8 checks) + verification report (56 unit + 120 e2e, clippy 0,
audit clean, secret-scan clean).
