# ADR-0017: Web UI rides the loopback admin plane (v0.3.0)

Date: 2026-10-02
Status: accepted
Supersedes: none (extends ADR-0004 admin plane)

## Context

Spec §8.3/App B/Phase 3 call for a local owner web console (dashboard, approve/deny,
revoke, logs) at a loopback UI port (suggested `127.0.0.1:7481`, explicitly
"examples, configurable"). Prior versions made every owner decision through
`frtrol` CLI commands against the admin API.

## Decision

Serve the console **from the existing admin plane** (default `127.0.0.1:7789`, TLS,
loopback-enforced at startup) instead of a third listener:

- one extra bind = one extra attack surface; the admin plane already guarantees
  loopback + TLS + rate-limit window. (App B values are suggestions, not binding.)
- login = the owner's **admin token** (same secret the CLI uses, ct_eq compare).
- login exchanges it for a random 32-byte cookie session: `far_ui`, HttpOnly,
  SameSite=Strict, Secure (when TLS), sliding 1h TTL, **in-memory store** —
  daemon restart = re-login (fail closed, no persistence to steal).
- CSRF: every `/ui/*` POST must carry the JS-only `X-Far-Ui: 1` header; a forged
  cross-site form cannot set custom headers. Combined with SameSite=Strict.
- XSS: the page is one embedded HTML file (include_str!), vanilla JS, and renders
  EVERY dynamic value via `textContent` — no HTML-string sink exists at all, so
  stored agent_name/reason cannot execute. Structural defense, not escaping.
- Login failures feed the same sliding-window backoff as the agent plane (SE-09).
- UI actions reuse the exact state-layer functions as the CLI (`approve_request`,
  `deny_request`, `revoke_session`, `panic_stop`) and audit an `owner:webui`
  marker event (`ui.login`, `ui.approve`, `ui.revoke`, `ui.panic`).

## Consequences

- No new dependencies (no cookie crate, no framework — manual Cookie header parse).
- UI port differs from the spec's example number; documented as configurable via
  `admin_bind` (spec marks the 7481 value as an example).
- In-memory sessions mean no "remember me" — acceptable for a security console.

## Evidence

e2e §19 (13 checks): shell served, no HTML sink in page source, wrong password 401,
login sets cookie, no-cookie 401, POST w/o X-Far-Ui 403 csrf_blocked, approve→exec
works, revoke kills access, UI panic revokes, audit shows owner:webui events,
logout invalidates server-side. Mutation check: disabling the CSRF check turns the
suite red (7 failures) — the test is load-bearing.
