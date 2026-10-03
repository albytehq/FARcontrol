# R12 — Localhost Security UX (admin plane hardening + credential entry)

> Research pass 12/15 · Mission 1.2.0 · Sources: DNS-rebinding attack literature
> (r12a: conception-world/Yeet SECURITY.md browser-driven attacks on local
> ports, CVE-2026-49471 Serena MCP DNS-rebinding RCE — Host-header allowlist
> fix, GUPNP Host-check issue, WPAD/Chromium issue), Chrome Local Network Access
> (r12b: Chrome 145 release notes — PNA superseded by local-network request
> gating, GitHub PNA CORS issue), v1.1 baseline (webui.rs auth observed).
> Raw: raw/r12a.json, raw/r12b.json

## Threat picture for a localhost admin UI in 2026

1. **Any web page can try your local ports** (r12a, Yeet SECURITY.md):
   drive-by pages + DNS rebinding let attacker JS reach `127.0.0.1:<port>`
   with a rebound Host. This is not theoretical — Serena MCP toolkit shipped a
   real unauthenticated-RCE-via-rebinding CVE in 2026, fixed by a Host allowlist.
   The same class keeps recurring in local dev tools.
2. **The two necessary defenses** (standard, cheap): (a) validate the `Host`
   header against an allowlist (`127.0.0.1[:port]`, `[::1][:port]`) — reject
   everything else BEFORE auth; (b) require a non-CORS-safelisted header on
   every state-changing call. FARcontrol v1.1 already has (b) — the JS-only
   `X-Far-Ui` header + `SameSite=Strict` cookie (ADR-0017, e2e-enforced).
   (a) is MISSING (observed: webui.rs routes never check Host) — this research
   recommends adding it in v1.2.
3. **Browser-side movement** (r12b): Chrome 145+ gates public→local network
   requests ("Local Network Access", superseding PNA preflight). Helpful, but
   NOT a defense we control — users run other browsers/versions; the server
   must defend itself (fail closed on its own).
4. **Admin token entry UX** (v1.1 observed): password input + backoff on
   failure is correct. v1.2 improvement: the token is session-bound and
   printed by `frtrol start` (r6), so the login screen should SAY where it
   comes from ("the Admin Token printed by frtrol start") — reduces the
   "which password?" confusion when v1.1 muscle-memory types a device password.
5. **Credential display hygiene** (master prompt §29): the console must never
   re-display the session password after start (it CAN re-display Device ID
   and non-secret state). Browser autofill should be off for the admin token
   (`autocomplete=off`), and the session cookie dies with the daemon
   (v1.1 in-memory map — keep).

## FARcontrol v1.2 adoption decisions

- Add Host-header allowlist (loopback only) on the admin plane, reject-before-
  auth, with an audit line (`system.admin.host_rejected`). Test: curl with
  spoofed Host → rejected; normal console → works (e2e candidate).
- Keep X-Far-Ui + SameSite=Strict + backoff + in-memory cookie session
  (ADR-0017 carryovers, all still e2e-proven).
- Login page labels the credential correctly; autocomplete=off; no password
  managers prompting on a one-time token.
- Admin token bound to session lifetime (r7); console shows "session ended"
  state (r10) rather than a generic 401 loop.

## Honest gaps

- No live exploit test against FARcontrol yet (sandbox lacks a second origin
  to attack from). The Host check will get an e2e case when implemented
  (discipline: no VERIFIED without evidence).
