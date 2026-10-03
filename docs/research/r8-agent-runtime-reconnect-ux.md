# R8 — Background Agent Runtime & Reconnect UX

> Research pass 8/15 · Mission 1.2.0 · Sources: daemon-CLI split patterns (r8a:
> mjolnir "mj daemon status" surfacing URL + six-digit code, tailscale status
> health view, Teltonika wiki), systemd user-service guides (r8b: salrahman.com,
> vladsiv.com, servercake.in socket activation), master prompt §§17–21.
> Raw: raw/r8a.json, raw/r8b.json

## What the reference tools do

1. **Status command = the daemon's face** (r8a): tools with background daemons
   expose one command that answers everything — mjolnir's `mj daemon status`
   prints the viewer URL AND a fresh six-digit login code (credential
   re-surfacing on demand — but for FARcontrol the session password must NOT be
   re-printable; show status without secrets). `tailscale status` shows peer +
  health state; degraded states are messages, not silence.
2. **systemd user services** (r8b): the standard Linux answer for "survives
   terminal close" — `systemctl --user` start/stop/status, socket activation for
   on-demand start, journal for logs. Trade-off: requires a user bus session;
   SSH-only boxes and containers often lack it. Conclusion: FARcontrol's agent
   runtime should be a **plain supervised background process by default**
   (double-fork + pidfile + `frtrol agent status/stop`), with systemd user unit
   as an OPTIONAL integration. Windows (service)/macOS (launchd) are future
   platform work, not v1.2 blockers (repo is Linux-only today — README honest
   limitation).
3. **State machine over booleans** (master prompt §20): the connection has
   states CONNECTED / RECONNECTING (backoff) / EXPIRED / REVOKED / STOPPED.
   Only the last three are terminal; a Wi-Fi blip must not force re-auth.
   Distinguish "network gone" from "credentials dead" — different colors,
   different next-actions (r9 taxonomy).
4. **Backoff discipline** (master prompt §21/§44): exponential with jitter,
   capped (e.g. 1s→2s→4s→…→60s max), no busy loop, near-zero idle CPU. Reconnect
   uses the SAME session credentials while unexpired; on EXPIRED/REVOKED the
   runtime exits cleanly and says why (fail closed, invariant).
5. **Runtime visibility**: `frtrol agent status` (agent box) must show:
   state, target Device ID, session id, expiry countdown, last error + when,
   pid, uptime, reconnect attempt count. `--json` for scripting. Owner box
   shows the mirrored view in the console session header (r10).

## FARcontrol v1.2 adoption decisions

- `frtrol agent` = connect → handoff to background runtime → CLI exits (§17).
- Runtime: detached process + pidfile under `~/.farcontrol/agent/`; commands:
  `frtrol agent status|stop` (start = default when no runtime exists).
- Reconnect: exponential backoff w/ jitter, cap 60s; hard-fail only on
  EXPIRED/REVOKED/auth-rejection (which are terminal, audited, and logged to
  the operator visibly).
- Never re-print the session password; `status` shows everything except secrets.
- Keepalive: piggyback on the existing request/HMAC path (no new port); idle
  heartbeat ≤ 30s only while connected (master prompt §22 anti-polling).
