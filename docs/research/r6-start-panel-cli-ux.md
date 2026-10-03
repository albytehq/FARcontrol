# R6 — `frtrol start` Startup Panel UX (v1.2 connection model)

> Research pass 6/15 · Mission 1.2.0 · Sources: ngrok docs/tutorials (r6a: ngrok.com,
> plainenglish.io, twilio.com — tunnel startup panels), first-run onboarding writeups
> (r6b: 1devtool.com checklist-onboarding), v1.1 baseline (src/server.rs banner,
> src/cli_admin.rs observed). Raw: raw/r6a.json, raw/r6b.json

## What the reference tools do at startup

1. **ngrok (the canonical "session panel")**: `ngrok http 8080` prints a bordered
   panel — session status, forwarding URL, region, connections counter — then stays
   in the foreground streaming status. Users are told to keep it open; that is
   ngrok's model, NOT ours (master prompt §17 forbids "terminal must remain open"
   as the primary design). What transfers: one glance = everything needed to
   connect (the URL is boxed, isolated, copyable).
2. **Tunnel/agent startup prints identity + reachability, not internals.** ngrok's
   agent connects outbound and works behind NAT (r6a) — the user never sees bind
   addresses or NAT state. FARcontrol's v1.1 banner currently prints data dir,
   os/arch, two bind addresses, fingerprint, policy numbers — operator-grade, not
   user-grade. v1.2 default should hide these behind `--verbose`/`doctor`.
3. **First-run = a self-ticking checklist** (r6b, 1devtool: "guided welcome, a
   checklist that ticks itself off as you work"). For FARcontrol the v1.2 flow is
   three steps and the startup panel should SAY them: (1) FARcontrol is running,
   (2) give Device ID + Session Password to your agent, (3) `frtrol agent` connects.
4. **Credentials are event output, not log lines**: "shown once" secrets are
   isolated on their own line, monospace, no decoration inside the line, with an
   explicit expiry/invalidity note (v1.1 already does this for device passwords —
   `device add` prints `DEVICE PASSWORD (shown once — store it now)`). Verified
   working in v1.1; extend to Session Password + Admin Token.
5. **Non-TTY degradation**: startup output must stay parseable when piped
   (CI, scripts): plain `key: value` lines, no box drawing, no ANSI (matches
   ADR-0026 rendering contract; picocli-style 80-col default width, r15a
   corroboration). Secrets never in argv.

## FARcontrol v1.2 adoption decisions

- `frtrol start` prints ONE panel, in this order (TTY):
  `● session active` header → Device ID → Session Password → Web UI URL +
  Admin Token → expiry line ("credentials die when this session ends") →
  2-line "what now" (agent-side command, web console hint) → `Ctrl-C to stop`.
- First run adds the 3-step checklist above the panel (one-time, not every run).
- Operator details (binds, fingerprint, policy, keyring mode) move to
  `frtrol status --verbose` / `doctor`; startup stays under ~15 lines
  (master prompt §8: "not excessively verbose").
- `--json` prints the same fields machine-readable (owner box stdout only).
- Panel is plain text lines when stdout is not a TTY or `NO_COLOR` is set.
