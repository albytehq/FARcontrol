# R13 — Session Lifecycle & Time UX (countdowns, expiry, end states)

> Research pass 13/15 · Mission 1.2.0 · Sources: session-timeout UX writing
> (r13a: pixinvent admin-panel session expiry, ux.stackexchange conference
> timer, themeplace accessibility of timeouts, casino auto-logout countdown
> clarity), just-in-time / temporary access literature (r13b: AD temporary
  membership pattern, CSA AICM temporary JIT grants, AI-agent ephemeral
  credentials guidance), v1.1 baseline (countdown() observed).
> Raw: raw/r13a.json, raw/r13b.json

## What the evidence says

1. **Countdowns must be visible and unambiguous**: the clearest pattern from
   both a video-conference timer (r13a, ux.stackexchange) and auto-logout
   warnings ("visual clarity of the countdown on the warning popup clears
   ambiguity — you know exactly how many seconds remain") is a live countdown
   attached to the thing that expires — not a timestamp the user must subtract.
   v1.1 already renders `4h 51m left` (good); v1.2 puts it in the session
   header where it is always visible (r10).
2. **Accessibility warning** (r13a, themeplace): live timers and 30-second
   warnings alone do little; the system must state UPFRONT that a time limit
   exists. FARcontrol: the start panel prints the session expiry, the console
   header shows the countdown, and agent requests carry `expires_at` in --json
   (machine clients get the fact too — r14).
3. **Warning thresholds**: continuous color scale, not a surprise — amber at
   <1h (v1.1 session table already warns <1h; keep), red + stronger wording at
   <5m ("about to expire — re-approve after expiry if still needed").
   No popup nags (owner-tool, single user; a nag is noise).
4. **Temporary access is the industry direction** (r13b): time-boxed membership
   (AD), auto-expiring JIT grants (CSA), "grant temporary credentials that
   expire immediately after use" for AI agents — v1.2's session-bound password
   model is aligned with the literature; the RESEARCH-backed way to present it
   is "grants expire, that is the product" (no extend button in v1.2 —
   extension = new request after expiry; honest, simple, Rule 1).
5. **End states must be loud and final** (master prompt §50): when the session
   ends: console banner "SESSION ENDED — credentials are dead", agent runtime
   exits with a clear reason (r8), CLI status says so. Stale sessions must not
   silently remain usable (invariant).
6. **Client-side ticking**: countdowns computed from `expires_at` + server
   clock offset, refreshed by `session_tick` every 30s (r11) — never one HTTP
   request per second. Reserve layout width so the countdown doesn't reflow
   the header each tick (v1.1 KPI/table pattern: fixed-width mono spans).

## FARcontrol v1.2 adoption decisions

- Session header: `● session active · 4h 51m left` (mono, fixed width) —
  amber <1h, red <5m with "re-approve after expiry" hint.
- Start panel prints `expires: <iso>` and "credentials die when the session
  ends" (r6 tie-in).
- No extend button in v1.2 (see §4); expiry is a feature, framed as such.
- Terminal end states: console banner + agent exit reason + owner CLI
  `status` line, all using the same words ("session ended").

## Honest gaps

- Thresholds (<1h amber, <5m red) follow v1.1 convention + general countdown
  writing; no usability study specific to FARcontrol (INFERRED, consistent
  with prior ADRs).
