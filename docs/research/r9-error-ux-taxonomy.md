# R9 — CLI Error UX Taxonomy (what happened / why / what next)

> Research pass 9/15 · Mission 1.2.0 · Sources: error-message UX guidelines
> (r9a: nngroup.com "Error-Message Guidelines", learn.microsoft.com Business
> Central actionable errors, usersnap, aguayo.co, ramotion.com), compiler
> diagnostics design (r9b: rustc-dev-guide, internals.rust-lang.org diagnostic
> structs, error.rust.phpboyscout.uk "errors are values, not handled events"),
> v1.1 baseline (error.rs FRT codes, out.rs observed).
> Raw: raw/r9a.json, raw/r9b.json

## What good error UX looks like

1. **NN/g core rules** (r9a): highly visible, constructive, human-readable,
   respectful (never blame the user), and preserve the user's effort — don't
   make them re-type what they already entered. Every error: WHAT happened,
   WHY (plain language), NEXT STEP (actionable). "An error message that doesn't
   help solve the problem is a wall" (aguayo).
2. **rustc's structure** (r9b): severity + summary line → labeled spans →
   *actionable suggestion* ("help: did you mean…"). The diagnostic is a VALUE
   with structure (code, message, spans, children), rendered differently per
   output mode — exactly FARcontrol's `{error:{code,message}}` envelope + pretty
   renderer split. Keep that architecture; improve the rendering.
3. **Machine identity ≠ human advice** (r9b, phpboyscout): stable code for
   programs, one line of human advice, then the rendering strategy decides
   verbosity. Exit codes stay authoritative (ADR-0022 §66: 0–7).
4. **Next-action lines are commands, not prose**: `next: frtrol agent status`
   beats "please check your connection" (mirrors r1 hint-line pattern).
5. **Terminal vs transient** (r8 state machine): EXPIRED/REVOKED/wrong-password
   are terminal (user must act); network failures are transient (auto-retry,
   show attempt count). Same visual weight, different wording and next-steps.

## FARcontrol v1.2 adoption decisions

- Error block format (TTY):
  `✗ <what happened> (FRT-0xx)` / dim: `why: <plain why>` / dim: `next: <command>`.
  One blank line separation; no stack traces ever (doctor keeps diagnostics).
- Map the master-prompt §31 state list to the existing FRT code registry; add
  codes where a state has none (e.g. `device_not_found`, `agent_runtime_stopped`,
  `port_unavailable`). Registry stays in error.rs, documented in README.
- Same error in `--json` = existing envelope + new `"hint"` field (additive).
- Reconnect-capable errors print state: `✗ connection lost — retrying (3/∞), next attempt in 4s`.
- Never echo the failed credential back; never log secrets (invariant §6.6).

## Honest gaps

- r9a/r9b snippets are guideline-level; no FARcontrol-specific usability
  testing exists yet. Post-v1.2: run the error paths past a stranger (S11
  check: "read the error as a stranger in an 80-col terminal").
