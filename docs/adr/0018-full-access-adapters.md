# ADR-0018: Full Access adapters v0.4 — process, application, desktop

Date: 2026-10-02
Status: accepted
Context: spec §14.2/§27 (Phase 4), owner decision "Linux dulu"

## Decision

Three adapters complete the §27 Full Access set (terminal + filesystem already
existed since v0.1):

**Process adapter** (`process.read` / `process.control`)
- list: walks `/proc` directly (pid, name, is_self) — no shell, no `ps`
  dependency, capped at 500 entries with a truncation flag.
- kill: `libc::kill(2)` (TERM default, KILL with force). Guards: PID ≤ 1 and
  the frtrol daemon itself are **protected** — a compromised agent must not be
  able to murder the gatekeeper (§27). ESRCH = idempotent success.
- Every kill (success AND refusal) is audited (Invariant 8).

**Application adapter** (`application.launch` / `application.close`)
- launch: detached spawn (stdio null, scrubbed env, cwd = home root, tokio
  orphan-reaper — no zombies, survives the daemon). Output is NOT captured —
  that's exec/term's job (Rule 1: one mechanism per job).
- close: same guards as process kill, TERM, audited as app.close.
- The policy denylist applies to launches (a launch IS an execution).

**Desktop adapter** (`desktop.read` / `desktop.input`)
- screenshot: fixed argv to ImageMagick `import` / `scrot` (no user input on
  any command line, §77); input: `xdotool type`.
- **Fail closed** when headless: clean machine error `desktop_unavailable`
  (409) instead of a crash or silent no-op. Verified by e2e on this headless
  box; the with-display path is NOT VERIFIED here (no graphical session
  available in CI) — documented honestly.

All six endpoints sit behind the same pipeline as everything else:
full_access authorize → policy → adapter → audit. Scope gate runs BEFORE
availability checks (terminal_only gets `scope_denied`, not
`desktop_unavailable`).

## Alternatives rejected

- `ps`/`sh -c kill` shell outs: adds PATH-dependent parsing + §77 risk.
- Tracking "apps FARcontrol launched" in a registry to limit close: state +
  complexity; the kill guards already protect the system-critical targets.
- X11 protocol clients / wayland libs: large dependency tree for a capability
  that is optional on servers — fixed external tools + fail-closed is narrower.

## Evidence

- Unit: 6 adapter tests (list+is_self, cap, guards PID1/self, idempotent-kill,
  detach+cleanup-kill, headless). Mutation check: guards disabled → red.
- e2e §20 (14 checks): scope gate (ps+shot on terminal_only), list+is_self,
  launch→running→kill→dead, PID 1 + daemon kill_refused, policy_denied on
  launch, desktop_unavailable ×2 (clean fail-closed), audit events.
