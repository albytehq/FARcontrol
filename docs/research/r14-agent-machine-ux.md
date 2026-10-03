# R14 — AI-Agent-Facing UX (machine-readable design for the second user)

> Research pass 14/15 · Mission 1.2.0 · Sources: agent-native CLI writing
> (r14a: InfoQ "Patterns for AI Agent Driven CLIs", openstatus.dev dual-mode
> CLIs, HN thread "Principles for agent-native CLIs"), MCP design guidance
> (r14b: AWS builder best practices, conduit issue #191, lasso.security MCP
> overview), v1.1 baseline (--json everywhere observed, ADR-0026).
> Raw: raw/r14a.json, raw/r14b.json

## The second user is a program

1. **Dual output mode is table stakes** (r14a, InfoQ): every command needs a
   machine-friendly escape hatch — flags/env vars for every interactive prompt,
   semantic exit codes, structured errors. v1.1 already ships this
   (ADR-0026: global `--json`, stable envelope, exit codes 0–7) — the v1.2 job
   is to keep the contract while the flows change, and to extend env-var
   coverage to the new session credentials.
2. **The counterintuitive HN finding** (r14a): for SMALL data read by an LLM,
   natural-language plain text can beat JSON; tables can confuse. Practical
   reading: pretty output is already agent-parseable when line-oriented and
   consistent — keep receipts one-line (v1.1 does), keep `--json` for
   programmatic use. No third format (Rule 1).
3. **Prompts must have env-var twins** (r14a): interactive asks (Device ID,
   Session Password) need `FARCONTROL_DEVICE` + `FARCONTROL_SESSION_PASSWORD`
   so an agent can bootstrap unattended; missing-prompt-in-non-TTY must be a
   clear error ("no TTY and FARCONTROL_SESSION_PASSWORD unset — FRT-0xx"), not
   a hang.
4. **MCP lessons for tool-shaped errors** (r14b): validate inputs against
   schema; return meaningful errors (what failed + which parameter); make
   state discoverable. Mapped to FARcontrol: `frtrol agent status --json`
   (full runtime state, r8), error envelope gains `"hint"` (r9), and every
   long-running action reports BOTH terminal and intermediate states.
5. **Secrets in machine output**: `--json` for owner commands MAY contain
   credentials ONLY where the human mode does (device add, session start) —
   stdout of the owner box is the intended channel; the agent-side runtime
   must persist its session key 0600 and never print it back (v1.1 behavior).
6. **Predictability beats cleverness**: stable field order, stable IDs, ISO
   timestamps, additive-only schema changes (ADR-0022 retention rule) — an AI
   consuming the CLI builds a model of it; churn breaks that model silently.

## FARcontrol v1.2 adoption decisions

- Every new command ships with: non-interactive flags + env twins, `--json`,
  exit-code mapping, one-line receipts, and errors from r9's format.
- `frtrol agent` bootstrap: `--device` flag + env pair; non-TTY without env =
   fail-closed with FRT code + hint.
- Keep agent exec/read byte passthrough (`--raw` semantics, ADR-0026) — the
  agent's toolchain depends on it.
- Additive JSON schema only; document the schema in README (v1.1 promise
  continues; any breaking change gets a migration note per master prompt §34).

## Honest gaps

- No MCP server is being built in v1.2 (out of scope, master prompt §46);
  MCP citations inform error/verbosity design only.
