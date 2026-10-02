# ADR-0013: Interactive terminals (PTY) per approved session

Date: 2026-10-02 · Status: ACCEPTED (owner: "bangun sampai benar-benar bisa digunakan")

## Context
v0.1 exec is one-shot (spawn → capture ≤256KiB → return). Real agent work often
needs an interactive shell (installers, REPLs, long processes).

## Decision
Add a PTY terminal registry in the daemon:
- `POST /v1/term/open` (session + command) → `trm_...` id, max 8 concurrent
- `POST /v1/term/write` (stdin, ≤64KiB/chunk) · `POST /v1/term/read` (drain, b64)
- `POST /v1/term/close` — kill + reap
CLI: `frtrol agent term <ses> <cmd...>` pipes stdin/stdout (ssh-like).

Invariants kept: every call re-authorizes the session; terminals are killed on
revoke/expiry/panic (sweeper reaps strays ≤30s); denylist + env-scrub apply;
output drained per read is policy-capped; rolling 1MiB buffer per terminal.

## Consequences
+ Real interactivity for agents and humans, AI-friendly polling API.
- Polling (not push) — streaming responses deferred to v0.3.
