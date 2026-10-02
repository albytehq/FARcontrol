# ADR-0026 — v1.1.0: CLI v2 — enterprise output (gh-style) + global --json

- Status: ACCEPTED (owner instruction 2026-10-02: "CLI nya masih belum enterprise like,
  belum bagus tampilan outputnya" + chose "gh style" + "--json ya")
- Date: 2026-10-02
- Research: docs/research/r1-enterprise-cli.md, r2-rust-cli-crates.md, r5-synthesis-spec.md
- Supersedes: partially ADR-0022 §CLI presentation (command SYNTAX unchanged — only
  presentation changes)

## Context

1.0.0 CLI prints raw JSON envelopes and unadorned lines. For an owner deciding whether
to approve access in a terminal, that is noise: no visual hierarchy, no status at a
glance, no machine-stable mode for scripts/AI agents (they had to regex raw output).

## Decision

### 1. Crates

- **comfy-table 7.x** for tables (dynamic width, wrapping, presets: UTF8_FULL on TTY,
  ASCII_FULL when piped).
- **owo-colors 4.x** for color + built-in NO_COLOR / not-a-TTY / CI detection
  (research R2 verdicts).
No progress-bar crate (no long-running owner ops).

### 2. Rendering contract (every owner command + agent ping/status/request/login)

| Mode | Behavior |
|---|---|
| TTY | UTF8 table, colors, glyphs, dim hints |
| pipe / CI | ASCII table, no color, glyphs still printed (shape-carried meaning) |
| `NO_COLOR=1` | color off, tables remain |
| `--json` (global) | pure machine JSON to stdout, no styling, nonzero exit on error, error = existing `{error:{code,message}}` envelope |
| `agent exec/read/term` | **byte-exact passthrough, never tabled** (`--raw` semantics stay default for exec output) |

### 3. Status glyphs (colorblind-safe: glyph shape + color + word, R1)

`●` ok/active (green) · `◐` pending/warn (cyan/amber) · `○` quiet/expired (dim) ·
`●` revoked/error (red). Never color alone.

### 4. Content rules

- Durations humanized (`4h 51m left`, `about an hour ago`); absolute timestamps
  compact (`Oct 02 14:28`); raw epoch only in `--json`.
- Tables ≤100 cols, middle-truncate long text with `…`; full value always in `--json`.
- Receipt lines for actions: `✓ approved req_ab12cd → ses_cd34ef (5h, terminal_only,
  device FAR-7K2M-QX94)` / `✗ …` on failure.
- Dim `tip:` hint lines under tables (verb-led, e.g. `tip: frtrol approve req_ab12cd`).
- Informative empty states ("No pending requests — nothing is waiting on you. ✓").
- Errors: what happened (short, red) + why + what to do (dim hint); machine detail
  stays in `--json`.
- `start` banner redesigned as a boot panel: version, planes, data dir, policy,
  **daemon cert fingerprint**, and the web console URL — printed once, gh-style block.

### 5. --json schemas (stable, documented in README)

`status` → `{version, uptime_secs, agent_bind, admin_bind, pending[], sessions[],
devices[]}` · `list` → `{pending[], sessions[]}` · `device add` →
`{device_id, name, password}` (password included — it IS the point) · `audit` →
`{events[]}` · `doctor` → `{checks[{name, ok, detail}]}` · agent `ping`/`status`/
`request`/`login` mirror the wire envelopes. Schema changes are additive-only within
1.x.

## Consequences

- e2e harness switches machine assertions to `--json` (kills output-fragility), while
  new "pretty" checks pin the visual contract (table alignment, glyphs, NO_COLOR).
- Cargo gains comfy-table + owo-colors (cargo-audit re-verified at Done Gate).
- Exit codes unchanged (ADR-0022 §66 classification preserved).
