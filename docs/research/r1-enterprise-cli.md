# R1 — Enterprise CLI Output Design (gh / kubectl / industry)

> Research pass 1/5 · Mission 1.1.0 · Sources: cli.github.com manual, heaths.dev (gh 2.0 table
> formatting), evilmartians.com CLI UX, UX-writing articles, dev.to "Designing CLI Tools".
> Raw snippets: raw/r1a.json, raw/r1b.json

## What the industry standard (gh-style) actually does

1. **Dual output mode is THE pattern.** Every list/status command has a human table AND
   `--json` (+ optional `--jq` filtering). Human and machine never share one format:
   - pretty: aligned table, color accents, humanized fields
   - `--json`: stable schema, no color, no decorative text, exit code carries status
2. **Humanized values.** Durations render as `2h 15m left`, timestamps as relative
   (`about an hour ago`) or short absolute (`Oct 02 14:28`). Raw epoch/ISO only in `--json`.
3. **Status via symbol+color PAIRS, never color alone** (colorblind-safe):
   `● active` (green), `◐ expiring` (amber), `○ expired` (dim), `● revoked` (red).
   The glyph shape differs too, so meaning survives color loss and NO_COLOR.
4. **Hint lines are dim gray, verb-led, below the table**: e.g.
   `tip: frtrol approve req_ab12 to grant 5h terminal-only`.
   gh does this after command output ("run gh pr view 12 to view").
5. **Empty states are informative, not blank**: "No pending requests — nothing is waiting
   on you. ✓" beats a bare table with headers only.
6. **Errors = three parts**: what happened (red, short), why (plain), what to do next
   (dim hint). Never a stack-ish dump; keep the machine detail in `--json`.
7. **Action results are receipts**: `✓ approved req_ab12 → ses_cd34 (5h, terminal_only)`
   single line, green check; failure `✗ denied …` red. After-state, not just "OK".
8. **Progress for long ops**: spinner or "x of y" pattern; daemon `start` prints a
   boot panel (gh style header block) then flips to "waiting…" status line.
9. **Columns truncate middle/smart** with ellipsis so 80-col terminals stay aligned;
   full values always in `--json`.
10. **NO_COLOR + not-a-TTY auto-disable styling** (pipe safety); tables degrade to
    plain aligned text, exit codes stay authoritative.

## FARcontrol adoption decisions

- Global `--json` flag on every owner command (status, list, approve/deny/revoke,
  device *, audit, doctor, agent status/request …). Schema documented in README.
- Symbol+color status dots, humanize helpers, dim hints, receipt lines — as above.
- `--raw` (agent exec/read) unchanged: stdout passthrough remains byte-exact.
