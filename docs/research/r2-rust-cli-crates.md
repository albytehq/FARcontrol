# R2 — Rust CLI Rendering Crate Selection

> Research pass 2/5 · Mission 1.1.0 · Sources: docs.rs/lib.rs/crates.io, rust-cli-recommendations
> (sunshowers), libhunt comparison. Raw: raw/r2a.json, raw/r2b.json

## Candidates

| Need | Candidates | Verdict |
|---|---|---|
| Tables | comfy-table, tabled, prettytable-rs, csview | **comfy-table 7.x** |
| Colors | owo-colors, anstyle, colored, yansi | **owo-colors** |
| Progress/spinner | indicatif | not needed (no long ops on owner side; daemon start is fast) — skip dep |

## Why comfy-table over tabled

- Purpose-built "beautiful terminal tables, easy to use"; every part customizable.
- No derive-macro machinery (tabled leans on `Tabled` derive — more compile surface).
- Content wrapping + dynamic width arrangement handles our long fields (reason text,
  audit message) without manual width math.
- Actively maintained (v7.1.4); used widely; docs.rs quality high.
- Styling API maps 1:1 to our needs: header bold-ish, preset `ASCII_FULL` in pipes,
  UTF8 full when TTY.

## Why owo-colors over anstyle/colored

- Recommended by rust-cli-recommendations ("only library I've found" re: correctness).
- Built-in: NO_COLOR / FORCE_COLOR env handling, TTY detection, CI detection
  (zero-surprise in e2e harnesses — important: our e2e greps output).
- Zero allocations, no_std-capable, drop-in `colored` replacement.
- anstyle is fine but styled for building style strings (anstyle-query etc.) —
  owo-colors is one crate, less plumbing for our scale.

## Binary/dependency cost

comfy-table + owo-colors add ~2 crates, no transitive bloat worth worrying about;
cargo-audit will re-verify at Done Gate. Binary stays ~8 MB.

## NO_COLOR / pipe policy (testable)

1. TTY → UTF8 table + colors.
2. Not a TTY (pipe/CI) → plain ASCII table, no colors, same alignment.
3. `NO_COLOR=1` → colors off even on TTY.
4. `--json` → no styling at all, pure machine JSON to stdout (errors still JSON to stderr? —
   no: errors as JSON envelope to stdout with nonzero exit, consistent with 1.0 envelope
   convention, simpler for agents to parse).
