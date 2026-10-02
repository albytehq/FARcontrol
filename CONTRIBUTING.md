# Contributing

First: FARcontrol's whole value proposition is *"the owner would trust this on their own
laptop, and can prove why."* Contribution bar follows from that.

## The wall

A PR is mergeable when it passes, in CI, with zero special cases:

```bash
cargo clippy --all-targets -- -D warnings
cargo test                # 78+ unit tests, includes the in-process fuzz suite
bash scripts/e2e.sh       # 172+ end-to-end checks, runs the real daemon
```

If your change touches anything security-relevant, add the mutation check: deliberately
break your control (comment out the guard, make the function return success), show the
suite going **red**, then revert. Paste that output into the PR. A control that cannot be
observed failing is a control we cannot claim works.

## Design changes start in an ADR

Anything that changes *why*, not just *how* — new endpoints, new secret storage, policy
semantics, scope changes — gets an ADR in `docs/adr/` (see `docs/templates/adr.md` for
the shape) **before** the diff. Number it sequentially, state the context and the
consequences honestly, including what gets worse.

## Project conventions worth knowing

- **Fail closed.** When in doubt, deny. Daemon down, DB broken, keyring unreadable, clock
  insane: all of those are *deny* paths. An error that allows is a bug class of its own.
- **No new dependencies without a fight.** The crate count is 220 and the SBOM is
  reproducible from `Cargo.lock`; keep it that way. (`cargo audit` and `scripts/sbom.sh`
  run in CI.)
- **Secrets never touch logs, audit rows, argv, or error strings.** Audit is
  metadata-only: ids, scopes, byte counts, durations.
- **The CLI stays positional.** `frtrol agent exec ses_x ls -la` — no `--`, no
  `--session-id`. The agent side is driven by LLMs; every symbol is a typo risk.
- **Honest tracking.** If your feature lands partial, `tracking/PROGRESS.md` says
  PARTIAL with what's missing — never VERIFIED with an asterisk.
- Linux x86_64 only (ADR-0002). Anything needing root is a design smell (the daemon
  refuses to run as root; override exists for containers, use it nowhere else).

## Test topology

- **Unit tests** (`cargo test`): pure logic + in-process router tests, including the
  fuzz corpus. No network, no daemon, no flakiness budget.
- **e2e** (`scripts/e2e.sh`): the real binary, real TLS, real PTYs, real kills — 30+
  sections, self-contained, `FARCONTROL_E2E_ONLY="29,30,31"` runs just the numbered
  sections (that's how the mutation checks stay fast).
- **Evidence** (`tracking/evidence/`): what a human should read to believe a claim.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — private disclosure, not issues.
