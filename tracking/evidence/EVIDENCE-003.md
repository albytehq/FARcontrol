# EVIDENCE-003 — v1.1.0 device authentication + CLI v2 + console v2

- Version: 1.1.0 · Date: 2026-10-02 · Verdict: **VERIFIED**
- Method: unit tests, e2e §33–39 (+ full 0.1→1.1 regression), 3 new mutation checks,
  browser-driven console flows, independent VLM design review, cargo-audit, secret-scan,
  SBOM, clippy.

## What was verified

| Claim | Evidence |
|---|---|
| Device registry (add/list/lock/unlock/passwd/remove) | e2e §33 (full lifecycle), §37 (--json) |
| Login → key exchange (Argon2id, rotation per login) | e2e §33/§36, unit `argon2_roundtrip_and_reject` |
| FAR id check char catches single typos client-side | unit `device_id_format_and_checksum` (200 ids), e2e §33 |
| Per-device progressive backoff (one device ≠ all devices) | unit `backoff_is_per_principal`, e2e §34 |
| Fingerprint TOFU: capture + pin + strict `--expect-fp` | e2e §35 (match, mismatch abort exit 3 BEFORE password) |
| Legacy v1.0 migration (token → key-only device; headerless compat) | e2e §36 |
| Fresh install rejects headerless requests | e2e §36 (no_legacy_device, fail closed) |
| Sessions/requests/audit bound to device | e2e §33 (list --json), §33 (approve receipt) |
| Panic rotates every device key + recovery via re-login | e2e §18/§32/§38 |
| CLI v2 contract (tables, glyphs, hints, NO_COLOR, pipe-safe, --json) | e2e §39, §37, unit `out::tests` |
| Console v2 (login, CSRF on new endpoints, device add, state payload, panic) | e2e §38 (curl-level) + browser run (zero console errors) |
| Console security invariants kept (no HTML sinks, no external assets) | e2e §38 grep checks + code review |
| Backup/restore carry device keys (file + keyring map) | e2e §22 (updated: re-login recovery path) |
| Doctor v1.1 checks | e2e §13/§32 (ALL GREEN) |

## The verification wall (2026-10-02)

```
unit tests ......... 104 passed
e2e checks ......... 231 passed, 0 failed   (39 sections)
mutation checks .... 9 total (6 prior + M1 device-lock, M2 login-backoff, M3 TOFU)
browser console .... zero JS console errors across the v2 flows
VLM design review .. 8/10, no visual bugs
clippy ............. 0 warnings
cargo audit ........ 0 vulnerabilities (1 pre-existing allowed: unmaintained serial)
secret scan ........ CLEAN
SBOM ............... 239 crates (SPDX, offline from Cargo.lock)
```

## Mutation checks (v1.1)

| # | Mutation injected | e2e result | Reverted |
|---|---|---|---|
| M1 | locked-device guard bypassed | §33 RED (1 FAIL — key rotation caught it: defense in depth) | ✓ green |
| M2 | strike escalation disabled | §29/§34 RED (2 FAIL: lock not extended, no auth.backoff audit) | ✓ green |
| M3 | TOFU fingerprint compare disabled | §35 RED (1 FAIL: mismatch not aborted, rc=0) | ✓ green |

## Real bugs found & fixed DURING this verification (the discipline working)

1. **Deadlock in verify_agent** (mutex re-acquired on the same thread after the
   rate-limit reordering) — e2e hung; scoped the guard.
2. **5 deadlocks in the new console device handlers** (ui_audit called while holding
   the DB lock) — curl probe hung; scoped every handler.
3. **Unthrottled rejection path**: headerless/unknown-device floods were rejected
   before any rate-limit check (new in 1.1's device resolution order) — moved the
   brake ahead of resolution.
4. Doctor failed on fresh 1.1 installs (agent-token file expected); restore required
   v1.0 files; keyring backup materialized the wrong artifact — all fixed + e2e'd.
5. Device-id checksum inconsistency (gen vs valid used different math) — caught by
   smoke test before any release.

## Gaps (honest)

- TOFU first-connect residual risk (same as SSH "type yes" reality): documented
  ADR-0025 §4, mitigated by `--expect-fp` + high-entropy passwords + backoff.
- Full kernel-keyring device-map path only provable on a real kernel (sandbox keyring
  partial — fail-closed refusal verified here; unchanged since v0.9).
- Console visual review is one reviewer pass (VLM) + browser smoke; no dedicated
  cross-browser matrix.
