# EVIDENCE-002 — v0.9.0 hardening (ADR-0023)

Date: 2026-10-02 · Verdict: **VERIFIED** (environment-limited keyring path documented below)
Scope: progressive auth backoff (SC-01) · startup config validation (SC-02) · OS keyring secret store (ID-04)
Report: `farcontrol/reports/verification-output.txt` (78 unit + 161 e2e ALL GREEN · clippy 0 · cargo-audit 1 pre-existing allowed warning (unmaintained `serial`) · secret-scan CLEAN · SBOM 220 crates)

## 1. What was built (ADR-0023)

1. **Progressive lockout (SC-01)** — a strike counter on top of the v0.2 burst window:
   strikes ≥ 10 → lock `60s × 2^(strikes−10)` capped 3600s; **every attempt while locked extends
   the lock**; only a *successful* HMAC auth resets both layers; in-memory (restart clears —
   documented); audited as `auth.backoff` only on lock-duration change (bounded rows).
   Applies to the agent plane + web-UI login; the admin plane deliberately stays unlocked so
   the owner's approve/revoke/panic path works *during* an attack.
2. **Startup config validation (SC-02)** — `Config::validate()` in `init` AND `run`, before
   any bind/state open: binds parse + port ≠ 0 + admin loopback; policy/audit/identity
   recognized keys type- and range-checked. Fail → `config_invalid: …` → **exit 2** (§66).
   `doctor` config check upgraded parse → parse+validate.
3. **OS keyring (ID-04)** — `[identity] secret_store = "keyring"`: agent token in the Linux
   kernel keyring via raw `add_key(2)`/`keyctl(2)` (persistent ring → user-ring fallback);
   no plaintext file, no `agent_token` DB row; per-request load (rotation instant);
   rotate updates the key in place; backup materializes the token into the archive and
   unlinks the file after; restore writes it back into the keyring and removes the file;
   doctor gains a `secret_store` check.

## 2. Verification (all commands in reports/verification-output.txt)

| Control | Test | Result |
|---|---|---|
| lock math (pure) | unit `lock_math_escalates_and_caps`, `apply_strike_sets_lock_and_extends` | PASS — 60→120→240→3600 cap; below-threshold = 0; capped strikes change nothing |
| escalation on the wire | e2e §29 | PASS — 429 "progressive backoff, retry in 4s"; hammering extends 4s→8s; valid token blocked while locked (fail closed); restart clears; `auth.backoff` audited |
| recovery | e2e §14/§21 | PASS — after the (now longer) lockout window, ping OK |
| validation | unit ×4 (binds/policy/audit/identity) | PASS |
| validation on the wire | e2e §30 | PASS — 5 bad configs (non-loopback admin, negative hours, ttl 0, bad secret_store, negative max_events) → exit 2 + `config_invalid`, no state.db created; a valid custom config still starts |
| keyring backend | e2e §31 (branch on env probe) | PASS — in a fully working kernel keyring: no plaintext file, token absent from state.db, exec works, restart+rotate+doctor+backup/restore round-trip. In THIS sandbox: **refused** (below) |
| keyring fail-closed | e2e §31 else-branch | PASS — init refuses with exit 2 `config_invalid … keyring` **before** creating any state |

## 3. Mutations (each: inject → e2e red → revert → green)

| ID | Mutation | Expected red | Observed |
|---|---|---|---|
| M1 | `lock_secs()` returns 0 (escalation disabled) | §29 | RED — "no progressive lockout message" (160/1) |
| M2 | `Config::validate()` returns Ok (validation disabled) | §30 | RED — 10 failures: bad configs accepted, state.db created (151/10) |
| M3 | `keyring::usable()` returns true (probe disabled) | §31 | RED — half-init: daemon starts, then "agent token missing from the kernel keyring" instead of the clean refusal (159/1) |

## 4. Environment limitation (honest, investigated to the bottom)

This sandbox (gVisor-style) implements the kernel keyring **partially**: `add_key`/`UPDATE`/
`UNLINK` succeed, but `KEYCTL_READ`/`KEYCTL_SEARCH`/`DESCRIBE` return EINVAL/ENOKEY/EACCES
even with correct syscall constants (probed with three standalone C programs —
`scripts/keyring_probe*.c`). A secret stored here would be **unrecoverable**.

Response (fail-closed design, ADR-0023): `keyring::usable()` = full store→load→remove
roundtrip probe; keyring mode is only offered when the environment can actually read the
secret back. In this sandbox the probe fails → `frtrol init` refuses with exit 2 and a clear
message (verified e2e §31). On a real Linux kernel (syscall constants validated against
include/linux/keyctl.h: SEARCH=8, READ=9, UNLINK=7, GET_PERSISTENT=16) the full path runs;
the unit tests skip loudly (`SKIP: kernel keyring not fully usable…`) rather than fake green.

## 5. Not verified / known gaps

- Full keyring happy-path e2e executed only where the kernel keyring is complete (not this
  sandbox). The fail-closed refusal path IS verified here. Owner: run
  `FARCONTROL_E2E_ONLY=31 bash scripts/e2e.sh` once on a real Linux box.
- The lockout is in-memory: a daemon restart clears strikes (documented trade-off — same as
  the v0.2 window; persistence would let an attacker DoS the counter itself).
- Admin-plane brute force is throttled only by the shared window (deliberate: owner path
  must survive an active attack; §97-14).
- Desktop on-display adapter path remains NOT VERIFIED (no X/display tools in this env —
  unchanged since v0.4, no sudo to install).
- cargo-fuzz coverage-guided fuzzing still deferred (deterministic corpus + seeded random +
  concurrent chaos remain the fuzz evidence, ADR-0019).
