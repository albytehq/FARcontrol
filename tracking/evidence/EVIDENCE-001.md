# Evidence Report — v0.1.0 walking skeleton (full vertical slice)

**Verdict:** `VERIFIED`
**Date / commit:** 2026-10-02 / no git yet (single-crate build, source at `farcontrol/`)
**OS / environment verified on:** Debian (Linux x86_64, gcc 14, Rust 1.99.0). **NOT verified on:** macOS, Windows, any other Linux distro/kernel — do not claim otherwise.

## 1. What this covers
The v0.1.0 vertical slice per ADR-0000: session lifecycle (request → approve/deny → exec → revoke → expire), HMAC authentication with anti-replay, scope + policy enforcement, file operations under `$HOME`, audit trail, state persistence across restart, token rotation. REQ families touched: ID-02/03/06/09, ST-01/02, RQ-01…RQ-11 (subset), SE-01/03/05/06, AC-01/09 (files only), TM-01/02/03/07/08 (one-shot), AD-01/02/03/05/06, CL-01/02/05/07. 36 unit tests + 46 e2e checks.

## 2. Done criteria (written BEFORE the code)
- `cargo test` green (crypto vectors, policy floor/caps/denylist, state lifecycle incl. scope/expiry/revoke/replay, files guards, exec timeout, auth verify).
- `scripts/e2e.sh` green: every invariant produces an observable machine-readable outcome (error codes, exit codes, JSON fields).
- Binary builds with `cargo build --release`, single file, no `unsafe` in application code.

## 3. How to reproduce (from a clean state)
```
cd farcontrol
cargo test                      # 38 unit tests
cargo build --release
./scripts/e2e.sh                # 46 checks (sets FARCONTROL_TEST_MODE=1 itself)
cat reports/verification-output.txt
```

## 3b. Prediction (written BEFORE running)
Request without approval → no session id exists → exec fails `session_not_found`; after approve → exec returns marker in stdout; scope violations → `scope_denied`; tampered/replayed request → 401 codes; revoke/expiry → `session_revoked`/`session_expired`; daemon kill → agent network error; restart → active session still usable; rotate → old token `invalid_signature`.

## 4. Observed result
```
=== RESULT ===
  passed: 46
  failed: 0
  ALL GREEN — FARcontrol 0.1.0 e2e verification PASSED
```
Full raw output (122 lines): `farcontrol/reports/verification-output.txt` — includes all 14 sections: init/start, unsigned 401, HMAC ping, deny path, approve→exec, scope enforcement, policy denylist + timeout, self-revoke, full_access file roundtrip + escape rejection, owner revoke, expiry, audit completeness, restart persistence, token rotation.

## 5. WHY it works *(Rule 2 — mandatory)*
Every capability handler calls `state::authorize_session` BEFORE doing work. That function re-reads the session row from SQLite on every call, compares `expires_at` to `now()`, persists expiry lazily (audit `session.expired`), and matches status+scope — so there is no code path from "request bytes" to "process spawn" that skips a live DB check. Authentication is a separate gate (`verify_agent`): HMAC over (timestamp, nonce, method, path, body-hash) keyed by the agent token, nonce single-use via PRIMARY KEY insert, comparison constant-time, window ±300s. Because auth and authz are independent, a stolen/replayed/old token still cannot act, and a valid token without an active session can do nothing but ask. Expiry is doubly enforced (lazy per-op + 30s sweeper); token rotation is effective per-request because the token is read from the DB, never cached in memory.

## 6. Failure signature + mutation check
- If it did NOT work I would see: exec succeed with `pending`/`revoked`/`expired` session; missing 401 on unsigned curl; audit rows absent; old token still valid after rotate.
- I broke it by: (a) serving stale in-memory token (pre-fix) → e2e §14 "old token still works" FAILED → fixed by DB-read-per-request → restored: yes, now passes; (b) `set -e` leak in e2e harness (not product) → script died silently at §13 → fixed → restored: yes.
- Deliberate attack attempts in §7 all produced the predicted refusal, not a crash.

## 7. How I tried to break it
| Attack / edge case | Result |
|---|---|
| Unsigned HTTP request to agent API | 401 `missing_headers` + audit `auth.rejected` |
| Valid signature, wrong key (simulated stolen-but-wrong token) | 401 `invalid_signature` |
| Tampered body with valid signature (sign `{}`, send evil) | 401 `invalid_signature` (body hash covers payload) |
| Exact replay of a valid request | 401 `replay_detected` (nonce PK) |
| Timestamp ±3600s | 401 `stale_timestamp` |
| Exec on non-existent session id | 404 `session_not_found` |
| File API under `terminal_only` | 403 `scope_denied` |
| `mkfs.ext4 /dev/sda9` | 403 `policy_denied` + audit `exec.denied` |
| `sleep 3` with 300 ms timeout | 200 `{status:"timeout"}`, child killed (<2s observed) |
| Symlink escape + absolute path + `../` path outside root | 403 `path_outside_root` |
| Daemon killed mid-session | agent gets network error (fail closed); after restart session still works (state persisted) |
| Token rotation while old token held | old → 401 `invalid_signature`; new → 200 |
| Second concurrent session approval | 409 `session_limit` (unit test, D-004) |
| Stale pending request (>TTL) approval attempt | 409 `request_not_pending`, status persisted `expired` |

## 8. Invariants and secrets
- Invariants §102: 1 (no approval→no access), 2 (expired), 3 (revoked), 4 (capability), 5 (secret≠session), 6 (identity≠authz), 7 (network fail→closed), 8 (auditable) — all exercised in e2e §4–§13; hold by construction (single authorize gate + fail-closed error paths).
- Canary secret check: `grep -r "test-agent-token" ~/.farcontrol 2>/dev/null` → empty; tokens live in 0600 files/DB meta; audit rows contain ids/scope/bytes only — no token, no command output content, no file content.
- Authorization pipeline bypass possible? **No known path**: both planes (agent HTTP, admin loopback) converge on the same SQLite gate; the CLI never opens the DB directly; there is no third listener.

## 9. Assumptions
None blocking. All design choices the owner delegated ("sisanya rekomendasi aja") are recorded as accepted ADRs 0004–0012, not silent assumptions.

## 10. Not verified / known gaps
- No TLS on the wire (HMAC = auth+integrity, not confidentiality) — ADR-0004, v0.2.
- Interactive PTY/streaming not implemented; exec is one-shot — ADR-0000 deferred.
- Process/desktop/browser adapters of Full Access not in v0.1 (files only) — ADR-0009.
- TOCTOU window on file write (canonicalize→write) — documented, v0.2 (openat2).
- Audit has no hash chain; single-writer SQLite + append-only JSONL only — v0.2.
- No fuzzing run, no external security audit, no load testing (all e2e single-client).
- ID-01/ID-02 formats deviate from spec §7 (prefixed base58 16B / 32B token per ADR-0012, owner-approved recommendation); pending-fix note recorded in DECISIONS D-024.
- Only tested on this Debian sandbox; owner should rerun `cargo test && ./scripts/e2e.sh` on the target machine (Rule 2: verified where run).
