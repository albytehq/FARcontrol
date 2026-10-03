# EVIDENCE-004 — v1.2.0 ephemeral session credentials + agent connect/runtime + console v1.2

- Version: 1.2.0 · Date: 2026-10-03 · Verdict: **VERIFIED**
- Method: 104 unit tests, 262-check e2e (39 sections), 4 new mutation checks
  (M-1 state / M-2 host guard / M-4 password verify / M-6 migration lock), 37-check
  §50-DoD smoke run by hand with written predictions, browser-driven console v1.2
  (agent-browser), cargo-audit (0 CVE), secret-scan (clean), clippy `-D warnings` (0).

## What was verified

| Claim | Evidence |
|---|---|
| `frtrol start` mints ephemeral credentials; password printed exactly once | e2e §1 (box parse + once-only + second-start refusal + bind-before-mint) |
| Restart rotates password + key + admin token; old ones dead | e2e §16 (old key → invalid_signature, runtime → expired, creds cleared, re-connect) |
| Login v1.2: password → session key, no key rotation, agent_name recorded | e2e §1/§19; auth.login audit with declared name |
| `frtrol agent` connect flow (ladder, TOFU, connection.json 0600) | e2e §1, §33; §35 (`--expect-fp` match + mismatch exit 3 + no login + evil pin removed) |
| agentd survives CLI exit; heartbeat map; terminal states clear creds | e2e §33 (pid alive, idempotent connect, owner status --json agents), §16/§18 (expired + cleared), smoke §4/§6 |
| `frtrol agent status/stop` | e2e §33 (status/json/stop/receipt, connection.json cleared) |
| `frtrol stop` + /admin/shutdown | e2e §1→§16 chain (stop used between all sections), smoke §9 |
| CLI surface v1.2 (device cmds / agent login / --token gone) | e2e §0 (guide clean), §39 (removed commands refused) |
| Console v1.2 (session header, agent chips, tabs, PANIC persistent, rotate) | e2e §38 (state payload, /ui/rotate CSRF + fields, host allowlist) + browser: login → session view → agent chip visible → Advanced (rotate/stop); screenshots in reports |
| Host allowlist (DNS rebinding) | e2e §38 (evil Host → 403 on admin plane; agent plane unaffected → 401) |
| v1.1 registry migration (locked + keys rotated + grants revoked + audited) | e2e §36 (audit event, row-level SQL proof, legacy login + key dead, headerless 401, machine connect works) + unit tests in state.rs |
| Rate limiting / progressive backoff v1.2 semantics | e2e §14 (7 wrong passwords → 429, correct password refused while locked, recovery), §29 (extension + valid-key blocked), §34 (per-principal isolation via webui) |
| Exit-code contract §66 | e2e §25 (0/2/3/4/5/6/7, including new invalid_credentials→3 and transport→6) |
| Secret hygiene (canary) | e2e §33 (key/password absent from agent-side logs + status.json), §12 (audit scan), smoke §8/§12 |

## Bugs found by this verification pass (all fixed in-tree, each with a red test)

1. **Rotate/panic bricked the owner CLI** — the daemon's in-memory admin token was
   never updated at any rotation site; after `frtrol rotate` every owner command failed
   `admin_auth_failed` until restart. Fixed: `App.admin_token` is a live `Mutex<String>`
   updated by admin_rotate / admin_panic / ui_rotate / ui_panic. (e2e run 2)
2. **Innocent lockout inheritance** — the global auth-burst branch copied the storm's
   strike count onto whichever principal called next, so a valid agent runtime
   heartbeating beside a login brute-force wedged its own progressive lock
   (self-extending). Fixed: the burst refuses for its window without touching
   per-principal strike state. (e2e run 1, §15 cascade)
3. **Failed second start rotated live credentials** — mint happened before the port
   bind check. Fixed: bind-before-mint. (smoke, prior session; e2e §1 now proves it)
4. **agentd stop latency / stale runtime** — SIGTERM waited out the current backoff nap
   (up to 60 s). Fixed: term-aware sleep + SIGKILL escalation. (browser test, prior
   session; e2e §33 now proves the stop)
5. **Banner extraction trap** — the web-console hint line contained "admin token",
   breaking `grep 'admin token'` extractions (multiline token → 422s). Fixed: value
   labels are unique in the box. (e2e run 3, §34/§38)
6. **Exit-code contract holes** — `invalid_credentials` exited 1 (not 3) and agent
   subcommand transport errors exited 1 (not 6/5). Fixed: error.rs mapping +
   `call_net`. (e2e run 4, §25)
7. **ADR-0029 drift** — `--expect-fp` was promised by the ADR but never implemented.
   Implemented + e2e §35 (mismatch aborts pre-login, evil pin never left behind).

## Mutation checks (this pass)

| ID | Mutation | Expected red | Result |
|---|---|---|---|
| M-1 | state.rs: session-model rotation skipped | session-model unit tests | red → revert → green (prior session) |
| M-2 | server.rs: `host_allowed` → always true | §38 evil-Host 403 | red ("evil host → 401") → revert → green |
| M-4 | server.rs: login password verify neutered | §14 lock + §17 old-password + §25 rc3 | red (all three) → revert → green |
| M-6 | state.rs: migration lock skipped (`stale = []`) | §36 row-proof + legacy-key dead | red (both) → revert → green |

## Wall (final, v1.2.0 binary)

```
cargo clippy --all-targets -- -D warnings ... 0 warnings
cargo test --release .......................... 104 passed, 0 failed
bash scripts/e2e.sh ............................ 262 passed, 0 failed (exit 0)
bash scripts/smoke_1.2.sh ...................... 37/37
cargo audit .................................... 0 vulnerabilities (1 pre-existing allowed advisory)
scripts/secret-scan.sh ........................ clean
browser (agent-browser) ....................... console v1.2: login, session header,
                                                agent chips, Advanced rotate/stop; no JS errors
```

## Not verified (honest list)

- Desktop adapters on a real X display (headless environment; fail-closed path
  verified instead — e2e §20g).
- Kernel-keyring full path (sandbox has a partial keyring; the fail-closed refusal
  path is verified — e2e §31. On real Linux kernels the full path applies).
- mDNS/LAN discovery explicitly rejected for v1.2 (ADR-0029 design 2) — cross-network
  agents use `--url`/env once, documented in README.
