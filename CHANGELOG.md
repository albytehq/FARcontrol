# Changelog

All notable changes to FARcontrol. Versions 0.1.0 → 0.8.0 were internal engineering
milestones (never published as releases, per owner decision D-042); **v1.0.0 and v1.1.0
are the published releases.** Dates are 2026-10-02 (UTC). v1.2.0: 2026-10-03 (UTC).

## [1.2.0] — 2026-10-03

**Ephemeral session credentials: the whole story is now two lines.** `frtrol start` alone
mints the complete credential set — device id + session password + admin token — and
**every one of those dies when that daemon run ends.** The agent connects with exactly
`frtrol agent` (device id + session password, nothing else), keeps working after closing
its terminal via a supervised background runtime, and loses everything (credentials
erased, runtime exited) the moment the owner's session ends. Verified as one wall:
**104 unit tests + 262 e2e checks + 13 mutation checks, clippy 0, cargo-audit 0 CVEs,
secret-scan clean, smoke §50 DoD 37/37, browser-tested console v1.2.**

### Added
- **Ephemeral session model (ADR-0028):** per-`frtrol start` rotation of the session
  password, the HMAC session key, and the admin token. Old passwords/keys are dead the
  moment a new start mints fresh ones — fail-closed by construction (a dead daemon
  authenticates nothing). The machine's device id (`FAR-XXXX-XXXX`) is a stable identity,
  never a secret. `frtrol rotate` re-mints password + admin token mid-run **without
  touching the session key** — connected agents keep working through a rotation.
- **`frtrol agent` connect flow (ADR-0029):** interactive connect with hidden prompts,
  endpoint ladder (`--url`/env → remembered host → localhost), TOFU cert pinning with
  `--expect-fp` strict verification (a mismatch aborts **before** the password is sent,
  and a mismatched cert is never left pinned).
- **Background runtime `agentd` (ADR-0030, hard requirement §17):** the connect flow
  spawns a detached runtime (own process group, single instance per agent home). It
  heartbeats every 15 s so `frtrol status` and the console show **live agent chips**;
  reconnects with capped exponential backoff; and on a terminal state (`expired`,
  `revoked`, `stop`) it **erases its own credentials and exits** — the anti-backdoor
  rule. `frtrol agent status [--json]` and `frtrol agent stop` manage it. Operations do
  not proxy through the runtime — the CLI talks to the daemon directly via the saved
  `connection.json` (0600).
- **`frtrol stop` + `POST /v1/admin/shutdown`:** graceful session end from the owner CLI
  or the console.
- **Host-header allowlist on the admin plane (ADR-0032, r12):** foreign `Host` headers
  get `403 bad_host` — closes the DNS-rebinding class against the cookie path. The
  agent plane (HMAC, no ambient cookies) is deliberately unaffected.
- **Web console v1.2 (ADR-0032):** session-first redesign — header with device id,
  version, uptime, live agent chips (aria-live), persistent PANIC; tabs
  Activity/Sessions/Audit/Advanced; `/ui/rotate` mirrors `frtrol rotate` (new password
  shown once in-modal); login label says the token comes from `frtrol start`; polling
  pauses when the tab is hidden; a11y fixes (WCAG-computed badge contrast, focus-visible,
  aria-labels, in-flight button disabling).

### Changed
- **CLI surface (ADR-0031):** `frtrol device …`, `frtrol agent login`, and the v1.0
  `--token` flag are **removed** (documented breaking change — the registry they
  operated on no longer exists). `frtrol start` prints the session box (r6: ≤15 lines,
  script-safe value labels, operator detail behind `--verbose`); `frtrol status` shows
  the session + live agents; bare `frtrol` prints the v1.2 quick guide.
- **Exit-code contract (§66):** `invalid_credentials` / `invalid_device_id` /
  `device_locked` / `login_disabled` now exit **3** (auth); agent-subcommand transport
  failures exit **6** (unavailable) / **5** (timeout) instead of a generic 1.
- `frtrol panic` output reports the v1.2 rotation set (session password + session key +
  admin token).

### Fixed (all e2e-found, mutation- or smoke-verified)
- **rotate/panic bricked the owner CLI:** the daemon kept the *old* admin token in
  memory after `frtrol rotate` / `frtrol panic` / their console equivalents, so every
  subsequent owner command failed `admin_auth_failed` until restart. The live token is
  now updated in place at every rotation site.
- **Innocent lockout inheritance:** the global auth-burst brake put the storm's strike
  count onto whichever principal happened to call next — a valid agent heartbeat beside
  a brute-force storm could wedge its own progressive lock. The brake now refuses for its
  seconds-scale window without touching per-principal strike state.
- **Failed second start rotated live credentials:** a `frtrol start` against occupied
  ports minted a new credential set *before* failing the bind — killing the running
  session's on-disk credentials. Ports are now claimed **before** any mint
  (bind-before-mint).
- **agentd stop latency / stale runtime:** SIGTERM is now noticed within milliseconds
  (term-aware sleep) instead of after the current backoff nap (up to 60 s), and
  `stop_pid` escalates to SIGKILL so a stuck runtime can never block a reconnect.
- **Banner extraction trap:** the start banner's web-console hint contained the words
  "admin token", poisoning `grep 'admin token'` extractions (value lines must be
  uniquely greppable — r6).

### Migration (v5, automatic at first `frtrol start`)
- v1.1 registry devices → **locked**, keys rotated to noise, their active grants
  revoked, audited as `device.model_migrated`. v1.1 agents reconnect with the new
  session password (same handover UX they already had).
- v1.0 `agent_token` meta is ignored; the headerless request path is gone — fresh
  installs reject it fail-closed.
- The machine device row is created (or reused) with the stable device id; a fresh
  session password + key are minted at every start (ADR-0028).

### Verification (1.2.0 wall)
```
unit tests ...... 104 passed
smoke §50 DoD ... 37/37  (session lifecycle, by hand, predictions written first)
e2e ............. 262 passed, 0 failed  (39 sections; v1.2: session lifecycle,
                  runtime survival, reconnect/expiry, allowlist, canary, migration)
mutation checks .. 13 total: 9 carried + M-1 session model + M-2 host guard
                  + M-4 password verify + M-6 migration lock (each red → revert → green)
browser ......... console v1.2 login → session view → agent chips → Advanced (rotate/stop)
clippy .......... 0 warnings    cargo-audit: 0 vulnerabilities    secret-scan: clean
```

## [1.1.0] — 2026-10-02

**Device authentication: the agent now needs exactly two things.** Owner instruction:
"yang diperlukan agent itu cuman ID device dan passwordnya" — plus an enterprise-grade
CLI and a total console redesign. Verified as one wall: **104 unit tests + 231 e2e
checks + 9 mutation checks, clippy 0, cargo-audit 0 CVEs, secret-scan clean, SPDX SBOM
(239 crates), browser-tested console, VLM design review 8/10.**

### Added
- **Device registry (ADR-0025):** `frtrol device add/list/lock/unlock/passwd/remove`.
  Each device gets a `FAR-XXXX-XXXX` id (Crockford base32 + check char — single typos
  are caught client-side) and an auto-generated password (5 words from a 1024-word list
  + 2 digits ≈ 56.6 bits). Login exchanges the password for a 256-bit per-device signing
  key, rotated on **every** login — a stolen key cannot survive the next legitimate
  login.
- **Login endpoint** `POST /v1/auth/login`: Argon2id (m=64 MiB, t=3, p=1 — above the
  OWASP floor), per-device progressive backoff, timing-equalized rejection (no
  user-enumeration oracle), audited `auth.login` / `auth.login_failed`.
- **Fingerprint TOFU (SSH-style):** `frtrol agent login` captures the daemon cert on
  first connect, prints its SHA-256 fingerprint, and pins it (known_hosts analog).
  `--expect-fp` verifies strictly — a mismatch aborts **before** the password is sent.
  Owner side: `frtrol fingerprint`.
- **Legacy v1.0 migration:** existing agent-tokens become a key-only `legacy` device at
  daemon start — v1.0 agent binaries keep working unchanged, headerless requests
  resolve to the legacy device, fresh installs reject them (fail closed).
- **Per-device request binding:** requests/sessions/audit events record the device id;
  `device lock` revokes that device's sessions in the same command.
- **CLI v2 (ADR-0026, gh-style):** comfy-table tables, colorblind-safe status glyphs,
  humanized durations (`4h 51m left`), dim `tip:` hints, informative empty states,
  receipt lines, `--json` on every command (global flag), NO_COLOR + pipe-safe output.
- **Web console v2 (ADR-0027):** total redesign — dark sidebar cockpit (Dashboard /
  Sessions / Devices / Audit / Danger), KPI cards, live countdowns, device panel with
  copy-to-clipboard secrets, searchable audit + hash-chain status chip, panic confirm
  modal. Still one dependency-free file, textContent-only, no CDN, same CSRF/cookie
  model. New `/ui/device/*` endpoints (cookie + CSRF, same state-layer code path).
- **Metrics:** `farcontrol_devices` gauge; per-principal lockout metrics.

### Changed
- `frtrol panic` rotates **every** device key (was: single agent token).
- `frtrol rotate` maps to the legacy device; devices use `device passwd`.
- Backup/restore: file mode carries device keys in `state.db`; keyring-mode archives
  materialize the key map as `device-keys.json` (validated on restore). `agent-token`
  in archives is a tolerated v1.0 artifact; restore of a fresh 1.1 archive no longer
  requires it.
- Doctor: v1.1 checks (admin-token perms, devices-with-keys, keyring map, schema v4).
- e2e grew from 172 to **231 checks** (new §33–39: device lifecycle, login backoff,
  TOFU strict/mismatch, legacy migration, --json schemas, console v2 flows, output
  contract).

### Fixed (found by our own tests — the discipline working)
- **Deadlock** in the device-auth verify path (mutex re-acquired on the same thread)
  and **five more** in the new web console handlers — found by the e2e + curl probes.
- **Unthrottled rejection path:** headerless/unknown-device floods now hit the rate
  brake *before* rejection (v1.1 hardening during e2e).
- Doctor no longer fails on fresh 1.1 installs (agent-token is optional legacy).
- Missing-header/invalid-timestamp rejections are now audited (invariant 8).

### Security
- Argon2id at m=64 MiB/t=3/p=1 for password hashing (login endpoint only).
- Per-principal progressive lockout: one attacked device never locks out the others;
  the seconds-scale global burst brake stays (documented fail-closed trade-off).
- Login rotates the device key on success; `device passwd` rotates password + key;
  `device lock` revokes sessions + key + login in one step.

## [1.0.0] — 2026-10-02

The release. Everything below, verified as one wall:
**78 unit tests + 172 e2e checks + 6 mutation checks, clippy 0, cargo-audit 0 CVEs,
secret-scan clean, SPDX SBOM (220 crates), GPG-signed artifacts.**

### Added (since 0.9.0)
- **Emergency stop under stress** (e2e §32): panic with terminals and commands in flight —
  sessions revoked mid-air, terminals killed, in-flight commands bounded, old token dead,
  fresh cycle works immediately, daemon healthy (ADR-0024).
- Release engineering: humanized README, MIT LICENSE, CHANGELOG, SECURITY.md,
  CONTRIBUTING.md, GitHub Actions CI (clippy `-D warnings` + unit + full e2e — where the
  kernel keyring is real), GPG-signed `SHA256SUMS` + published release key
  (`docs/RELEASE_KEY.asc`).
- Closed-by-verification rows: SC-03/SC-04/SC-06 (assurance: no hidden persistence, no
  secrets in source/logs, no debug endpoints, metadata-only audit), §97-14 (stress panic),
  ID-08 (schema v3 stable across 0.8→1.0, restore preserves identity).

## [0.9.0] — 2026-10-02 (internal)

Hardening pass (ADR-0023). 78 unit + 161 e2e + 3 mutation checks.

### Added
- **Progressive auth backoff** (SC-01): strike counter → lockout `60s × 2^n` capped at
  1 h; attempts while locked *extend* the lock; only a successful auth resets; audited as
  `auth.backoff` (bounded rows); admin plane deliberately stays unlocked so the owner's
  panic path survives an attack.
- **Startup config validation** (SC-02): `Config::validate()` at init and run —
  fail-fast `config_invalid` exit 2 before anything binds; doctor upgraded to
  parse+validate.
- **OS keyring secret store** (ID-04): `[identity] secret_store = "keyring"` — Linux
  kernel keyring via raw `add_key(2)`/`keyctl(2)`; no plaintext file, no DB row;
  per-request load; rotate-in-place; backup materialize+unlink; restore write-back;
  **fail-closed environment probe** (gVisor-style sandboxes implement the keyring
  partially — keyring mode refuses to start there instead of storing an unreadable secret).

### Fixed
- Real bug found by probing: wrong `KEYCTL_*` command constants (SEARCH=8, READ=9,
  UNLINK=7 — not 10/11/9); corrected and validated with standalone C probes.

## [0.8.0] — 2026-10-02 (internal)

Agent identity surface (ADR-0022). 68 unit + 147 e2e + 4 mutation checks.

### Added
- Provider/model catalog (data-driven, embedded; Z.ai ×4, Qwen ×5 — spec §9.2–9.4);
  identity is an optional both-or-none *declaration*, validated server-side, labeled
  "declared — not verified" (AG-03).
- Stable CLI contract: §66 exit codes 0–7 shared `exit_for()`; §45 `status --json` /
  `list --json`.
- `X-Far-Proto` version negotiation (absent = 1, ≠1 → 422 `unsupported_proto`).
- Audit retention: opt-in `[audit] max_events`, trim re-chains from an `audit.trimmed`
  genesis, atomic rewrite (AD-08).
- Schema v3 + `SCHEMA_VERSION` const (fixes a readyz drift regression).

## [0.7.0] — 2026-10-02 (internal)

Observability + crash recovery + incident response (ADR-0021). 56 unit + 120 e2e.

### Added
- `/healthz`, `/readyz` (unauthenticated, loopback admin plane, zero leak) and
  `/admin/metrics` (Prometheus text, admin-auth).
- Crash recovery proven by e2e: SIGKILL the daemon → restart → sessions and audit intact
  (SQLite WAL replay).
- systemd unit hardening (Restart=always, NoNewPrivileges, PrivateTmp, ProtectSystem).
- `docs/incident-response.md`: the §73 8-step runbook mapped to tested commands.

## [0.6.0] — 2026-10-02 (internal)

Backup/restore + supply chain (ADR-0020). 56 unit + 112 e2e.

### Added
- `frtrol backup` (server-side via admin plane: WAL checkpoint + fixed-argv tar → 0600
  bytes) and `frtrol restore` (offline; allowlist anti-path-traversal; open-verify;
  never destroys old data — `.bak` swap).
- cargo-audit, SPDX SBOM from Cargo.lock, secret scan, clippy, SHA256SUMS in release
  artifacts.

## [0.5.0] — 2026-10-02 (internal)

Fuzzing (ADR-0019). 54 unit + 102 e2e.

### Added
- In-process black-box fuzzing of the *real* routers: §75 deterministic corpus × 11
  endpoints, 2,000 seeded-random requests, 50-way concurrent chaos; runs on every
  `cargo test`.

### Fixed
- Real bug found by the fuzzer: 413 body-limit responses were plain text → now a proper
  JSON envelope (verified in-process and on the wire).

## [0.4.0] — 2026-10-02 (internal)

Full Access adapters (ADR-0018). 51 unit + 97 e2e.

### Added
- Process adapter (/proc walk + guarded `kill`), application adapter (detached launch via
  orphan-reaper, no zombies), desktop adapter (screenshots/typing via fixed-argv tools,
  **fail closed** `desktop_unavailable` when headless — scope gate before availability).

## [0.3.0] — 2026-10-02 (internal)

Web console (ADR-0017). 45 unit + 83 e2e + mutation (CSRF).

### Added
- Owner console on the admin plane (loopback+TLS): token login → HttpOnly
  SameSite=Strict cookie, CSRF via JS-only `X-Far-Ui` header, XSS prevented structurally
  (one HTML file, `textContent` rendering, zero HTML-string sinks — grep-verified);
  dashboard with duration picker, revoke buttons, audit feed, PANIC button.

## [0.2.0] — 2026-10-02 (internal)

"Actually usable" release (owner: *sampai benar-benar bisa digunakan*). 40 unit + 68 e2e.

### Added
- TLS on both planes (rustls, self-signed cert auto-generated, TOFU pinning in the agent
  CLI) — no tunnel needed for remote agents.
- Interactive PTY terminal (`/v1/term/*` + `frtrol agent term`), dies with its session.
- `frtrol panic` (SE-11 emergency stop) and `frtrol doctor` (§46 checks).
- Global rate limiting (10 fails/60 s → 429, fail closed).
- Tamper-evident audit: hash chain in `audit.jsonl` + `doctor` verification.
- `[policy]` config section, env scrubbing, DB migrations, `.deb` + systemd packaging.

### Fixed
- Real bug: agent token was cached in daemon memory → rotation wasn't instant; now
  read-per-request from the source of truth.

## [0.1.0] — 2026-10-02 (internal)

The walking skeleton (spec §103 DoD, 21/21 items). 38 unit + 49 e2e.

- Full session lifecycle: request (5 min TTL) → local approval (loopback admin plane) →
  session (5–72 h) → expiry (lazy + sweeper) → revoke; 1 active session max.
- HMAC-SHA256 proof-of-possession auth (timestamp window, single-use nonces,
  constant-time compare), one-shot exec with policy (timeouts, output cap, denylist),
  file ops under $HOME with path-traversal guards, audit (DB + JSONL), SQLite WAL state,
  token rotation, fail-closed everywhere.
