# ADR-0025 — v1.1.0: Device authentication (ID + password) with fingerprint TOFU

- Status: ACCEPTED (owner instruction 2026-10-02: "yang diperlukan agent itu cuman ID device dan
  passwordnya — kita rancang FARcontrol 1.1.0")
- Date: 2026-10-02
- Research: docs/research/r4-device-auth-security.md, r5-synthesis-spec.md
- Supersedes: none (extends ADR-0005 proof-of-possession, ADR-0022 agent identity, ADR-0023 backoff/keyring)

## Context

1.0.0 hands an agent **three** artifacts (URL, agent-token, cert.pem). The owner judged the
handover too heavy for the product's own story — an agent should carry exactly two things:
a **device ID** and a **password**. Meanwhile the CLI's raw output was judged
"not enterprise" (addressed by ADR-0026) and the web console needed a total redesign
(ADR-0027).

Non-negotiable carried over: authentication ≠ authorization (invariant #1). A password
gets an agent *identity* — every session still needs explicit owner approval, and every
invariant (expiry, revoke, capability, fail-closed, auditability) applies unchanged.

## Decision

### 1. Device registry

New table `devices` (migration v3):

| column | notes |
|---|---|
| id TEXT PK | `FAR-XXXX-XXXX` — Crockford base32 (no 0/O/1/I), 7 random chars + 1 mod-31 check char |
| name TEXT | owner-chosen label |
| password_hash TEXT NULL | Argon2id PHC string; NULL = key-only legacy row |
| device_key TEXT | 256-bit random secret (base64url, 43 chars) — the HMAC key |
| status TEXT | `active` / `locked` |
| created_at, last_seen INTEGER | last_seen updated on verified request |
| strikes INTEGER, locked_until INTEGER | per-device backoff state (ADR-0023 engine, re-keyed) |

File mode: device keys live in `state.db` (same D-023 trust level — data dir 0700, db
0600; documented as D-045). Keyring mode: the single kernel key payload becomes a JSON
map `{device_id: key}` — old raw-token payloads are recognized and migrated (legacy row).

### 2. Login → key exchange

`POST /v1/auth/login {device_id, password}` (agent plane, TLS):

1. Global rate limit (10/60s, unchanged) then **per-device backoff** check.
2. Argon2id verify — **m=64 MiB, t=3, p=1** (OWASP floor is 19 MiB/t=2/p=1; we exceed it;
   login is a rare path so ~150 ms hash cost is fine; Argon2 NEVER runs per-request).
3. Success → reset strikes, **rotate the device_key**, return it once. Audit
   `auth.login` (actor: device id).
4. Failure → strike++, bounded `auth.backoff` audit, 401. Locked device → 403
   `device_locked` (login impossible, even with the right password).

After login, every request uses the existing **HMAC-SHA256 proof-of-possession**
pipeline (timestamp window, nonce burn, per-request key read) — Argon2 is not in the
hot path. Request header `X-Far-Device: FAR-XXXX-XXXX` selects the key; the header
value is appended to the signing payload (bound claim). Absent header → the legacy
device's key, and the v1.0.0 5-field payload is accepted (compat shim, one device,
one format — no ambiguity, documented).

### 3. Passwords (auto-generated, owner instruction)

5 words from an embedded 1024-word list + 2 decimal digits, joined by `-`:
`harbor-tiger-42-blue-quantum-mango` → **≈ 56.6 bits** entropy. Defense in depth:
Argon2id(64 MiB) makes offline guessing expensive even if state.db is stolen; online
guessing is throttled by global rate limit + per-device exponential backoff. Passwords
are shown ONCE at `device add` / `device passwd`; only the Argon2 hash is stored.

### 4. Fingerprint TOFU (replaces handing cert.pem to agents)

`frtrol agent login <device-id>`: if no pinned cert exists, the client connects with a
capture-mode TLS config (accepts the presented cert ONCE), prints its SHA-256
fingerprint, pins it to the agent home, then logs in. Later connections verify against
the pin — any MITM fails closed (SSH known_hosts model, research R4). Strict mode
`--expect-fp SHA256:…` compares before sending the password. Owner-side: the start
banner and `frtrol fingerprint` print the same digest for out-of-band comparison.

Residual risk (same as SSH first-connect reality, stated honestly): an active MITM on
the very first connection could capture the password and pin its own cert. Mitigations:
high-entropy single-purpose password, per-device backoff, `device lock` /
`device passwd` / `frtrol panic` rotate instantly, `--expect-fp` for operators who
verify.

### 5. Owner device commands (admin plane, audited)

`frtrol device add <name>` · `device list` · `device lock <id>` (login disabled, key
rotated, that device's sessions revoked) · `device unlock <id>` · `device passwd <id>`
(new password + new key → forces re-login) · `device remove <id>`.
`frtrol panic` rotates every device key. `frtrol rotate` maps to the legacy device.

### 6. Legacy migration (owner instruction: auto-migrate)

First 1.1.0 start with an existing `agent_token` and empty devices table → create a
device row: generated FAR id, `name="legacy"`, `password_hash=NULL` (key-only, login
disabled), `device_key = old token`. v1.0.0 agent binaries keep working unchanged.
`frtrol device list` marks it `[key-only]`.

### 7. Session ↔ device binding

`requests`/`sessions` gain a nullable `device_id`; audit events for agent actions
record it; the web console and `frtrol list` display it.

## Consequences

- Agent handover = ID + password (URL is config, not a secret).
- The v1.0.0 agent-token flow survives as the legacy device (zero-break upgrade).
- New e2e sections: device lifecycle, per-device backoff, legacy compat, TOFU pin
  (cert change → fail closed), passwd kills old key, --expect-fp. Mutation checks:
  drop lock-check, drop backoff, skip pin-verify — each must turn e2e red.
- Honest deviations: D-045 (device keys in SQLite, file mode), D-046 (TOFU
  first-connect residual risk, mitigated, operator-verifiable).
