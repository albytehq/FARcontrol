# R4 — Device Auth & TOFU Security Patterns

> Research pass 4/5 · Mission 1.1.0 · Sources: OWASP Password Storage Cheat Sheet,
> Wikipedia/termai/smallstep TOFU articles, SSH known_hosts model.
> Raw: raw/r4a.json, raw/r4b.json

## Password hashing (OWASP, current)

- **Argon2id**, minimum config per OWASP Cheat Sheet: **m=19 MiB, t=2, p=1**.
  Security-conscious configs go to 128 MiB. We adopt **m=64 MiB, t=3, p=1**:
  login is a rare path (per device), so ~100–200 ms hash cost is acceptable and
  the daemon's steady-state footprint is unaffected.
- Argon2 runs ONLY on the login endpoint — never per-request (HMAC handles that).

## SSH-style TOFU (the model we adopt for cert pinning)

1. First connect: client has no pinned key/cert. It captures the server-presented
   certificate, shows its **SHA-256 fingerprint**, and pins it (known_hosts analog).
2. Out-of-band verification is *available*: the owner side prints the same
   fingerprint (`frtrol device fingerprint` / start banner); cautious operators
   compare them. Scriptable strict mode: `agent login --expect-fp SHA256:…`.
3. Later connections verify against the pin → MITM with any other key fails closed.
4. Accepted residual risk (same as SSH's "type yes" reality): an active MITM on the
   FIRST connection could present its own cert and capture the password. Mitigations:
   password is high-entropy auto-generated (not reusable elsewhere), per-device
   strike backoff throttles guessing, `device lock`/`passwd`/`panic` rotate instantly.
   Documented honestly in ADR-0025 — consistent with how the industry ships SSH.

## Login → key exchange (our protocol shape)

- `POST /v1/auth/login {device_id, password}` → Argon2 verify → server mints a
  random 256-bit **device key** (stored server-side like today's agent-token:
  file 0600 / keyring mode) → returned once over TLS.
- Every subsequent request: existing HMAC-SHA256 proof-of-possession pipeline
  (nonce, anti-replay, read-key-from-DB-per-request) keyed by the device key,
  with `device_id` inside the signed envelope.
- Per-device progressive backoff (v0.9 engine) keyed by device, so one attacked
  device never locks out others; admin plane stays unlocked (owner panic path).
- **Password ≠ authorization**: login only establishes identity + signing key.
  Every session still requires explicit owner approval (invariant #1 unchanged).

## Legacy migration (chosen: auto-migrate)

On first 1.1.0 start, if `agent-token` file exists and devices table is empty:
create device row `name=legacy`, `device_key = old token bytes` (old agent CLI
keeps working), `password_hash = NULL` + `login_disabled=1` (legacy row is
key-only; it can be locked/removed like any device). Requests without
`device_id` field resolve to the legacy device (v1.0.0 binary compat shim).

## Device ID format (chosen: FAR-XXXX-XXXX)

- Crockford-base32 alphabet (no 0/O/1/I), 4+4 chars + 1 check char → e.g.
  `FAR-7K2M-QX94`. Checksum detects single typos before a network round-trip.
- Generated from CSPRNG; collision-checked against DB.
