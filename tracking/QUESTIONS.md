# Open Questions for the Owner

**Rule 3: if you don't know, don't assume — ask.** This file is where unknowns live.

How to use:
- Before starting any phase, read every question marked **Blocks** that phase.
- Do **not** work around a blocked question by guessing. Mark the REQ `BLOCKED (Q-xxx)` and take unblocked work.
- When the owner answers, record the answer under **Answer**, set Status to `ANSWERED`, and (if it is a design
  decision) capture it in `DECISIONS.md` or an ADR.
- Add new questions at the bottom using the format below. One unknown per question.

```
### Q-NNN — <short title>
Status: OPEN | ANSWERED | WITHDRAWN        Blocks: <phase / REQ IDs>
Spec: §…
Unknown: <exactly what is not known>
Why it matters: <what goes wrong if guessed wrong>
Options (not decisions): <A / B / C with trade-offs>
Meanwhile: <what you will do that doesn't depend on it>
Answer: <filled by owner>
```

The questions below were found by reading the spec. They are real gaps or ambiguities, not
hypotheticals. Options listed are **candidates for discussion, not recommendations to adopt silently**.

---

> **2026-10-02 update — Gate 0 cleared.** The owner answered all blocking questions in one message
> ("Linux dulu · control plane self-hosted cepat/free/tanpa cloudflared · komparasi bahasa wajib ·
> sisanya rekomendasi · agent interface wajib AI-super-mudah · policy paket standart").
> Answers are recorded below; every delegated design choice became an ACCEPTED ADR (docs/adr/).

### Q-001 — Implementation language(s) and toolchain
Status: ANSWERED        Blocks: Phase 0 (everything)
Spec: App. C, §52
Unknown: Which language/toolchain?
Why it matters: drives bindings, distribution, tooling.
Options: Go · Rust · others.
Meanwhile: —
Answer: **Owner: "yang paling bagus, yang bener-bener bagus — wajib komparasi."** Full comparison delivered at `farcontrol/docs/05-language-comparison.md` (9 candidates, 8 weighted criteria; Rust 9.15 vs Go 8.30). **Rust** chosen → ADR-0001.

### Q-002 — What is the "control plane" for v0.1 in practice?
Status: ANSWERED        Blocks: Phase 1
Spec: §4.3, §19, §33, App. B, §71
Unknown: hosted cloud vs self-contained control plane?
Why it matters: shapes the whole architecture.
Options: (A) owner-run minimal · (B) full hosted · (C) dev-local first.
Meanwhile: —
Answer: **Owner: "SELF hosted lengkap, wajib sangat cepat, fully free, JANGAN pakai cloudflared."** → daemon on the owner's box, direct listeners, remote reach via SSH/WireGuard. → ADR-0003.

### Q-003 — Transport: WebSocket vs QUIC
Status: ANSWERED (v0.1)        Blocks: Phase 1
Spec: §19, App. D #1
Unknown: Which transport carries the session channel?
Why it matters: library choice, traversal, reconnect.
Options: WebSocket · HTTP/2 · QUIC.
Meanwhile: —
Answer: Delegated → recommendation: **HTTP/1.1 + JSON** for v0.1 (most universal for AI agents; TLS 1.3/WebSocket/QUIC reconsidered in v0.2 once streaming exists). → ADR-0004.

### Q-004 — How is the device secret authenticated? (verifier **and** proof-of-possession)
Status: ANSWERED (v0.1 scope)        Blocks: Phase 1 (AU-01, AU-02, AU-03, ID-05)
Spec: §7.2, §18.1–18.2, §20
Unknown: Which construction reconciles server-side verifier + MAC proof?
Why it matters: the core auth scheme; improvised design = the most likely serious vuln.
Options: (A) PAKE-style · (B) KDF keypair + server challenge · (C) other reviewed construction.
Meanwhile: —
Answer: Delegated → recommendation: **agent token (32-byte CSPRNG, base58) + HMAC-SHA256 proof-of-possession over (ts, nonce, method, path, body-hash), ±300s window, single-use nonce table.** Honest deviation recorded: for the single-user self-hosted v0.1 the token lives in local state (0600 + SQLite meta); server-side verifier-only storage is a hosted-control-plane concern deferred to v0.2 (DECISIONS D-023). → ADR-0005.

### Q-005 — Device ownership, accounts, and registration
Status: ANSWERED (v0.1 scope)        Blocks: Phase 1
Spec: §8.2, §4.3, §38, §57
Unknown: user accounts in v0.1? registry?
Why it matters: registry schema, rate-limit keys.
Answer: Delegated → recommendation: **no accounts, no registry in v0.1** — identity = the agent token generated locally at `frtrol init` (ADR-0003 self-hosted scope). Multi-device registry is a hosted-era feature.

### Q-006 — How does the control plane trust that approval was local?
Status: ANSWERED (v0.1 scope)        Blocks: Phase 1 (RQ-04, RQ-06)
Spec: §62, §34, §61 Attacker D
Unknown: what proves approve came from the local user path?
Why it matters: Invariant 1 — a hole here lets an AI approve itself.
Options: (A) device holds approval authority · (B) CP trusts device-authenticated channel · (C) other.
Answer: Delegated → recommendation: since the control plane IS the local daemon (Q-002), approval lives on a **loopback-only admin plane** (daemon refuses non-loopback admin bind) + admin token file 0600. The agent plane has no route to approval endpoints. → ADR-0004/0006. E2E-proven (unsigned 401; agent cannot reach /admin).

### Q-007 — How does an AI actually use the session? (agent-side interface)
Status: ANSWERED        Blocks: Phase 2
Spec: §9–10, §25.1, §60, App. F
Unknown: non-interactive credential input; command submission path; password not on argv.
Why it matters: without it an AI cannot run the product.
Answer: Delegated with hard constraint ("AI harus super mudah") → **two doors**: (1) `frtrol agent` CLI that signs everything (token via `--token`/env/file — never argv-embedded secrets beyond the token flag, which is a file-read by default); (2) raw REST+JSON with HMAC — 10 lines of Python, example shipped in README. All output compact single-line JSON; all errors machine-readable `{"error":{"code"}}`. → ADR-0007.

### Q-008 — Numeric policy values left "configurable"
Status: ANSWERED        Blocks: Phase 1–2
Spec: §48, §87, §25.3, §38, §22, §49
Unknown: grace periods, caps, rate limits, timeouts…
Why it matters: security limits.
Answer: **Owner: "policy limit paket standart."** Concrete values in `src/policy.rs` (ADR-0008): session 5–72h, 1 active session, request TTL 300s, exec 30s/300s, output 256 KiB, file 1 MiB under $HOME, denylist, 10 pending/agent. Configurable-file policy is v0.2.

### Q-009 — Is `terminal.close` part of `terminal_only`?
Status: WITHDRAWN (v0.1)        Blocks: AC-02
Spec: §14.1 vs §15/§17
Unknown: which is canonical?
Answer: Not applicable in v0.1 — exec is one-shot (no persistent terminal to close); PTY/streaming arrives in v0.2, resolve then.

### Q-010 — What does credential rotation do to existing sessions?
Status: ANSWERED (v0.1 behavior)        Blocks: ID-06
Spec: §42
Unknown: keep / revoke / ask each time?
Answer: Delegated → v0.1 behavior implemented & e2e-proven: **rotation kills the old credential instantly** (auth impossible with old token), while existing sessions technically remain in DB until expiry/revoke — but cannot be exercised without the new token. Audited as `token.rotated`.

### Q-011 — What must "Full Access" include to call v0.1 done?
Status: ANSWERED        Blocks: Phase 4, DoD
Spec: §103, App. E, §14.2
Unknown: which adapters/OSes for the milestone?
Why it matters: sets project size.
Answer: Delegated → recommendation: **terminal + filesystem adapter (read/write/list) restricted to `$HOME` with canonicalize guard**, Linux only. Process/application/desktop/browser adapters deferred (v0.2+). → ADR-0009.

### Q-012 — Target operating system(s)
Status: ANSWERED        Blocks: Phase 0
Spec: §78, §21, §93
Unknown: which OS first?
Answer: **Owner: "Linux dulu."** → ADR-0002. Verified on Debian x86_64 in this sandbox; owner should re-run tests on the target machine.

### Q-013 — Local web UI authentication
Status: ANSWERED (v0.1 scope)        Blocks: Phase 3
Spec: §22
Unknown: how does the browser session authenticate?
Why it matters: loopback is reachable by local malware.
Answer: Delegated → recommendation: **no web UI in v0.1 at all** (CLI + console logs + audit). A read-only console with login is a v0.2 candidate AFTER external review. → ADR-0010.

### Q-014 — Session state machine: unspecified transitions
Status: ANSWERED (v0.1 simplification)        Blocks: SE-01, Phase 1
Spec: §16, §85, §87, §37
Unknown: ACCEPTED vs AUTHORIZED, ERROR transitions, request expiry state, DISCONNECTED→ACTIVE.
Why it matters: undefined transitions hide fail-open bugs.
Answer: Delegated → v0.1 implements a **strict subset**: request `pending→approved|denied|expired` (no reverse transitions; expired-by-TTL is terminal and unapprovable); session `active→revoked|expired` (terminal). No DISCONNECTED state (no persistent channel in v0.1). Full §16 machine with reconnect semantics lands with v0.2 streaming. All transitions are single-row conditional UPDATEs (idempotent).

### Q-015 — Alphabets for Device ID and Device Secret
Status: ANSWERED (deviation recorded)        Blocks: ID-01, ID-02
Spec: §7.1, §7.2
Unknown: exact alphabets; 24-char ≥128-bit feasibility.
Why it matters: entropy + usability.
Answer: Delegated → recommendation: **base58 (Bitcoin alphabet, no 0/O/I/l) for tokens and prefixed ids (`req_`, `ses_`), hex for signatures/digests, base64 for payloads.** Deviation vs §7 (8-char id / 24-char secret): v0.1 uses 32-byte tokens (256-bit) + 16-byte prefixed ids — strictly MORE entropy; recorded as D-024. → ADR-0012.

### Q-016 — Who generates the Device ID?
Status: ANSWERED (v0.1 scope)        Blocks: Phase 1
Spec: §8.2, §4.3, §32
Unknown: local generation vs control-plane assignment?
Answer: Delegated → v0.1: **generated locally at `frtrol init`** (CSPRNG), no central registry to collide with (self-hosted, single device). Hosted registry model deferred.

### Q-017 — Audit storage, retention, and chain scope
Status: ANSWERED (v0.1 scope)        Blocks: Phase 2 (AD-04, AD-08)
Spec: §31, §32, §68, App. D #10
Unknown: local vs central chain; retention; debug capture?
Answer: Delegated → v0.1: **local SQLite `audit` table + mirrored append-only `audit.jsonl`**; command logging is metadata-only (command line, exit, durations, byte counts — no output content). Hash chain + retention rotation = v0.2 hardening (gap noted in EVIDENCE-001 §10).

### Q-018 — Provider/model id slugs
Status: WITHDRAWN (v0.1)        Blocks: AG-02 (minor)
Spec: §9.5, §81
Unknown: slug convention for the catalog.
Answer: Not applicable in v0.1 — no provider/model catalog in the self-hosted slice (agent self-declares `agent_name`). Resolve when the catalog feature is scheduled.
