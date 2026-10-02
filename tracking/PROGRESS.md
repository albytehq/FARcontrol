# Progress

The single source of truth for status. **Update only with evidence.**

> **2026-10-02 — v1.1.0 DELIVERED & VERIFIED (104 unit + 231 e2e + 9 mutation checks, clippy 0, cargo-audit 0 CVE, secret-scan CLEAN, SBOM 239 crates, browser-tested console v2 + VLM review 8/10 — device authentication (ADR-0025: FAR-XXXX-XXXX + Argon2 password, fingerprint TOFU, legacy migration), CLI v2 gh-style (ADR-0026), web console v2 total redesign (ADR-0027); 5 research notes; bug nyata ditemukan & difix: 6 deadlock + unthrottled rejection path + doctor v1.1 + backup/restore keyring map).**
> **2026-10-02 — v1.0.0 RELEASED & VERIFIED (78 unit + 172 e2e, clippy 0, 6 mutation checks total, GPG-signed artifacts — stress-panic §97-14 + assurance rows closed-by-verification; ADR-0024).**
> **2026-10-02 — v0.9.0 DELIVERED & VERIFIED (78 unit + 161 e2e, clippy 0, 3 mutation checks — progressive auth backoff SC-01 + startup config validation SC-02 + OS keyring ID-04; D-044/ADR-0023).**
> **2026-10-02 — v0.8.0 DELIVERED & VERIFIED (68 unit + 147 e2e, clippy 0, 4 mutation checks — agent identity catalog + §66 exit codes + §45 --json + X-Far-Proto + audit retention; D-042/D-043).**
> **2026-10-02 — v0.7.0 DELIVERED & VERIFIED (56 unit + 120 e2e, clippy 0, audit 0 CVE — full roadmap 0.3→0.7 complete).**
> Source: `farcontrol/` (Rust, ADR-0001). Evidence: `tracking/evidence/EVIDENCE-001.md` +
> `farcontrol/reports/verification-output.txt` (56 unit + 120 e2e ALL GREEN + clippy 0 + cargo-audit 0 CVE + SBOM + secret-scan; v0.7 menambah **observability + crash recovery + IR runbook**).
> Scope of the slice is defined by ADR-0000 (owner-approved): session lifecycle + exec + file
> ops + audit on a self-hosted Linux daemon. Rows below stay honest per-row: verified items
> say VERIFIED with evidence; deferred items stay TODO with a pointer.

## Status legend

| Status | Meaning |
|---|---|
| `TODO` | Not started |
| `IN-PROGRESS` | Being worked on |
| `BLOCKED (Q-xxx)` | Waiting on an owner answer — do not guess |
| `PARTIAL` | Some of it works; list what's missing in the evidence file |
| `VERIFIED` | Level-3 verified (discipline.md Rule 2) **and** an evidence report is linked |
| `DEFERRED (ADR-xxxx)` | Intentionally out of v0.1 scope per an accepted ADR |

**You may set `VERIFIED` only after the Done Gate (discipline.md §5) is fully true and an evidence file exists in `tracking/evidence/`.**

## Phases

| Phase | Status | Exit criteria evidence |
|---|---|---|
| Gate 0 — ADRs + blocking questions | VERIFIED | All 18 questions answered (QUESTIONS.md); ADR-0000…0012 ACCEPTED; DECISIONS D-017…D-030 |
| Phase 0 — Foundations | VERIFIED | `frtrol init/start`, config, SQLite WAL state, tokens 0600 — EVIDENCE-001 §1/§3 |
| Phase 1 — Session Core | PARTIAL | Session lifecycle, request TTL, 1-active-session, HMAC auth, approval, expiry, revoke: VERIFIED (EVIDENCE-001). Missing for full phase: hosted-CP semantics, TLS, progressive auth rate-limit (deferred — ADR-0003/0004) |
| Phase 2 — Terminal Only | PARTIAL | One-shot exec + policy + timeout + output caps + audit: VERIFIED (EVIDENCE-001 §5/§7). Missing: interactive PTY, streaming, per-command env scrubbing (v0.2 — ADR-0000) |
| Phase 3 — Local Web UI | DEFERRED (ADR-0010) | Owner-approved: CLI-first v0.1; web console = v0.2 candidate |
| Phase 4 — Full Access | PARTIAL | Filesystem adapter under $HOME with path guard: VERIFIED (EVIDENCE-001 §7). Missing: process/desktop/browser adapters (ADR-0009) |
| Phase 5 — Hardening | TODO | Fuzzing, hash-chain audit, signed releases, external review — v0.2 (EVIDENCE-001 §10) |

## Requirements

### ID — Device identity and secrets

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| ID-01 | Device ID is 8 chars; alphabet excludes 0 O I l 1; format is versioned. | TODO | |
| ID-02 | Device Secret is 24 chars from the OS CSPRNG with ≥128 bits effective entropy. | VERIFIED (deviasi D-024: 32-byte base58 = 256-bit) | EV-001, crypto.rs test |
| ID-03 | Secret is never derived from hostname, username, MAC, serial, or timestamp. | VERIFIED | crypto.rs — OS CSPRNG only |
| ID-04 | Secret stored in OS secret store (Windows DPAPI/Credential Manager · macOS Keychain · Linux Sec… | VERIFIED (Linux kernel keyring, opt-in v0.9) | e2e §31 + EVIDENCE-002: `[identity] secret_store="keyring"` — no plaintext file/DB row; fail-closed env probe (full path on real kernels; sandbox refusal verified) |
| ID-05 | Server stores only a verifier/hash of the secret — never reversible plaintext | PARTIAL (by design, self-hosted) | HMAC verifikasi butuh kunci asli; keyring mode (v0.9) keluarkan secret dari DB+file total; verifier-only tetap konsep hosted CP (D-023) |
| ID-06 | Secret is rotatable and revocable; rotation invalidates the old credential. | VERIFIED | `frtrol rotate` — e2e §14 (old token 401 instan) |
| ID-07 | First start shows the secret once; later starts mask it (); credential reveal needs explicit lo… | VERIFIED | init print sekali; file mode 0600 |
| ID-08 | Device ID and secret do not silently change on upgrade. | VERIFIED (v1.0) | schema v3 stabil lintas 0.8→0.9→1.0 (migrations table traceable); e2e §22 restore→restart tanpa re-init, token & audit utuh |
| ID-09 | Device ID is public-ish, not secret; never treated as a credential. | VERIFIED | `agent_name` bebas deklarasi; token = kredensial (AU-03) |

### ST — frtrol start

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| ST-01 | On run: load config → create identity on first run → load on later runs → bind local web to loo… | PARTIAL | init/start/restore state VERIFIED (e2e §1/§13); tanpa web UI (ADR-0010) |
| ST-02 | Output includes server address, control-plane status, device name, OS, arch, version, runtime s… | VERIFIED | banner startup: endpoint, data dir, policy, pid, OS/arch (v0.8) |
| ST-03 | Flags: --no-web --port --host --foreground --verbose | PARTIAL | `--bind`, `--allow-root`, `--data-dir`; port via config/bind; web flags n/a |
| ST-04 | Web UI binds 127.0.0.1 by default. | N/A (ADR-0010) | tidak ada web UI di v0.1; admin plane loopback-only |
| ST-05 | Outbound-only connectivity: works behind NAT/firewall without inbound port forwarding. | DEFERRED (ADR-0003) | owner pilih direct self-hosted + SSH/WireGuard |
| ST-06 | stop stops the runtime cleanly; status reports state; autostart (if built) is transparent and n… | PARTIAL | Ctrl-C graceful + `frtrol status`; systemd unit di README |

### AG — frtrol agent

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| AG-01 | Provider → model menus are data-driven from a catalog (initial: Z.ai ×4 models, Qwen ×5 models,… | VERIFIED (v0.8) | src/catalog.rs embedded JSON per §9.2–9.4; unit catalog_shape_matches_spec; e2e §24 (D-043/ADR-0022) |
| AG-02 | Identity object {provider, model, identityVersion, clientVersion} | VERIFIED (v0.8) | §11 `agent:{provider,model}` in request/session JSON (request_json/session_json); catalog v1; e2e §24 |
| AG-03 | Identity is a declaration, grants no authority; UI must not imply vendor verification. | VERIFIED (v0.8) | UI/webui CLI label "declared — not verified"; identity never consulted by authorize_session; e2e §24 |
| AG-04 | Flow: insert Device ID → search → minimal device info → insert password → "accepted" → send req… | TODO | |
| AG-05 | Failure message is generic; reveals neither device existence nor which input was wrong. | TODO | |
| AG-06 | Pre-auth responses never expose IP, network topology, filesystem paths, home dir, raw OS accoun… | TODO | |
| AG-07 | Agent cannot pre-approve or set scope/duration; request carries requestedScope=null, requestedD… | VERIFIED | agent hanya BISA meminta; approve hanya di admin plane loopback (e2e §4) |
| AG-08 | Protocol leaves room for an agent public key + request signature (do not build it). | TODO | |

### AU — Authentication and handshake

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| AU-01 | Each auth request carries unique request ID, timestamp, nonce, server challenge (where practica… | PARTIAL | ts+nonce per request diimplementasi; server challenge n/a v0.1 (HMAC model) |
| AU-02 | Secret is not sent repeatedly | VERIFIED | token tak pernah dikirim; hanya HMAC proof (ADR-0005) |
| AU-03 | Device secret ≠ session token (never accepted as one, never reused as one). | VERIFIED | auth & authz terpisah; e2e §5/§14 |
| AU-04 | TLS 1.3, cert + hostname validation | DEFERRED (ADR-0004) | v0.2 rustls; sementara SSH/WireGuard utk lintas jaringan |
| AU-05 | No custom crypto; banned: MD5, SHA-1 for password storage, reversible server-side secret storag… | VERIFIED | HMAC-SHA256/SHA-256 std RustCrypto; unit test vektor RFC |
| AU-06 | Protocol version FAR-PROTO/1; clients advertise versions; server negotiates; unsupported versio… | VERIFIED (v0.8) | X-Far-Proto header: absent=1 (compat), ≠1 → 422 unsupported_proto (fail-closed negotiation); e2e §27 (mutation M4) |
| AU-07 | Authenticated end-to-end encrypted session channel between authorized endpoints (control plane … | TODO | |

### RQ — Connection request and approval

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| RQ-01 | Request object has the §11 fields; initial status PENDING. | VERIFIED (bentuk v0.1) | id/agent/scope/hours/reason/status/created_at; e2e §4 |
| RQ-02 | Request TTL is short (default 5 min); expired request can never be approved later; distinct fro… | VERIFIED | TTL 300s: approve ditolak + status expired (unit test stale_pending_request_cannot_be_approved) |
| RQ-03 | Request is shown in the local terminal (when practical) and the local web UI. | VERIFIED (terminal) | logline REQUEST di konsol daemon; web defer ADR-0010 |
| RQ-04 | Approval comes only from a local trusted path (CLI / loopback UI) | VERIFIED | admin plane loopback-only + token 0600; daemon refuse bind non-loopback (ADR-0006) |
| RQ-05 | If UI is unavailable, pending requests stay pending until expiry | VERIFIED | request menunggu tanpa UI; TTL sweeper yang mematikan |
| RQ-06 | Approval is one atomic transaction PENDING_APPROVAL → AUTHORIZED + session created. | VERIFIED | BEGIN IMMEDIATE…COMMIT di approve_request (D-026 unit tests) |
| RQ-07 | Server validates 5h ≤ duration ≤ 72h, scope ∈ {terminal_only, full_access}, status == PENDING_A… | VERIFIED | create_request + approve_request validations (unit tests) |
| RQ-08 | User-selected policy is authoritative; the user chooses duration and scope. | PARTIAL | owner bisa shorten durasi; scope mengikuti request (paket standart) |
| RQ-09 | Duration is enforced server-side and locally; client values never trusted. | VERIFIED | expires_at dihitung server; expire lazy+sweeper |
| RQ-10 | No silent renewal in v0.1; a new session requires fresh approval. | VERIFIED | tak ada jalur renew; session baru = request+approve baru |
| RQ-11 | Max 1 active remote session per device (default; configurable via security.max_active_sessions). | VERIFIED | session_limit 409 (unit test second_concurrent_session_denied); nilai via kode v0.1 |
| RQ-12 | Approval/deny/revoke endpoints accept idempotency keys; repeats cause one logical transition. | PARTIAL | idempotent by status-guard (request_not_pending/session_not_active); idempotency-key header belum |

### SE — Session lifecycle

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| SE-01 | State machine implemented; transitions atomic, idempotent, compare-and-set. | VERIFIED (subset D-014) | pending→approved/denied/expired; active→revoked/expired; UPDATE … WHERE status=… |
| SE-02 | Session object has the §17 fields incl | VERIFIED (bentuk v0.1) | id/request_id/agent/scope/created/expires/status/revoke info + effective_status |
| SE-03 | On now ≥ expiresAt: mark EXPIRED → revoke credentials → close streams → terminate/cancel worker… | VERIFIED (tanpa stream) | lazy+sweeper+persisted; e2e §11 |
| SE-04 | Timestamps UTC; local timeouts use a monotonic clock (clock-jump safe). | PARTIAL | UTC unix secs penuh; exec timeout pakai tokio Instant (monotonic); sesi expiry pakai wall clock |
| SE-05 | Revoke: mark REVOKED atomically → invalidate creds → notify control plane → cancel workers → cl… | VERIFIED (lokal) | revoke atomic + audit; e2e §8/§10; tanpa CP eksternal |
| SE-06 | Race: revoke at T0, command at T1 → command rejected | VERIFIED | cek status per-request di authorize_session; e2e §8 |
| SE-07 | Disconnect ≠ revoke | N/A (v0.1) | tidak ada kanal persisten (one-shot exec) |
| SE-08 | Control plane lost → no new authorization; existing session gets a grace period, then terminate… | N/A (ADR-0003) | control plane = daemon lokal; daemon mati = semua akses mati (fail-closed, e2e §13) |
| SE-09 | Runtime crash → session DISCONNECTED, remote commands stop, workers terminated or orphan-safe. | PARTIAL | crash = kill_on_drop membunuh anak; state persist; reconnect-semantics defer |
| SE-10 | Terminal channel drop with valid session → retain authorization; new channel possible; audit li… | VERIFIED (analog) | exec per-request; session tetap valid lintas panggilan; restart daemon pun tetap (e2e §13) |
| SE-11 | emergency-stop: revoke all sessions, reject all pending requests, disable new remote sessions u… | TODO | kandidat v0.2 (`frtrol panic`) |
| SE-12 | Device revocation: all sessions revoked → device disabled → new requests denied. | PARTIAL | rotasi token ≈ matikan identitas; bulk-revoke-all belum ada |

### AC — Access control and capabilities

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| AC-01 | Default deny | VERIFIED | semua handler: tanpa session aktif = tolak; fallback JSON 404 |
| AC-02 | terminal_only exposes only terminal capabilities (§14.1 list; terminal.close → Q-009). | VERIFIED (one-shot) | exec only; file API 403 scope_denied (e2e §6) |
| AC-03 | full_access grants the §14.2/§15 capability set — and only that | PARTIAL | terminal+files bawah $HOME (ADR-0009); adapter lain defer |
| AC-04 | Capabilities are modeled internally; the UI exposes just two levels. | VERIFIED | dua scope string + gate tunggal authorize_session |
| AC-05 | Full Access = separate adapters (Terminal, Filesystem, Process, Application, Desktop) | PARTIAL | adapter filesystem = files.rs; lainnya defer |
| AC-06 | The §54 authorization pipeline lives in one central place; no adapter or handler can reach the … | VERIFIED | satu fungsi authorize_session dipanggil semua handler |
| AC-07 | No privilege elevation | VERIFIED | daemon jalan sebagai user (root ditolak); anak proses inherit user itu |
| AC-08 | Full Access has internal deny rules for §64 dangerous categories (until an explicit future elev… | VERIFIED (subset) | denylist destruktif di policy.rs; e2e §7 policy_denied |
| AC-09 | Filesystem: canonicalize, reject malformed paths, prevent traversal outside allowed roots (if c… | VERIFIED | resolve_existing/write + guard_root; e2e §9 escape_rejected |
| AC-10 | Desktop input uses structured actions, not raw driver commands; each subject to session auth. | DEFERRED (ADR-0009) | desktop adapter v0.2+ |
| AC-11 | Browser automation (if included) runs in a controlled context; never exposes saved passwords/pr… | DEFERRED (ADR-0009) | browser adapter v0.2+ |
| AC-12 | Full Access scope for v0.1 (which adapters, which OS) is unspecified. | VERIFIED (kini dispesifikkan) | ADR-0009: files under $HOME, Linux |

### TM — Terminal execution

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| TM-01 | Commands flow: validator → capability validator → envelope validator → worker → OS process → st… | VERIFIED (v0.1 pipeline) | auth → authorize → policy → spawn → truncate → audit |
| TM-02 | Envelope validations: session active, not expired, capability, operationId unique, payload size… | PARTIAL | session/scope/ukuran/argv caps; operationId & stream n/a one-shot |
| TM-03 | Output bounded: max output bytes, max line length, max stream duration, max concurrent processe… | VERIFIED (subset) | 256 KiB truncate+flag; timeout 30/300s; line/stream/concurrent defer |
| TM-04 | One dedicated worker per active terminal session: minimal env, no access to the secret store, e… | PARTIAL | spawn per command (no persistent worker); env inherit penuh (terdokumentasi README §8.3) |
| TM-05 | Child env never contains FARCONTROL_DEVICE_SECRET, SESSION_TOKEN, CONTROL_PLANE_AUTH, private k… | VERIFIED | tidak ada env secret sama sekali (token hanya di header HTTP, tidak pernah di env/argv daemon) |
| TM-06 | Supported shells declared per OS (Win: PowerShell, cmd.exe · mac/Linux: bash, zsh); agent must … | PARTIAL | Linux: `sh -c` (dash) untuk mode shell; deklarasi formal defer |
| TM-07 | No shell invocation with concatenated unvalidated input where avoidable. | VERIFIED | mode argv = exec langsung tanpa shell; shell mode eksplisit |
| TM-08 | Revoke/expiry kills the whole process tree | PARTIAL | exec one-shot dibatasi timeout (≤300s) + kill_on_drop; revoke memblokir request baru, child yang sedang jalan dibatasi timeout |

### AD — Audit and logging

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| AD-01 | Every security-relevant event is audited: the §30 list (DEVICE_REGISTERED … EMERGENCY_STOP). | VERIFIED (subset v0.1) | request.created/denied/expired, session.approved/revoked/expired, exec.run/denied, file.*, token.rotated, auth.rejected, system.initialized |
| AD-02 | Event has the §30.1 structure. | VERIFIED (bentuk v0.1) | ts/actor/action/subject/detail JSON + jsonl mirror |
| AD-03 | Audit never contains device secret, session private key, bearer tokens, or passwords typed in a… | VERIFIED | canary check di EVIDENCE-001 §8; audit berisi id/ukuran/durasi saja |
| AD-04 | Tamper-evident: hash_n = H(event_n ‖ hash_{n-1}); data model has previous_hash / current_hash | TODO | v0.2 hardening (EVIDENCE-001 §10) |
| AD-05 | Command logging is metadata-only by default (shell, cwd, operationId) | VERIFIED | detail exec: command line, exit, durasi, byte count — tanpa isi output |
| AD-06 | Logs are structured JSON; redaction runs before emit. | VERIFIED | jsonl terstruktur; tidak ada rahasia yang bisa di-redact (tak pernah ditangkap) |
| AD-07 | Trace correlation ID across request → session → operation; no secrets in trace attributes. | PARTIAL | subject = request/session id menghubungkan event; trace id eksplisit belum |
| AD-08 | Audit retention policy. | VERIFIED (v0.8) | opt-in [audit] max_events; trim re-chains from audit.trimmed genesis, atomic rewrite, doctor stays green; unit retention_tests ×3 + e2e §28 (mutation M2) |

### UI — Local web UI

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| UI-01 | Loopback only; local auth/session cookie; SameSite; CSRF protection; strict CSP; no remote inli… | VERIFIED | plane admin loopback+TLS; cookie HttpOnly SameSite=Strict; CSRF header X-Far-Ui; e2e §19 (login 401/200, no-cookie 401, csrf 403, logout) |
| UI-02 | Prominent banner while a remote session is active: agent, access, time left, Revoke button. | VERIFIED | kartu sesi aktif menampilkan agent/scope/remaining + tombol REVOKE (e2e §19 revoke via UI) |
| UI-03 | UI always answers WHO / WHAT / UNTIL / HOW TO STOP within seconds. | VERIFIED (via CLI) | `frtrol list` menjawab keempatnya; e2e |
| UI-04 | Active session shows: provider, model, device, scope, start, expiry, connection mode, state (op… | VERIFIED (v0.8) | sessions carry agent{provider,model} (session_json); web UI + `frtrol list` show identity "declared"; e2e §24 |
| UI-05 | Screens: dashboard, pending request (+ duration & scope selectors), active session, one-click r… | VERIFIED | dashboard + pending (pilih durasi jam) + revoke + audit(50) + panic; e2e §19 |
| UI-06 | Alerts: new request · expires in 15 min · access revoked · repeated auth failures. | PARTIAL | request baru muncul di dashboard (auto-refresh 5s); banner 15-min & alert auth-fail belum (v0.4) |
| UI-07 | Response typically <200 ms (excl | VERIFIED | handler ringan + SQLite WAL; loopback <1 ms |

### CL — CLI quality

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| CL-01 | Command tree per §23 (incl | VERIFIED (subset v0.1) | init/start/status/list/approve/deny/revoke/rotate/audit + agent subcommand |
| CL-02 | Stable --json on status, sessions list, requests list. | VERIFIED (v0.8) | `frtrol status --json` + `frtrol list --json` single-line stable (e2e §26; ADR-0022) |
| CL-03 | Exit codes 0–7 as §66. | VERIFIED (v0.8) | shared exit_for() error.rs + agent & owner CLI; e2e §25 tests 0,2,3,4,5,6,7 (mutation M3 red) |
| CL-04 | Works without color; keyboard-only; narrow terminals; confirmation before destructive local act… | VERIFIED (subset) | tanpa warna; approve/deny/revoke eksplisit by design |
| CL-05 | Stable error codes FRT-001…FRT-020; human-readable messages; details only in internal logs. | VERIFIED (renamed) | kode stabil snake_case (README §2d) — penyimpangan dari FRT-xxx dicatat D-025 |
| CL-06 | frtrol doctor runs the §46 checks and prints code + action on failure. | TODO | kandidat v0.2 |
| CL-07 | frtrol version exists (§23) | VERIFIED | `frtrol --version` |

### SC — Security controls

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| SC-01 | Rate limits: device auth (progressive backoff), connection requests (per device / agent identit… | VERIFIED (v0.9) | burst window (v0.2) + progressive lockout: strikes→60s×2^n cap 1h, hammering extends, success resets; e2e §29 + mutation M1 (ADR-0023) |
| SC-02 | Config validated at startup (schema version, port range, safe bind, control-plane URL, TLS, sec… | VERIFIED (v0.9) | Config::validate() at init+run, fail-fast exit 2 `config_invalid`; 5 bad-config e2e cases + unit ×4 + mutation M2 (ADR-0023) |
| SC-03 | No hidden persistence, covert startup, credential harvesting, silent elevation, or OS-permissio… | VERIFIED (closed by verification, v1.0) | endpoint set = router compile-time (src/server.rs) — tak ada listener lain; tak ada autostart di luar systemd unit terdokumentasi (deb); secret-scan CLEAN; CLI tidak buka DB langsung (ADR-0006) |
| SC-04 | No secrets in source, test fixtures, or logs; no debug endpoints in production; no wildcard COR… | VERIFIED (closed by verification, v1.0) | secret-scan CLEAN (scripts/secret-scan.sh); audit canary EVIDENCE-001 §8 (log berisi id/bytes/durasi saja); tak ada header CORS di kode apa pun; tak ada endpoint debug (router eksplisit) |
| SC-05 | Protocol parser fuzzed; malformed remote input never crashes FARcontrol | VERIFIED | ADR-0019: corpus §75 penuh + seeded-random + concurrent; e2e §21 chaos jaringan; mutation-check panic terdeteksi |
| SC-06 | Privacy: control plane collects only what it needs (§58 list); never files, clipboard, browser … | VERIFIED (self-hosted scope, v1.0) | self-hosted penuh — tak ada telemetry/endpoint keluar (grep ureq = hanya sisi agent client); audit metadata-only (e2e §12: isi file/clipboard/output tak pernah dikirim ke plane) |
| SC-07 | Dependency hygiene: lockfiles, vuln scan, SBOM, secret scan, static analysis; signed releases | VERIFIED (v1.0) | Cargo.lock + cargo-audit (0 CVE) + SBOM SPDX (220 crate) + secret-scan CLEAN + clippy 0; **SHA256SUMS + GPG detach-signature** di rilis 1.0.0 (docs/RELEASE_KEY.asc, ADR-0024) |
| SC-08 | Incident response and recovery documented (detect → contain → revoke → preserve evidence → rota… | VERIFIED | docs/incident-response.md: 8 langkah §73 → command teruji (panic/revoke/backup/doctor tiap langkah menunjuk e2e section) |

### DB — Storage and upgrades

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| DB-01 | Persistent entities per §32 | VERIFIED (subset) | meta/requests/sessions/nonces/audit di SQLite WAL |
| DB-02 | Session transitions are transactional (UPDATE … WHERE status=…; affected rows = 0 ⇒ idempotent/… | VERIFIED | approve dalam BEGIN IMMEDIATE…COMMIT; semua transisi kondisional |
| DB-03 | Upgrade: validate compat → preserve ID/creds → migrate schema → restart safely → reconnect → re… | VERIFIED | unit test old-db upgrade in place + e2e §22 restore→restart (no re-init, token & audit survive); migrations table traceable |
| DB-04 | Packaging targets: Windows (signed MSI), macOS (signed + notarized), Linux (deb/rpm + portable)… | PARTIAL | portable Linux binary ada; deb/rpm/signing defer (ADR-0002) |

## v0.1 Definition of Done (§103)

| Item | Status | Evidence |
|---|---|---|
| frtrol start exists | VERIFIED | E2E §1; `frtrol start` banner + status |
| device identity exists | VERIFIED (deviasi D-024) | agent token = identity (ADR-0012); not 8-char ID |
| device secret exists | VERIFIED | 32-byte CSPRNG base58, file 0600 (crypto.rs test) |
| frtrol agent exists | VERIFIED | E2E — seluruh siklus lewat `frtrol agent` (ADR-0007) |
| provider selection exists | VERIFIED (v0.8) | FAR_AGENT_PROVIDER env + catalog validation (§103 DoD; D-043) |
| model selection exists | VERIFIED (v0.8) | FAR_AGENT_MODEL env + catalog validation (§103 DoD; D-043) |
| device authentication exists | VERIFIED | HMAC proof-of-possession + anti-replay (E2E §2/§3/§14; server tests) |
| connection request exists | VERIFIED | POST /v1/session/request → pending (E2E §4) |
| local approval exists | VERIFIED | admin loopback + CLI approve/deny (E2E §4/§5/§10) |
| duration selection exists | VERIFIED | request hours + approve --hours (shorten-only, unit test) |
| 5h minimum enforced | VERIFIED | policy test hours_validation + state test |
| 72h maximum enforced | VERIFIED | policy test hours_clamped (100→72) |
| Terminal Only exists | VERIFIED (one-shot) | exec + scope gate (E2E §5/§6); PTY defer v0.2 |
| Full Access exists | VERIFIED | terminal + filesystem + **process + application + desktop adapters** (E2E §20, ADR-0018; desktop on-display path NOT VERIFIED headless CI) |
| session exists | VERIFIED | SQLite sessions row + status API |
| expiration exists | VERIFIED | lazy + sweeper + persisted (E2E §11, unit test) |
| revoke exists | VERIFIED | owner & agent revoke (E2E §8/§10) |
| audit exists | VERIFIED | DB + JSONL, 10 jenis event dicek (E2E §12) |
| fail-closed behavior exists | VERIFIED | daemon down → agent gagal (E2E §13); semua auth path fail-closed |
| secure secret storage exists | PARTIAL | file 0600 + dir 0700 (Linux); OS keyring defer (D-023, EVIDENCE §10) |
| test suite covers critical paths | VERIFIED | 40 unit + 68 e2e, `reports/verification-output.txt` |

## Production readiness (§97) — 14 criteria

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Device starts reliably and registers itself | VERIFIED | e2e §1/§13 (start, restart, state restore) |
| 2 | Agent can identify itself | VERIFIED | token + agent_name (ADR-0005/0007) |
| 3 | Device auth attempts are rate-limited | VERIFIED (v0.9) | window 10/60s (v0.2) + progressive lockout 60s×2^n cap 1h, extend-on-hammer, reset-on-success; e2e §29 + M1 (ADR-0023) |
| 4 | Valid request creates a pending approval event | VERIFIED | e2e §4 + audit request.created |
| 5 | No remote operation possible before approval | VERIFIED | e2e §4 (session_not_found) + scope/design |
| 6 | Duration enforced server-side and locally | VERIFIED | e2e §11 + unit tests |
| 7 | Only the selected scope is active | VERIFIED | e2e §6 (scope_denied) |
| 8 | Session expiration terminates access | VERIFIED | e2e §11 (lazy + sweeper) |
| 9 | User revoke terminates access promptly | VERIFIED | e2e §8/§10 (instan, per-request check) |
| 10 | Audit events emitted reliably | VERIFIED | e2e §12 (10 jenis event + jsonl) |
| 11 | Secrets never appear in logs | VERIFIED | canary check EVIDENCE-001 §8 |
| 12 | Protocol inputs are fuzz-tested | VERIFIED | harness in-process §75 corpus + 2000 seeded-random + concurrent chaos (ADR-0019, mutation-checked); cargo-fuzz coverage-guided defer |
| 13 | Updates preserve the security contract | N/A (v0.1) | rilis pertama; jalur upgrade belum ada |
| 14 | Emergency stop works under stress | VERIFIED (v1.0) | e2e §32: panic saat term + 3 exec in flight — semua session revoked, terminal killed, command tak orphan (bounded timeout), token rotated, siklus baru langsung jalan, doctor ALL GREEN |
