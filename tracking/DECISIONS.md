# Decisions

Two kinds of entries live here.

1. **Spec-given defaults** — the spec states a concrete value. You may use it **without asking**; always cite the §
   and make the value configurable where the spec says so. These are *not* assumptions: they are written in the spec.
2. **Recorded decisions** — choices the owner approved (via a Q-answer or an ADR). Never record your own guess as a decision.

If a value is not in this file and not in the spec, it is a question (`QUESTIONS.md`), not a decision.

---

## A. Spec-given defaults (usable now)

| ID | Default | § | Notes |
|---|---|---|---|
| D-001 | Session lifetime min **5 h**, max **72 h** (3 days) | 13.1 | Binding. Enforce server-side and locally. |
| D-002 | Duration presets in UI: 5h, 12h, 24h, 2d, 3d | 12, 24 | API accepts any value within range (§34). |
| D-003 | Scopes: `terminal_only`, `full_access`; default scope in config `terminal_only` | 14, 43 | |
| D-004 | Max active sessions per device = **1** | 35, 43 | Spec "v0.1 recommended default". Configurable key `security.max_active_sessions`. |
| D-005 | Pending request TTL = **5 minutes** | 85 | Spec: "for example 5 minutes by default". |
| D-006 | Local UI bind `127.0.0.1`, port `7481` | 8.3, 43, App. B | Port is an example → must be configurable (`--port`). Host must default to loopback. |
| D-007 | Protocol version string `FAR-PROTO/1`; semver for the app | 44 | |
| D-008 | Device ID: 8 chars; Device Secret: 24 chars, ≥128 bits entropy | 7 | Alphabets: Q-015. |
| D-009 | Exit codes 0–7 as in §66 | 66 | |
| D-010 | Error codes `FRT-001`…`FRT-020` as in §37 | 37 | "Suggested stable" — adopt, keep stable once shipped. |
| D-011 | Config shape (conceptual): `version, runtime.{host,port,web_ui}, control_plane.endpoint, security.{require_user_approval,min_session_hours,max_session_hours,max_active_sessions}, session.default_scope, logging.level`. Secrets never in this file. | 43 | `require_user_approval` must not be settable to a value that bypasses approval in release builds (§77). |
| D-012 | Provider/model catalog exactly as in §81 (data-driven) | 9, 81 | Slugs: Q-018. |
| D-013 | Local config location example `~/.farcontrol/config.json` (non-secret only) | 21 | Spec uses it as the "do not store secrets here" example. Final path: confirm with owner if it matters. |
| D-014 | All timestamps UTC; monotonic clock for local timeouts | 47 | |
| D-015 | Audit logging command content: **metadata-only by default** | 95 | |
| D-016 | Session lifecycle sequences for expire/revoke as in §13.2 and §28 | 13.2, 28 | |

## B. Recorded decisions (owner-approved)

| ID | Decision | Source (Q-xxx / ADR) | Date |
|---|---|---|---|
| D-017 | Bahasa implementasi: **Rust** (stable, ed. 2021) untuk daemon + kedua CLI; komparasi 9 kandidat di `farcontrol/docs/05-language-comparison.md` (Rust 9.15 vs Go 8.30) | Q-001 / ADR-0001 | 2026-10-02 |
| D-018 | OS target v0.1: **Linux (x86_64)**; macOS/Windows defer | Q-012 / ADR-0002 | 2026-10-02 |
| D-019 | Control plane: **self-hosted penuh di mesin owner**, direct listeners, tanpa layanan tunnel/cloud; remote via SSH/WireGuard | Q-002 / ADR-0003 | 2026-10-02 |
| D-020 | Transport: HTTP/1.1+JSON dua plane (agent 7788 configurable, admin **loopback-only**); TLS native = v0.2 | Q-003 / ADR-0004 | 2026-10-02 |
| D-021 | Auth: token base58 32-byte + **HMAC-SHA256 proof-of-possession** (ts±300s, nonce sekali-pakai persisten, compare constant-time) | Q-004 / ADR-0005 | 2026-10-02 |
| D-022 | Approval path: CLI owner via admin plane loopback (daemon menolak bind admin non-loopback) | Q-006 / ADR-0006 | 2026-10-02 |
| D-023 | Token disimpan plaintext lokal (SQLite meta + file 0600) untuk self-hosted single-user; **verifier-only storage defer ke hosted CP v0.2** — deviasi sadar & terdokumentasi | Q-004/005 / ADR-0005, EVIDENCE-001 §10 | 2026-10-02 |
| D-024 | Format identitas v0.1 menyimpang dari §7: prefixed base58 (`req_`/`ses_` 16-byte) + token 32-byte (256-bit, > 128-bit spec floor) — konsisten ADR-0012 | Q-015 / ADR-0012 | 2026-10-02 |
| D-025 | Agent interface AI-first: REST JSON + CLI `frtrol agent`; output JSON satu baris; error `{"error":{"code"}}` stabil | Q-007 / ADR-0007 | 2026-10-02 |
| D-026 | Policy: **paket standart** — 5–72h, 1 session aktif (D-004), request TTL 300s (D-005), exec 30s/max 300s, output 256 KiB, file ≤1 MiB bawah $HOME, denylist destruktif, 10 pending/agent | Q-008 / ADR-0008 | 2026-10-02 |
| D-027 | Scope `full_access` v0.1 = terminal + file read/write/list **bawah $HOME** (guard canonicalize); adapter lain defer | Q-011 / ADR-0009 | 2026-10-02 |
| D-028 | Tidak ada web UI/login di v0.1 (CLI-first; console web read-only = kandidat v0.2 pasca review) | Q-013 / ADR-0010 | 2026-10-02 |
| D-029 | State: **SQLite WAL** single-file + audit mirror `audit.jsonl`; hash chain & retention = v0.2 | Q-017 / ADR-0011 | 2026-10-02 |
| D-030 | v0.1 scope = vertical slice penuh (ADR-0000): siklus session + exec + file + audit; PTY/streaming, TLS, fuzz defer | ADR-0000 | 2026-10-02 |

| D-031 | **CLI simpel**: semua perintah agen positional (`frtrol agent exec ses_x ls -la` — tanpa `--`, tanpa `--session-id`); `frtrol start` auto-init saat pertama kali; `frtrol` tanpa argumen cetak quick guide; `write` terima konten argumen/pipe stdin | owner feedback post-build (2026-10-02) | 2026-10-02 |

| D-032 | **v0.2 built**: TLS rustls kedua plane (cert self-signed TOFU, ADR-0015), terminal PTY interaktif `/v1/term/*` + `frtrol agent term` (ADR-0013), `frtrol panic` SE-11 + `frtrol doctor` §46 (ADR-0014), rate-limit 10/60s fail-closed, audit hash chain + verify, policy `[policy]` di config.toml, env-scrub exec/term, migrations DB v2, paket .deb + systemd | owner: "bangun sampai benar-benar bisa digunakan, full spec" | 2026-10-02 |
| D-033 | Enrollment agen v0.2 = **token + cert.pem** (TOFU pinning; FARCONTROL_CA override; use_tls=false utk loopback dev) | ADR-0015 | 2026-10-02 |
| D-034 | Rate limiter bersifat **global** (asumsi single-tenant self-hosted), bukan per-IP — window slide 60s, 429 rate_limited, fail closed | ADR-0016 | 2026-10-02 |
| D-035 | Audit tamper-evidence lewat **hash chain di audit.jsonl** (prev+sha256), diverifikasi doctor; audit tabel DB tetap tanpa hash | ADR-0016 | 2026-10-02 |
| D-036 | Term limits: max 8 terminal konkuren, stdin ≤64KiB/chunk, drain ≤256KiB/read, buffer rolling 1MiB, mati bersama session | ADR-0013 | 2026-10-02 |
| D-037 | Web UI v0.3 ditumpangkan ke **plane admin loopback+TLS** (bukan listener baru); login = admin token → cookie HttpOnly SameSite=Strict 1h in-memory; CSRF = header JS-only X-Far-Ui; XSS dicegah struktural (textContent, tanpa HTML sink) | ADR-0017 | 2026-10-02 |
| D-038 | Adapter v0.4: process via /proc+libc kill (guard PID1 & self), app launch detached (orphan-reaper), desktop via tools tetap fix argv + **fail closed desktop_unavailable** saat headless; scope gate jalan sebelum availability | ADR-0018 | 2026-10-02 |
| D-039 | Fuzz v0.5 = black-box in-process pada router ASLI (request ter-HMAC-sign, corpus §75 penuh + 2000 seeded-random + 50-way concurrent) tiap cargo test; cargo-fuzz coverage-guided defer; bug nyata 413-plain-text ketemu & difix | ADR-0019 | 2026-10-02 |
| D-040 | Backup = server-side via admin plane (WAL checkpoint + tar fixed-argv → bytes 0600); restore = offline, allowlist anti-traversal, open_db-verify (migrasi jalan = DB-03 live), swap dgn .bak; cargo-audit + SBOM SPDX + secret-scan + clippy masuk verifikasi rutin | ADR-0020 | 2026-10-02 |
| D-041 | Observability v0.7: healthz/readyz unauth di plane admin loopback (tanpa kebocoran), metrics Prometheus auth admin, crash recovery = WAL + e2e SIGKILL, systemd unit di-hardening (Restart=always + sandbox), runbook insiden §73 dipetakan ke command teruji | ADR-0021 | 2026-10-02 |

| D-042 | **Owner override: build beyond the spec's v0.1 ceiling to 1.0.0** (single release). Spec §103/§101 mark post-v0.1 as "do not build"; owner instructions 2026-10-02 ("bangun sampai benar-benar bisa digunakan, full spec" → 0.2; "dari 0.2.0 sampai 0.7.0" → 0.7; "selesaikan project farcontrol sampai versi 1.0.0" → 1.0) explicitly override. Scope stays inside the ADR-0000 self-hosted slice + spec surface it can honestly claim; §101 exotic items (org mode, TPM, hosted CP, agent keypairs, session recording) remain NOT BUILT. GitHub release: exactly ONE release (v1.0.0), repo contents complete. | owner instruction (2026-10-02) | 2026-10-02 |
| D-043 | **v0.8.0 (ADR-0022)**: agent identity catalog data-driven embedded JSON (z_ai ×4 GLM, qwen ×5 — spec §9.2–9.4); identity optional both-or-none declaration, server-side validation only, UI labels "declared — not verified" (AG-03); §66 exit codes 0–7 shared `exit_for()` (observed wire code `invalid_signature` → 3); §45 `status --json` / `list --json`; `X-Far-Proto` absent=1 (compat), ≠1 → 422 unsupported_proto; audit retention opt-in `[audit] max_events` (default keep-forever, trim re-chains from `audit.trimmed` genesis, atomic rewrite); schema v3 + SCHEMA_VERSION const (fixes readyz drift regression). | ADR-0022 | 2026-10-02 |
| D-044 | **v0.9.0 (ADR-0023)**: (1) progressive auth backoff — strike counter → lock 60s×2^(strikes−10) cap 1h, attempts while locked EXTEND the lock, only successful auth resets; audited `auth.backoff` on duration change; agent plane + UI login only (admin plane deliberately unlocked: owner panic path must survive an attack); (2) startup config validation `Config::validate()` at init+run → `config_invalid` exit 2, fail-before-bind, doctor upgraded to parse+validate; (3) OS keyring opt-in `[identity] secret_store="keyring"` — Linux kernel keyring via raw syscalls (persistent ring→user-ring fallback), no plaintext file/DB row, per-request load, rotate-in-place, backup materialize+unlink, restore write-back; **fail-closed `usable()` probe** (store→load→remove roundtrip) karena sandbox gVisor-style mengimplementasikan keyring parsial (add_key ok, READ/SEARCH EINVAL) — full path berjalan di kernel Linux asli, refusal terverifikasi di sandbox. 3 mutation checks M1/M2/M3 all caught. | ADR-0023 | 2026-10-02 |

## C. Decision log format

```
D-NNN  <what was decided>
       Approved by: owner (<date>)    Source: Q-xxx / ADR NNNN
       Affects REQ: …                  Reversal cost: low | medium | high
```
