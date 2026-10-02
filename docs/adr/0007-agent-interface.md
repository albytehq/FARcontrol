# ADR-0007 — Antarmuka Agent: REST JSON + CLI `frtrol agent` (AI-First)

**Status:** ACCEPTED (by owner, 2026-10-02 — "agent interface. rekomendasi aja. pastikan AI jadi sangat super mudah buat ngeakses dan kontrolnya")
**Related:** Q-006, ADR-0004, ADR-0005

## 1. Context
Constraint keras owner: AI agent harus **sangat super mudah** mengakses dan mengontrol. Antarmuka harus bisa dipakai tanpa membaca dokumentasi panjang, dari bahasa/SDK apa pun, dengan error yang bisa diprogram.

## 2. Known / Inferred / Unknown
- KNOWN: model AI paling mahir dengan: HTTP + JSON, CLI yang output-nya terstruktur, pesan error yang jelas, dan contoh curl yang bisa disalin.
- INFERRED: dua pintu (API mentah + CLI) menutup semua level kemampuan agent.
- UNKNOWN: — (pola sudah terbukti di industri).

## 3. Options
| Option | Kemudahan bagi AI | Risiko | Kompleksitas |
|---|---|---|---|
| A: REST JSON + CLI wrapper (`frtrol agent ...`) + contoh curl di README | Maksimal | — | Rendah |
| B: REST saja | Agent harus sign HMAC manual (friction) | Kurang ramah agent lemah | Rendah |
| C: SDK per-bahasa | Lebih kerja; menjaga 3 repo | Over-engineering v0.1 | Tinggi |

## 4. Recommendation
**A — dua pintu:**
1. **API HTTP** (ADR-0004): endpoint sempit & prediktabel — `/v1/ping`, `/v1/session/request`, `/v1/session/status`, `/v1/session/revoke`, `/v1/exec`, `/v1/file/read|write|list`. Semua response JSON; semua error `{"error":{"code","message"}}` dengan kode mesin stabil (tabel di README).
2. **CLI `frtrol agent`**: wrapper signing + HTTP — agent tinggal: `frtrol agent ping`, `frtrol agent request --scope ... --hours ... --reason ...`, `frtrol agent exec --session-id ... -- <cmd>`, `frtrol agent status --request-id ...`, dst. Output default JSON (mudah di-parse LLM); `--raw` untuk manusia.
3. Token via `--token`, env `FARCONTROL_TOKEN`, atau file token — agent menyalin satu secret saja.

## 5. Security analysis
Kemudahan TIDAK boleh menembus otorisasi: pintu agent tetap penuh HMAC + session + policy; CLI hanya memindahkan kerja kripto, bukan menurunkan verifikasi. Error code justru memperkuat invariant 7 (agent tahu kenapa gagal dan tidak retry membabi-buta). Semua aksi agent via pintu ini ter-audit.

## 6. How we will verify it
e2e menjalankan **seluruh siklus lewat `frtrol agent` saja** (tidak ada pintu belakang); README memuat contoh curl + python 10 baris yang bisa langsung jalan; error code e2e diparse programatik.

## 7. Consequences
Kontrak JSON = kontrak publik produk; perubahan endpoint harus backward-selaras di v0.2+. SDK bahasa & streaming defer.
