# ADR-0012 — Format Identifier, Token & Encoding (Alphabets)

**Status:** ACCEPTED (by owner, 2026-10-02 — "alphabets rekomendasi / sisanya rekomendasi aja")
**Related:** Q-013 (alphabets), ADR-0005

## 1. Context
Diperlukan konvensi format untuk: ID objek (request/session), token rahasia, tanda tangan, dan payload biner — supaya unambiguous, aman-disalin, dan gampang dibedakan mata & mesin.

## 2. Known / Inferred / Unknown
- KNOWN: base58 (Bitcoin alphabet) menghilangkan `0 O I l` — mengurangi salah-baca manusia; hex lowercase = kanonik untuk digest; base64 standard untuk payload biner.
- INFERRED: prefix type-safe mencegah ID tertukar tempat (request vs session) di CLI & API.
- UNKNOWN: —.

## 3. Options
| Option | Kejelasan | Risiko | Kompleksitas |
|---|---|---|---|
| A: prefix + base58 utk ID/token; hex utk signature/digest; base64 utk payload | Tinggi (ID tak tertukar) | — | Rendah |
| B: UUID v4 semua | Seragam tapi sulit dibedakan mata & panjang | Salah-tempat ID | Rendah |

## 4. Recommendation
**A.** Konvensi v0.1:
- `req_<base58>` — 16 byte random (±22 char) — pending request.
- `ses_<base58>` — 16 byte random — session grant.
- Token agent/admin: base58 32 byte, **tanpa prefix**, 44–45 char (disimpan file, tidak sering diketik).
- Signature & digest: hex lowercase (64 char untuk SHA-256).
- Body biner (file content): base64 standard.
- Timestamp: unix detik (UTC) di semua wire & DB; ISO-8601 hanya untuk display CLI.
- Semua wire field: `snake_case`.

## 5. Security analysis
Randomness dari CSPRNG OS (`getrandom`), bukan PRNG userland — 32 byte token = 256 bit entropi (brute force tidak realistis). Prefix mencegah kelas bug "session_id dimasukkan ke kolom request_id" — kejelasan adalah mitigasi bug otorisasi. Constant-time compare di semua perbandingan rahasia.

## 6. How we will verify it
Unit test: format ID (prefix, charset base58, panjang); distribusi acak (dua generasi beda); hex signature 64 char di e2e header.

## 7. Consequences
Konvensi ini bagian kontrak wire → stabil lintas versi. Tidak ada opsi konfigurasi format (kesederhanaan).
