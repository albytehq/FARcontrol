# ADR-0010 — UI Login: Tidak Ada di v0.1 (CLI-First)

**Status:** ACCEPTED (by owner, 2026-10-02 — "ui login. rekomendasi")
**Related:** Q-007, ADR-0006

## 1. Context
Pertanyaan: perlukah login UI (web console) di v0.1? Owner menyerahkan ke rekomendasi.

## 2. Known / Inferred / Unknown
- KNOWN: jalur approval v0.1 = CLI (ADR-0006); admin plane loopback.
- INFERRED: menambah web console + auth UI = trust boundary baru (session cookie, CSRF, XSS) sebelum core terverifikasi — melanggar Rule 1 (over-engineering) dan memperbesar attack surface tanpa nilai proposisi inti.
- UNKNOWN: preferensi visual owner → dicatat untuk v0.2.

## 3. Options
| Option | Nilai v0.1 | Risiko | Kompleksitas |
|---|---|---|---|
| A: Tanpa UI — CLI + output daemon + audit | Cukup (SSH-friendly) | — | Rendah |
| B: Web console + login lokal | Nyaman | Surface XSS/CSRF/session mgmt baru sebelum core teruji | Tinggi |

## 4. Recommendation
**A.** v0.1: tidak ada login UI, tidak ada password, tidak ada web server tambahan. Kepercayaan dibangun dari: file permission Unix + loopback admin + token 0600. Web console (read-only dashboard + tombol approve) = kandidat v0.2 **hanya setelah** core lulus audit eksternal.

## 5. Security analysis
Mengurangi trust boundary: tidak ada credential browser, tidak ada endpoint HTML yang bisa di-XSS, tidak ada session cookie. Invarian 6 (identity ≠ authorization) tetap tegak di dua plane yang ada. Fail-closed default terjaga.

## 6. How we will verify it
Review: tidak ada listener tambahan selain dua yang terdefinisi (e2e memastikan bind sesuai); tidak ada kode HTML/renderer dalam binary (audit manual sederhana).

## 7. Consequences
Owner berinteraksi via terminal/SSH di v0.1. Defer: web console, mobile push, approval via pesan.
