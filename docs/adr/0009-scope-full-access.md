# ADR-0009 — Scope `full_access`: Terminal + File di Bawah `$HOME`

**Status:** ACCEPTED (by owner, 2026-10-02 — "full access. rekomendasi aja")
**Related:** Q-011, spec §scope, invarian 4

## 1. Context
Spec mendefinisikan dua scope: `terminal_only` dan `full_access`. Pertanyaan: apa isi `full_access`?

## 2. Known / Inferred / Unknown
- KNOWN: terminal yang sudah disetujui manusia secara teknis bisa menyentuh seluruh FS (itulah hakikat terminal).
- INFERRED: file API tetap harus punya pagar lebih ketat daripada terminal — karena file API adalah jalur paling mudah bagi agent untuk menulis sesuatu secara massal.
- UNKNOWN: —.

## 3. Options
| Option | Isi full_access | Risiko | Kompleksitas |
|---|---|---|---|
| A: terminal + file read/write/list bawah `$HOME` (guard canonicalize) | Praktis & berpagar | Escape symlink (dimediasi) | Rendah |
| B: terminal + file tanpa pagar | Konsisten dgn terminal tapi API massal tanpa rem | Bahaya | Rendah |
| C: terminal + file + process control + network proxy | Scope creep v0.1 | Over-engineering | Tinggi |

## 4. Recommendation
**A.** `full_access` = `terminal_only` + operasi file di bawah root `$HOME`: `~` expansion, path relatif dianggap relatif `$HOME`, target di-*canonicalize* lalu wajib ber-prefix root; tulis ke path baru = parent harus sudah ada & valid; ukuran dibatasi policy (ADR-0008). Catat jujur: terminal sendiri tetap bisa `cat /etc/passwd` — scope terminal memang luas; pagar file API adalah lapisan tambahan, bukan pengganti approval manusia.

## 5. Security analysis
Melawan agent liar (A) yang ingin menulis ke `/etc/ld.so.preload` atau `~/.ssh/authorized_keys` **via file API** → ditolak path guard (403 `path_outside_root`). Catatan TOCTOU symlink: antara canonicalize dan write ada race kecil — diterima untuk v0.1 (didaftar limitation); mitigasi nyata = approval hanya untuk agent terpercaya. Fail-closed: semua kegagalan resolve = 4xx, bukan fallback.

## 6. How we will verify it
Unit test: path luar root ditolak, `~` benar, parent-baru ditolak; e2e: write ke `/tmp/x` → 403; read hasil write sendiri → konten cocok; terminal_only coba file API → 403 `scope_denied`.

## 7. Consequences
File di luar `$HOME` harus lewat terminal (ditujukkan eksplisit di README). TOCTOU hardening (openat2) & allowlist direktori = v0.2.
