# ADR-0002 — Target OS: Linux (x86_64) untuk v0.1

**Status:** ACCEPTED (by owner, 2026-10-02 jawaban: "OS target: Linux dulu")
**Related:** Q-012, spec §OS target

## 1. Context
Owner menetapkan Linux sebagai target pertama. Kebanyakan workload self-hosted dan VPS owner berbasis Linux; fokus satu OS memperkecil permukaan uji.

## 2. Known / Inferred / Unknown
- KNOWN: environment build & uji = Debian (gcc 14, kernel Linux).
- INFERRED: glibc dynamic binary cukup untuk mesin owner sendiri; static musl defer.
- UNKNOWN: distribusi spesifik owner — dianggap distro mainstream (systemd tersedia).

## 3. Options
| Option | Kepuasan constraint | Risiko | Kompleksitas |
|---|---|---|---|
| A: Linux x86_64 saja (v0.1) | Penuh | Tidak menjangkau pengguna macOS/Windows dulu | Rendah |
| B: Linux + macOS sekaligus | Lebih luas | Uji ganda; signal handling beda | Sedang |

## 4. Recommendation
**A.** Satu OS, satu jalur verifikasi. Abstraksi OS minimal (process spawn, file perms) sudah portabel via std Rust — jalan ke macOS/Windows terbuka di v0.2 tanpa refactor besar.

## 5. Security analysis
File permission Unix (0600/0700) jadi bagian dari kontrol akses token & data dir; Linux user-isolation (daemon berjalan sebagai user owner, **menolak root** kecuali `--allow-root`) mengecilkan blast radius.

## 6. How we will verify it
Build + seluruh test suite + e2e berjalan di Linux; unit test menutupi permission bit; uji `frtrol start` sebagai non-root.

## 7. Consequences
v0.1 tidak mendukung macOS/Windows (dieksplisitkan di README). Kompilasi silang & static build defer ke v0.2 (opsional musl).
