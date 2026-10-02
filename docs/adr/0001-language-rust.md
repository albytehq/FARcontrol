# ADR-0001 — Bahasa Implementasi: Rust

**Status:** ACCEPTED (by owner, 2026-10-02 — "yang paling bagus, yang bener-bener bagus, wajib komparasi")
**Related:** docs/05-language-comparison.md (dokumen komparasi lengkap), Q-001

## 1. Context
Owner meminta komparasi bahasa pemrograman yang ketat untuk FARcontrol dan mandat "pilih yang terbaik". FARcontrol adalah daemon keamanan-kritis: parsing input jaringan tidak-terpercaya, evaluasi otorisasi, eksekusi perintah sistem. Control plane juga wajib "sangat cepat" (owner), self-hosted, fully free.

## 2. Known / Inferred / Unknown
- KNOWN: 9 kandidat dievaluasi dengan 8 kriteria berbobot (docs/05 §2); finalis Rust vs Go.
- KNOWN: skor tertimbang Rust 9.15 vs Go 8.30.
- INFERRED: biaya velocity Rust (±30–40%) terkompensasi scope v0.1.0 yang kecil.
- UNKNOWN: — (komparasi selesai; owner menerima hasil).

## 3. Options
| Option | Skor | Risiko | Kompleksitas |
|---|---|---|---|
| Rust | 9.15 | Compile lambat, kurva belajar | Sedang |
| Go | 8.30 | GC jitter, cgo bila SQLite, race tidak dijamin compiler | Rendah |
| Lainnya (C, C++, Zig, Python, Node, JVM, Crystal/D/Nim) | ≤6.5 | Lihat eliminasi docs/05 §3 | Bervariasi |

## 4. Recommendation
**Rust** (stable, edition 2021): memory safety terjamin compiler pada permukaan serangan, determinisme latensi tanpa GC, enum+Result membuat state machine session tidak-bisa-salah-representasi, rusqlite bundled tanpa cgo. Detail lengkap + trade-off jujur: docs/05-language-comparison.md.

## 5. Security analysis
Kelas kerentanan "memory corruption di parser jaringan" tidak punya representasi di jalur safe Rust. Data race pada session table ditolak compiler. Supply chain: ±11 crate langsung, semuanya populer/teraudit; **zero `unsafe` di kode aplikasi**. Membantu melawan attacker A (agent liar) dan C (serangan jaringan).

## 6. How we will verify it
Binary ter-build dari source yang sama yang lulus test; `cargo build --release` + `cargo test` + e2e hijau; ukur RAM/latency startup sebagai sanity check "sangat cepat" (target < 50 ms startup, < 20 MB RSS).

## 7. Consequences
Lebih lambat menulis & compile; imbalannya garansi compiler. Fallback Go terdokumentasi dengan trigger revisit (docs/05 §7). Satu bahasa untuk daemon + kedua CLI = satu toolchain.
