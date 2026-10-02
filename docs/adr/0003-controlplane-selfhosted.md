# ADR-0003 — Control Plane: Self-Hosted Direct (Tanpa Layanan Tunnel)

**Status:** ACCEPTED (by owner, 2026-10-02 — "SELF hosted lengkap, wajib sangat cepat, fully free, jangan pakai cloudflared")
**Related:** Q-002, spec §control plane

## 1. Context
Owner menolak layanan tunnel pihak ketiga (cloudflared dsb.) dan mensyaratkan: self-hosted penuh, cepat, gratis. Artinya: daemon FARcontrol berjalan di mesin owner, mengelola listener miliknya sendiri; tidak ada komponen SaaS di jalur kontrol.

## 2. Known / Inferred / Unknown
- KNOWN: tanpa tunnel service, jangkauan default = loopback/LAN; akses remote = tanggung jawab jaringan owner.
- INFERRED: untuk pemakaian AI agent di mesin yang sama / LAN / VPS, direct listener memenuhi semua kebutuhan tanpa perantara.
- UNKNOWN: topologi pasti owner — diserahkan ke opsi deployment yang didokumentasikan (README §Remote Access).

## 3. Options
| Option | Kepuasan "self-hosted/cepat/free/no-cloudflared" | Risiko | Kompleksitas |
|---|---|---|---|
| A: Direct listener HTTP di mesin owner (loopback default, LAN opt-in) | Penuh | Akses remote butuh layer jaringan owner (SSH/WireGuard) | Rendah |
| B: Reverse proxy wajib (nginx/caddy) | Penuh tapi menambah komponen | Setup owner lebih berat | Sedang |
| C: QUIC/QUIC-mesh custom | Penuh | Kompleks; belum perlu (Rule 1) | Tinggi |

## 4. Recommendation
**A.** Daemon mem-bind sendiri; `--bind` untuk LAN. Untuk akses lintas-jaringan, README mendokumentasikan **WireGuard** atau **SSH tunnel** — keduanya self-hosted, gratis, terenkripsi, tanpa pihak ketiga. TLS native (rustls) dijadwalkan ADR-0004 fase lanjut.

## 5. Security analysis
Tanpa pihak ketiga = attack surface supply chain & akun cloud hilang. Kelemahan yang diterima: plaintext HTTP di jaringan lokal — dim mitigasi HMAC (ADR-0005) yang melindungi integrity+authn tanpa TLS; kerahasiaan konten di jaringan = tanggung jawab WireGuard/SSH tunnel bila lintas host. Fail-closed: listener mati = tidak ada akses.

## 6. How we will verify it
e2e lokal (loopback) hijau; manual-checklist remote (SSH tunnel + WireGuard) didokumentasikan; tidak ada dependensi network runtime selain std.

## 7. Consequences
Owner yang mengatur jangkauan jaringan (sesuai selera self-hosted). TLS di dalam daemon (rustls, self-signed otomatis) = kandidat v0.2. Layanan tunnel tetap dilarang sesuai mandat.
