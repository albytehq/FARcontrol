# ADR-0004 — Transport: HTTP/1.1 + JSON, Loopback Default

**Status:** ACCEPTED (by owner, 2026-10-02 — "Transport. rekomendasi aja")
**Related:** Q-003, ADR-0003, ADR-0005

## 1. Context
Agent (AI) harus bisa memanggil control plane dengan cara paling universal. Binding: control plane self-hosted (ADR-0003).

## 2. Known / Inferred / Unknown
- KNOWN: HTTP+JSON adalah protokol paling universal bagi agent AI (curl, python requests, SDK apa pun).
- KNOWN: dua bidang berbeda: agent plane (jaringan) dan admin plane (owner lokal).
- INFERRED: HTTP/1.1 dengan keep-alive memenuhi kebutuhan latency lokal (<1 ms RTT loopback).
- UNKNOWN: kebutuhan streaming output panjang → defer (v0.2 pertimbangkan chunked/SSE).

## 3. Options
| Option | Kepuasan kebutuhan | Risiko | Kompleksitas |
|---|---|---|---|
| A: HTTP/1.1 + JSON, dua listener (agent + admin) | Universal, cepat, sederhana | Plaintext di LAN (dim mitigasi HMAC) | Rendah |
| B: gRPC | Cepat tapi butuh protobuf codegen; CLI agent jadi ribet | Agent AI kurang familier | Sedang |
| C: WebSocket duplex | Bagus utk streaming, overkill sekarang | State machine lebih rumit | Sedang |

## 4. Recommendation
**A.** Satu listener agent (default `127.0.0.1:7788`, `--bind` untuk LAN) + satu listener admin **selalu loopback** (`127.0.0.1:7789`). Semua error berbentuk JSON machine-readable: `{"error":{"code":"...","message":"..."}}`. Endpoint map didokumentasikan di README (AI-first).

## 5. Security analysis
Admin plane dipaksa loopback → agent tidak pernah bisa menjangkau API approval. Agent plane dilindungi HMAC proof-of-possession (ADR-0005). Invariant 7 (network failure = fail closed): koneksi gagal = tidak ada aksi. Plaintext LAN diterima sementara dengan syarat HMAC; kerahasiaan penuh datang bersama TLS/rustls v0.2 atau WireGuard.

## 6. How we will verify it
e2e: request agent via HTTP; admin API tak terjangkau dari bind non-loopback (unit test validasi admin bind); error format JSON di semua jalur gagal (e2e mem-parse kode error mesin).

## 7. Consequences
v0.1 tanpa TLS native — jujur didokumentasikan sebagai limitation. Streaming/SSE defer. REST sederhana = mudah di-wrap SDK bahasa apa pun oleh agent.
