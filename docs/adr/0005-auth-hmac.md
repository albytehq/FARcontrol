# ADR-0005 — Autentikasi: Agent Token + HMAC Proof-of-Possession + Anti-Replay

**Status:** ACCEPTED (by owner, 2026-10-02 — "auth design. rekomendasi aja")
**Related:** Q-004, spec §kripto verifier & proof-of-possession, invarian 5–7

## 1. Context
Gap Q-004: bagaimana daemon memverifikasi agent tanpa menyerahkan credential yang bisa dipakai ulang pihak lain. Binding spec: secret ≠ session token; identity ≠ authorization; proof-of-possession disebut spec sebagai mekanisme kripto.

## 2. Known / Inferred / Unknown
- KNOWN: token statis bearer rentan replay/pencurian via log/proxy.
- KNOWN: HMAC-SHA256 over request + timestamp + nonce = proof-of-possession klasik tanpa kerumitan mTLS.
- INFERRED: window ±300s + nonce-unique-per-window memadai untuk v0.1.
- UNKNOWN: — (desain selesai; rotasi token disediakan).

## 3. Options
| Option | Kepuasan constraint | Risiko | Kompleksitas |
|---|---|---|---|
| A: Token + HMAC-SHA256(ts, nonce, method, path, body-hash) | Proof-of-possession penuh, tanpa TLS | Tidak menutup kerahasiaan plaintext | Rendah |
| B: mTLS | Kuat | Key mgmt berat; agent AI sulin setup cert | Tinggi |
| C: Bearer token polos | Paling mudah | Rentan replay — ditolak | Rendah |

## 4. Recommendation
**A.** Agent token (32 byte random, base58) dibuat `frtrol init`/`frtrol rotate`, disimpan file 0600, ditunjukkan sekali ke owner. Setiap request agent menandatangani: `ts \n nonce \n METHOD \n path \n sha256(body)` dengan HMAC key = token. Server cek: header ada → window ±300s → nonce belum pernah dipakai (tabel SQLite, persisten) → signature constant-time. Gagal salah satu = 401 + audit. Admin plane: bearer admin token via loopback (attack surface berbeda).

## 5. Security analysis
Melawan attacker C (jaringan): request yang ditangkap tidak bisa direplay (nonce) dan tidak bisa dimodifikasi (HMAC body). Melawan attacker A (agent liar) dan E (token curi): token tanpa proof tidak cukup; rotasi mematikan token lama seketika. Invarian 5: token = identitas; session = otorisasi — dua benda berbeda. Fail-closed: daemon baru start (nonce table kosong) tetap menolak replay lintas restart karena nonce persisten di DB.

Keterbatasan jujur: bila attacker membaca traffic plaintext DAN bisa inject, ia tetap tidak bisa memalsukan request baru (butuh key), tapi bisa membaca konten respons — kerahasiaan adalah tugas WireGuard/TLS (ADR-0003/0004), bukan HMAC.

## 6. How we will verify it
Unit test: signature valid, signature salah ditolak constant-time, timestamp basi ditolak, nonce sama kedua kalinya ditolak (replay), nonce persisten lintas "restart" (reopen DB). e2e: request tanpa header → 401; `frtrol rotate` → token lama mati.

## 7. Consequences
Agent harus bisa HMAC (trivial: python 5 baris / CLI frtrol agent built-in). Deferred: mTLS untuk jangkauan publik tanpa VPN (v0.2), refresh token otomatis.
