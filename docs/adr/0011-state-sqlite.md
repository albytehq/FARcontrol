# ADR-0011 — State Store: SQLite (WAL, Single File)

**Status:** ACCEPTED (by owner, 2026-10-02 — "state table rekomendasi")
**Related:** Q-009, ADR-0001 (rusqlite), spec §state

## 1. Context
State FARcontrol: requests (pending), sessions (active/revoked/expired), nonces (anti-replay), audit trail, meta (token). Constraint owner: self-hosted, cepat, gratis.

## 2. Known / Inferred / Unknown
- KNOWN: SQLite = public domain, single-file, tanpa server DB terpisah, WAL mode = reader tak memblok writer.
- KNOWN: daemon = satu-satunya writer (semua mutasi lewat daemon); CLI tidak pernah membuka DB langsung.
- INFERRED: beban tulis rendah (puluhan event/menit) → SQLite overkill-safe.
- UNKNOWN: kebutuhan HA/klaster — tidak ada di spec v0.1 (single host by design).

## 3. Options
| Option | Kepuasan "cepat/free/self-hosted/simpel" | Risiko | Kompleksitas |
|---|---|---|---|
| A: SQLite WAL via rusqlite (bundled) | Penuh | — | Rendah |
| B: File JSON di-rewrite | "Simpel" tapi race-prone & O(n) | Korupsi race | Rendah |
| C: PostgreSQL | Butuh service kedua | Berat untuk single-host | Tinggi |

## 4. Recommendation
**A.** Satu file `state.db` di data dir (default `~/.farcontrol/`), mode WAL + busy_timeout 5s + synchronous NORMAL. Schema: `requests`, `sessions`, `nonces`, `audit`, `meta` (lihat `src/state.rs`). Audit juga **di-mirror ke `audit.jsonl`** (append-only) sebagai bukti forensik yang gampang di-grep.

## 5. Security analysis
File DB di data dir 0700 → hanya user owner. Nonce persisten di DB = anti-replay lintas restart (invarian 7). Tidak ada service DB eksternal = tidak ada port tambahan yang dijaga. Audit table + JSONL memenuhi invarian 8 ganda.

## 6. How we will verify it
Unit test lifecycle penuh pada in-memory/temp DB; e2e memeriksa baris audit & keberadaan file WAL/JSONL; kill daemon → restart → nonce lama masih menolak replay.

## 7. Consequences
Single-host by design. Migrasi schema ke depan = `schema_version` di meta. Defer: retensi audit rotation, DB encryption.
