# ADR-0006 — Jalur Approval: CLI Lokal Owner (via Admin Loopback API)

**Status:** ACCEPTED (by owner, 2026-10-02 — "approval path. rekomendasi aja")
**Related:** Q-005/Q-008, spec §approval, invarian 1 & 8

## 1. Context
Setiap permintaan session harus berakhir ke keputusan manusia: APPROVE atau DENY. Jalur keputusan harus selalu tersedia, tidak bisa dimanipulasi agent, dan tercatat.

## 2. Known / Inferred / Unknown
- KNOWN: owner memakai Linux desktop/server; CLI = interface paling andal di semua situasi (SSH pun bisa).
- INFERRED: notifikasi terminal/log daemon + `frtrol list` cukup untuk v0.1; notifikasi desktop (notify-send) opsional kalau tersedia.
- UNKNOWN: preferensi UI visual owner → dicatat sebagai wish v0.2 (web console, ADR-0010).

## 3. Options
| Option | Kepuasan "human in the loop" | Risiko | Kompleksitas |
|---|---|---|---|
| A: CLI `frtrol approve/deny` via admin loopback API | Penuh, auditable, SSH-friendly | Tanpa GUI | Rendah |
| B: TUI interaktif full-screen | Nyaman tapi rawa scope (Rule 1) | Over-engineering untuk v0.1 | Sedang |
| C: Approve via chat/pesan | Praktis tapi memperluas attack surface ke channel chat | Channel baru = trust boundary baru | Tinggi |

## 4. Recommendation
**A.** Daemon mencetak setiap request baru ke konsol (id, agent, scope, durasi, reason). Owner memutuskan: `frtrol list` → `frtrol approve <id>` / `frtrol deny <id> --reason "..."`. Semua keputusan lewat admin plane loopback (ADR-0004) dan masuk audit. Default durasi = yang diminta agent (sudah divalidasi policy ADR-0008); `--hours` bisa memangkas durasi hanya ke bawah dari yang diminta.

## 5. Security analysis
Agent tidak punya jalur ke admin plane (loopback + admin token file 0600). Invarian 1 ditegakkan: request PENDING tidak memberi satu byte akses pun. Invarian 8: approve/deny/revoke semua tercatat (siapa: owner; kapan; apa). Keputusan yang salah ketik tidak mudah terjadi (id unik pendek, output jelas).

## 6. How we will verify it
e2e: request pending → exec ditolak (belum ada session) → approve → exec jalan → deny di request lain → tidak ada session yang lahir; audit berisi baris approve & deny.

## 7. Consequences
Makhluk yang approval-nya dijatuhkan = manusia via SSH/terminal. Desktop notifikasi (best-effort `notify-send`) dan web console = v0.2.
