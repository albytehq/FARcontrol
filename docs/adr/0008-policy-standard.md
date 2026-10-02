# ADR-0008 — Policy: Paket Standart (Default Spec)

**Status:** ACCEPTED (by owner, 2026-10-02 — "policy limit paket standart")
**Related:** Q-010, spec §policy, invarian 4

## 1. Context
Owner memilih paket policy standart (default spec). Policy = batas keras yang ditegakkan daemon sebelum eksekusi apa pun.

## 2. Known / Inferred / Unknown
- KNOWN: spec mendefinisikan rentang grants 5h–72h; paket standart mengambil nilai tengah yang aman.
- INFERRED: nilai konkret berikut konsisten dengan spec dan cukup untuk pemakaian nyata.
- UNKNOWN: kebutuhan whitelist command per-agent → v0.2 (config policy file).

## 3. Options
| Option | Isi | Risiko | Kompleksitas |
|---|---|---|---|
| A: Nilai standart di kode (policy.rs) | Session 5–72h; exec timeout 30s (max 300s); output 256 KB; file 1 MB; root file = $HOME; denylist perintah destruktif; max 10 pending | Kurang fleksibel | Rendah |
| B: Policy engine konfigurasi penuh | Fleksibel | Over-engineering (Rule 1) | Tinggi |

## 4. Recommendation
**A.** Konstanta di `src/policy.rs`:
- Session: `min 5h, max 72h` (request divalidasi di sini).
- Exec: timeout default 30.000 ms, max 300.000 ms; output stdout+stderr dibatasi 262.144 byte (truncated + flag).
- File (full_access): hanya bawah `$HOME`; read/write max 1 MB; list max 2.048 entri.
- Denylist substring perintah destruktif sistem: `mkfs`, `dd if=/dev/`, `dd of=/dev/`, `wipefs`, `shutdown`, `reboot`, `halt`, `poweroff`, `init 0`, `init 6`, `systemctl reboot`, `systemctl poweroff`, `rm -rf /`, `rm -fr /`, `rm -rf /*`, `> /dev/sd`, `:(){` (fork bomb), `kill -9 1`.
- Pending request: max 10 per agent.
- Test hook: `FARCONTROL_TEST_MODE=1` mengizinkan durasi sub-menit HANYA untuk automated test (tidak aktif di produksi).

## 5. Security analysis
Invarian 4 (missing capability = denied) ditegakkan dua lapis: scope session (terminal vs full) dan policy angka (timeout/output/denylist). Denylist konservatif: `rm -rf /` juga menangkap `rm -rf /home/x` — false-positive lebih baik daripada false-negative untuk v0.1 (didokumentasikan). Fail-closed: semua cek sebelum spawn.

## 6. How we will verify it
Unit test: durasi di-clamp; denylist match/miss; truncation tepat 256 KB. e2e: `sleep 2` dengan timeout 300 ms → status timeout; command denylist → 403 `policy_denied` + audit.

## 7. Consequences
Policy tidak bisa diubah user di v0.1 (kode = kebenaran; ubah = rebuild). Config policy file = kandidat awal v0.2.
