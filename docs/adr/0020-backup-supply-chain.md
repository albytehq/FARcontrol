# ADR-0020: Backup/restore + supply-chain hardening v0.6 (§72/§76/§103)

Date: 2026-10-02
Status: accepted

## Context

Spec §72 (disaster recovery: backup, key rotation, restore), §76 (dependency
security: lockfiles, vulnerability scanning, SBOM, secret scanning, static
analysis), §103 production readiness ("Backup/restore tested"), DB-03
(upgrade: validate compat → preserve identity/creds → migrate → restart),
§79 (a failed migration must not leave a partially upgraded state).

## Decision

**Backup — server-side, through the admin plane** (`POST /admin/backup`):
1. `PRAGMA wal_checkpoint(TRUNCATE)` makes state.db self-contained;
2. `tar -czf -` via FIXED argv (§77: no shell, no user input) packs
   state.db, config.toml, agent-token, admin-token, audit.jsonl (+cert/key
   when TLS on);
3. bytes stream to the CLI over loopback+TLS; the CLI writes the archive
   mode 0600 (it contains every secret).

ADR-0006 ("CLI never opens the DB") is preserved: the daemon owns its files
while running.

**Restore — offline, fail-safe, path-traversal-proof:**
1. archive FORMAT validated first (`tar -tzf`), then an ENTRY ALLOWLIST
   (only the 9 known state file names — no paths, no `..`, no dirs);
2. daemon must be DOWN (checked via admin ping; running → refuse);
3. extract to a sibling temp dir, then VERIFY by opening state.db —
   `open_db` runs migrations, so a v-old backup upgrades on restore
   (DB-03/§79 live test); garbage DB → reject, live dir untouched;
4. swap: live → `*.bak-<ts>` (never destroyed), tmp → live;
5. offline marker `restored_at` written directly (documented ADR-0006
   exception: owner-driven recovery, daemon down).

**Supply chain (§76), all in the verification report:**
- `cargo audit` — real RustSec scan of Cargo.lock (221 crates).
- `scripts/sbom.sh` — SPDX-2.2 SBOM from `cargo metadata` (offline,
  lockfile-driven; 220 dep entries).
- `scripts/secret-scan.sh` — token-shaped blob grep over src/scripts/docs.
- `cargo clippy --release` — 0 warnings (dead fields removed, idioms fixed).
- Checksums manifest (SHA256SUMS) at release packaging time.
- cargo-audit installed from crates.io (network available this session).

## DB-03 evidence (unit, state.rs)

`old_db_upgrades_in_place_preserving_data`: a simulated v0.1 DB upgrades to
schema 2 on open, data preserved, migrations recorded once (idempotent).
`garbage_db_fails_closed`: a non-sqlite file is rejected, not "repaired".

## Evidence

e2e §22 (10 checks): backup from running daemon (0600, non-empty), restore
with .bak preservation, no re-init on restart (identity survives), agent
token still authenticates, audit history intact, restore refuses while
daemon runs, garbage archive rejected.
Verification report: clippy 0, audit 0 vulns (1 unmaintained-info warning:
`serial`, transitive of portable-pty), secret-scan CLEAN, SBOM written,
56 unit + 112 e2e ALL GREEN.
