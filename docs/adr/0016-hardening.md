# ADR-0016: Rate limiting, audit hash chain, policy config, env scrub, migrations

Date: 2026-10-02 · Status: ACCEPTED

## Decision
- **Rate limiting (SE-09)**: global sliding window of auth failures
  (10/60s prod, 6/2s test mode) → HTTP 429 `rate_limited`, fail closed.
  Global scope is honest for a single-tenant box (D-034).
- **Audit hash chain**: every audit.jsonl line carries prev+sha256 hash;
  `doctor` walks and verifies it; tampering/truncation turns doctor red.
- **Policy config**: optional `[policy]` in config.toml (ints/floats both
  accepted; extra_denylist only ADDS — never removes standard entries).
- **Env scrubbing**: exec + term children get PATH/HOME/LANG/TERM/SHELL only.
- **Migrations (DB-03)**: `migrations` table + ordered steps, schema_version=2.

## Consequences
Brute force is throttled, tamper is detectable, limits are owner-tunable,
children never inherit the daemon's env, upgrades are traceable.
