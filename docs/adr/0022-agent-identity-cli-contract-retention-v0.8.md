# ADR-0022 — Agent identity catalog, CLI contract, protocol version, audit retention

- **Status:** ACCEPTED (owner instruction 2026-10-02: "selesaikan project farcontrol sampai versi 1.0.0"; identity/catalog delegated at Gate 0: "sisanya rekomendasi")
- **Context:** v0.7 ships the full self-hosted slice but leaves four spec surfaces open: agent identity catalog (spec §9.2–9.5, §11, §81 / AG-01..03), CLI contract (§45 `--json`, §66 exit codes 0–7 / CL-02, CL-03), protocol version negotiation (§44 / AU-06), and audit retention (§72, App D #10 / AD-08).
- **Decision:**
  1. **Catalog is embedded data, not code.** A JSON document (spec §9.2–9.4 initial catalog: `z_ai` ×4 GLM, `qwen` ×5) is parsed at startup and drives all validation (`src/catalog.rs`). No runtime override file — no REQ asks for one (Rule 1 delete test).
  2. **Identity is optional, declaration-only, both-or-none.** `/v1/session/request` accepts `provider` + `model` (spec §11 `agent` object). Present → both required, exact slug match against the catalog, else `400 invalid_agent_identity`. Absent → request still works (v0.7 agents unaffected). Identity grants **no authority** and the web UI labels it "declared — not verified" (AG-03, spec §9.2 note: no implied vendor verification).
  3. **One enforcement point.** Validation happens server-side only (S4); the CLI merely forwards optional `FAR_AGENT_PROVIDER`/`FAR_AGENT_MODEL` env vars. No client-side duplicate catalog.
  4. **Exit codes 0–7 (§66):** shared `exit_for()` maps wire error codes → `0 success · 1 generic · 2 usage/invalid-request · 3 auth · 4 authorization denied · 5 timeout · 6 unavailable (incl. connection refused, rate-limited) · 7 conflict/state race`. Applied to both agent and owner CLI paths.
  5. **`--json` (§45):** `frtrol status --json` and `frtrol list --json` emit the raw JSON payload unchanged.
  6. **Protocol version (§44):** agent plane reads `X-Far-Proto`. Absent → treated as `1` (backward compatible, documented). Present and ≠ `1` → `422 unsupported_proto` (bad-request family convention). No negotiation beyond v1 exists yet — rejecting unknown versions is the fail-closed form of "negotiate".
  7. **Audit retention (AD-08):** optional `[audit] max_events = N` in config.toml. Default **absent = keep forever** (never destroy evidence unless the owner opts in). When set, after every append the oldest rows are deleted beyond N and `audit.jsonl` is **re-chained from a fresh genesis** whose first event is `audit.trimmed` recording `{removed, retained, prior_head}` — the retained events stay tamper-evident, the cut is itself audited, and `frtrol doctor` chain verification stays green. Trim runs only inside the state lock; the file is rewritten atomically (write `.new` → rename).
- **Alternatives rejected:**
  - *Runtime catalog override file* — no REQ; extra config surface = attack surface (Rule 1).
  - *Client-side catalog validation* — duplicates the enforcement point; a forged client skips it anyway.
  - *Retention trim that keeps the old chain prefix* — a chain whose head references deleted lines cannot be verified; re-chaining with an `audit.trimmed` genesis is verifiable and honest about the cut.
  - *Rejecting requests without a version header* — breaks every 0.x client for zero security gain (HMAC + TLS already gate the plane).
- **Consequences:** DB migration 3 (agent identity columns + retention meta). Wire additions are backward-compatible (all optional). Retention destroys old audit rows by design when the owner opts in — the `audit.trimmed` event plus prior_head hash preserves forensic traceability of the cut.
- **Affects REQ:** AG-01, AG-02, AG-03, UI-04, CL-02, CL-03, AU-06, AD-08, ST-02 (banner OS/arch).
- **Reversal cost:** low–medium (additive wire fields; retention is opt-in).
