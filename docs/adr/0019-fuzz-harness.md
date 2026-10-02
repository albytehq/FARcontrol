# ADR-0019: Adversarial-input fuzzing v0.5 (spec §75)

Date: 2026-10-02
Status: accepted

## Context

Spec §75: the protocol parser must be fuzz-tested with invalid JSON,
oversized strings, invalid enums, missing fields, duplicated fields, invalid
UTF-8, extreme numeric values, deeply nested payloads, truncated frames —
"malformed remote input must not crash FARcontrol."

## Decision

**In-process black-box fuzzing of the REAL router** (not a mock): the agent
router is now built by `build_agent_router()` and the harness drives it via
`tower::ServiceExt::oneshot` with **validly HMAC-signed** requests — so the
corpus reaches parsers and handlers, not just the auth gate.

Three tests (run on every `cargo test`):
1. `deterministic_corpus_never_crashes` — every §75 class × every JSON
   endpoint (242 combinations) + raw 10 MiB body + garbage auth headers.
   Acceptance: response always <500, always JSON envelope for 4xx, and a
   valid ping still succeeds afterwards.
2. `seeded_random_fuzz_2000_requests` — seeded `StdRng` (reproducible):
   mutated-valid-JSON / raw noise / brace floods / null fields against all
   endpoints. Same acceptance.
3. `concurrent_chaos_no_race_panics` — 50 tasks × 40 random bodies at once
   (shakes the rate-limiter/nonce/mutex interleavings).

Network-level chaos also runs in e2e §21 (garbage + binary + 10 MiB over
real TLS; daemon must survive and recover from the rate-limit lockout).

**Coverage-guided fuzzing (cargo-fuzz/libFuzzer) is deferred** — it needs
nightly + a separate fuzz-target crate + long runs. What we have is
deterministic + seeded-random black-box fuzz executed on every build, which
satisfies the spec's stated goal. Honest label, no overclaim.

## Found & fixed during this build (the harness paid for itself)

- **Bug:** bodies over axum's 2 MiB default limit were rejected with a
  PLAIN-TEXT error ("Failed to buffer the request body: length limit
  exceeded") — unparseable for machine clients.
  **Fix:** `body_limit_json` middleware rewrites 413 responses into the
  standard JSON error envelope (`payload_too_large`). Verified in-process by
  the corpus AND on the wire (e2e §21: 10 MiB → 413 + JSON body).

## Mutation evidence

- Injected `panic!` into `session_request` (empty body path) → corpus test
  FAILED immediately. Restored → green. The harness detects panics, i.e. it
  is load-bearing.

## Consequences

- +1 dev-dependency (tower/util — already in the graph via axum).
- Router construction split into `build_agent_router`/`build_admin_router`
  (no behavior change; `run()` uses the same builders).
