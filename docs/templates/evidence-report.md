# Evidence Report — <REQ IDs, e.g. RQ-07, SE-03>

Save as `tracking/evidence/<REQ-IDs>-<short-title>.md`. Be honest. Short beats long.

**Verdict:** `VERIFIED` | `PARTIAL` | `BLOCKED (Q-xxx)`
**Date / commit:** <UTC date> / <git sha>
**OS / environment verified on:** <e.g. Windows 11 x64 — and say explicitly which OSes were NOT verified>

## 1. What this covers
<1–3 sentences. Which REQ IDs, which spec §§.>

## 2. Done criteria (written BEFORE the code)
<The tests / observable outcomes that define done. Paste or link the test names.>

## 3. How to reproduce (from a clean state)
```
<exact commands, starting from fresh checkout / empty data dir>
```

## 3b. Prediction (written BEFORE running)
<What you expected to observe. Then compare in §4 — say "matched" or describe the mismatch and what it taught you.>

## 4. Observed result
```
<real captured output — not a summary>
```

## 5. WHY it works  *(Rule 2 — mandatory)*
<The mechanism, in your own words. Not "the test passed". If you can't write this, it's not done.>

## 6. Failure signature + mutation check
- If it did NOT work I would see: <…>
- I broke it by: <what you changed> → <which test failed / what output appeared> → restored: <yes>

## 7. How I tried to break it
| Attack / edge case | Result |
|---|---|
| <malformed / oversized / replayed / concurrent / boundary / hostile> | <what happened> |

## 8. Invariants and secrets
- Invariants (§102) touched: <list> — still hold: <how you know>
- Canary secret check: <command> → <empty result>
- Authorization pipeline bypass possible? <no — why>

## 9. Assumptions
<"None." — or list each with its Q-id / D-id. An unresolved assumption means this is not VERIFIED.>

## 10. Not verified / known gaps
<Be explicit. What you did not test, on what OS, under what load, and why.>
