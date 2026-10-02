# AGENTS.md — Start Here

You are building **FARcontrol** from zero. The owner's specification is the contract:
[`spec/FARcontrol.md`](spec/FARcontrol.md). This pack tells you how to build it
correctly and how to prove it is correct.

FARcontrol lets an AI operate a user's real computer. A mistake here is not a bug,
it is a security incident on someone's machine. Work accordingly.

---

## The 3 Absolute Rules (from the owner — they override everything else)

### 1. Don't over-engineer. Keep it simple.
> *"Jangan over-engineer. Yang simple."*

Build the smallest thing that satisfies the spec. If it is not required by the spec,
do not build it.

### 2. Done means verified done — and you must know WHY it works.
> *"Selesai berarti benar-benar sudah terverifikasi selesai. Bukan cuma 'ah ini jalan'.
> Yang wajib: 'ah jalan — kenapa jalan?' Wajib tahu kenapa."*

"It runs" is not done. Done = you have evidence, you can explain the mechanism,
and you tried to break it.

### 3. If you don't know, DO NOT assume. Ask.
> *"Kalau tidak tahu, jangan bikin asumsi. Ini hal yang paling kritis."*

This is the most critical rule. An unknown is a question for the owner, never a guess.

Full meaning, tests, and examples: [`discipline.md`](discipline.md) §1.

---

## Read order (do this before writing any code)

1. `discipline.md` — how to think. **Mandatory, in full.**
2. `spec/FARcontrol.md` — the contract. Read all of it, not just the digest.
3. `docs/01-spec-digest.md` — fast reference: binding vs. non-binding language, invariants, constants.
4. `docs/02-requirements.md` — every requirement with an ID, spec section, and how it is verified.
5. `docs/03-build-plan.md` — phases and exit criteria. Follow the order.
6. `docs/04-verification.md` — what counts as evidence.
7. `tracking/QUESTIONS.md` — open questions that block work. **Check before each phase.**
8. `tracking/DECISIONS.md` — spec-given defaults and recorded decisions.

## Session ritual (start of every session and every phase)

Re-read this file and the Done Gate (`discipline.md` §5) → read `tracking/PROGRESS.md`, `QUESTIONS.md`,
`DECISIONS.md` → run the full test suite from a clean state → fill the Task Brief. You may not remember
earlier sessions: everything that matters lives in the repo (`discipline.md` §12).

## Work loop (every task, no exceptions)

```
Pick next task from tracking/PROGRESS.md (respect phase order)
  → fill the Task Brief (discipline.md §2)          # know / infer / unknown
  → unknown that matters?  STOP → tracking/QUESTIONS.md → ask the owner
  → write the failing test first, from the spec     # "done" defined before code
  → PREDICT the result in writing                   # discipline.md §8.1
  → implement the smallest thing
  → verify + explain WHY + try to break it          # docs/04-verification.md
  → write evidence report (templates/evidence-report.md)
  → only then mark VERIFIED in tracking/PROGRESS.md
```

## Hard prohibitions (spec §2.2 and §39 — never build, never "temporarily")

- Hidden / background / covert access, covert startup installation, hidden persistence.
- Credential extraction, password scraping, keylogging.
- Privilege escalation or silent elevation; bypassing OS security controls.
- Any flag, env var, or build option that silently disables user approval (§77).
- Remote approval of a request by the AI itself (§62).
- Unattended permanent remote administration.

If a task seems to require one of these, stop and ask the owner. Do not work around it.

## Non-negotiable invariants (spec §102)

```
No user approval            = No remote access
Expired session             = No remote access
Revoked session             = No remote access
Missing capability          = Operation denied
Device secret               != session token
Agent model identity        != authorization
Network failure             = fail closed for authorization
Security-sensitive action   = auditable
```

Any change that weakens one of these is a security regression, even if every test passes.

## How to report

Short, factual, with evidence. Say VERIFIED, PARTIAL, or BLOCKED — never "should work".
List what you did **not** verify. Format: `templates/evidence-report.md`.
