# Incident Response Runbook — FARcontrol

Spec §73 / SC-08. The 8-step procedure, mapped to concrete commands you
already have. **You are the control plane owner: everything below runs on
the target machine.**

> Golden rule: FARcontrol is fail-closed by design. When in doubt, PANIC
> first, investigate second — revoking is instant and recoverable; not
> revoking is not.

## 0. What an incident looks like

Signals available to you (all tested):

| Signal | Where |
|---|---|
| auth.rejected events (brute force) | `frtrol audit` / web console audit feed |
| sessions you don't recognize | `frtrol list` / dashboard |
| audit chain tamper alarm | `frtrol doctor` → `audit_chain` check |
| rate-limit lockouts | daemon log + `farcontrol_auth_failures_window` metric |
| garbage/abnormal agent behavior | `exec.run` / `file.*` / `process.kill` audit trail |

## 1. Detect

```
frtrol list          # who has access RIGHT NOW?
frtrol audit         # what did they do? (actor, action, subject)
frtrol doctor        # is the audit chain intact? db healthy?
curl -k https://127.0.0.1:7789/admin/metrics -H "Authorization: Bearer $(cat ~/.farcontrol/admin-token)"
```

## 2. Contain

```
frtrol panic "incident: <one-line reason>"
```

One command: every session revoked, every pending request expired, every
terminal killed, the agent token rotated. Access is now mathematically
impossible. (Same button exists in the web console — red, bottom right.)

Or surgical containment of a single session:

```
frtrol revoke ses_xxxxx "contained: suspected compromise"
```

## 3. Revoke affected credentials/sessions

Already done by step 2 — but ALSO rotate the admin-side secret if the
console itself may be exposed (admin-token file was read):

```
frtrol rotate         # rotates the AGENT token (prints the new one once)
# admin token: regenerate via a fresh init after restoring, or replace the
# admin-token file + DB meta row — see docs/adr/0020-backup-supply-chain.md
```

## 4. Preserve audit evidence

Before anything else touches the data dir:

```
frtrol backup /secure-place/evidence-$(date +%s).tar.gz   # 0600, all state
cp -a ~/.farcontrol/audit.jsonl /secure-place/            # tamper-evident chain
```

The audit chain is hash-linked (`prev` + `sha256` per line) — `frtrol
doctor` verifies it. Keep the original daemon log too (`journalctl -u
frtrol` under systemd).

## 5. Rotate secrets

- Agent token: `frtrol rotate` (done in step 2/3).
- TLS cert: delete `~/.farcontrol/cert.pem` + `key.pem` and restart — a
  fresh self-signed pair is generated (agents must re-pin; send them the
  new cert.pem).

## 6. Patch

Update the binary, then verify:

```
# replace the binary, then:
frtrol doctor         # schema, tokens, cert, chain — ALL GREEN required
```

DB migrations run automatically on start (traceable in the `migrations`
table). A failed migration never leaves partial state (§79, unit-tested).

## 7. Validate

```
frtrol doctor                       # every check green
frtrol agent ping  (from the agent box, with the NEW token)
bash scripts/e2e.sh   (from source, optional but thorough)
```

## 8. Restore normal service

```
frtrol start                       # back online, state intact
frtrol list                        # confirm zero unexpected sessions
```

Re-issue access only per request → approval, as always. Nothing survives an
incident silently: old sessions are dead, the old token is dead, everything
that ever happened is in the audit trail.

## Post-incident

- Write a one-page timeline from `frtrol audit` output.
- If the agent misbehaved: do not re-approve until its request reason
  includes a fix; the request TTL (5 min default) forces fresh intent.
- Root-cause: `exec.run` audit rows contain the exact command lines that ran.

## Why this runbook is trustworthy

Every command above is covered by automated verification: panic (e2e §18,
§19-k), revoke (§5, §10, §20), backup/restore (§22), audit chain tamper
detection (§14 doctor), doctor (§15), crash recovery (§23), rate-limit
lockout (§10). This document is tested, not aspirational.
