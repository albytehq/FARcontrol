# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |
| anything else | no (pre-1.0 internal milestones were never published) |

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Email the maintainer via GitHub's *Report a vulnerability* button on the
[Security tab](https://github.com/albytehq/FARcontrol/security), or open a private
security advisory. You will get an acknowledgement within 72 hours.

Include, if you can:

- what you found, and the exact version/commit
- reproduction steps (a failing curl command is worth a thousand words)
- your read of which of the 8 invariants it bends
- whether it is reachable remotely, loopback-only, or requires a compromised owner account

Please do not fuzz, stress, or attack machines you do not own or have permission to test.

## What we consider a security bug

FARcontrol's contract is eight invariants (see the README). Anything that breaks one is
a security bug, in particular:

1. Any path where a request is served without approval, past expiry, after revoke, or
   above its granted scope.
2. Any secret (agent token, admin token, session material, keyring payload) appearing in
   logs, audit rows, process arguments, error messages, or unintended files.
3. Any crash-recovery or fail-open behavior: network failure, DB corruption, unreadable
   keyring, or clock skew that ends in *allowing* instead of denying.
4. Any bypass of the loopback-only admin plane.
5. Anything that lets the brute-force lockout be poisoned into locking out the owner
   permanently, or letting the attacker recover faster than documented.

## Verifying a release

Every release ships `SHA256SUMS` and a GPG detached signature (`SHA256SUMS.asc`). The
signing public key is in the repo at `docs/RELEASE_KEY.asc`:

```bash
gpg --import docs/RELEASE_KEY.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS
```

The signing key used for the v1.0.0 artifacts was generated at release time. For maximum
rigor, treat the fingerprint published in the release notes as the trust anchor and
re-sign with your own key when distributing internally.

## Incident response (already written, already tested)

If FARcontrol itself is your incident: `docs/incident-response.md` is an 8-step runbook
(detect → contain → revoke → preserve → rotate → recover) with every step mapped to a
command that an e2e section has actually executed. The short version:

```bash
frtrol panic "reason"        # every session dead, terminals killed, token rotated
frtrol backup out.tar.gz     # preserve evidence AFTER containment (contains secrets, 0600)
frtrol doctor                # verify integrity (DB, audit chain, certs, keyring)
```
