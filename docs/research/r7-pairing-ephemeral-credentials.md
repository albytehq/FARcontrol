# R7 — Ephemeral Credentials & Pairing UX (session password model)

> Research pass 7/15 · Mission 1.2.0 · Sources: BLE Secure Simple Pairing numeric
> comparison/passkey literature (r7a: cs.uml.edu, ezurio.com, silabs community,
> security.stackexchange), OAuth 2.0 Device Flow analyses (r7b: okta.com,
> guptadeepak.com device-flow attack wave, levelup.gitconnected), v1.1 baseline
> (src/cli_admin.rs device add, src/agent_client.rs login observed).
> Raw: raw/r7a.json, raw/r7b.json

## What pairing research says

1. **Bluetooth numeric comparison**: a short random code shown on both devices,
   confirmed by a human, is MITM-resistant ONLY when the confirmation is
   interactive — "passkey pairing does not make much sense from a security point
   of view if it's not done interactively by the user" (r7a, github BLE spec
   notes). Lesson: short human-verified codes work; unattended ones don't.
2. **OAuth device flow** (r7b): `user_code` + `verification_url`, short-lived
   (minutes), human-typeable charset, then a stronger token is issued over the
   authenticated channel. FARcontrol's v1.1 `device add` already follows this
   shape: print once, exchange over TLS+TOFU-pinned channel.
3. **Device-flow phishing wave 2024–25** (r7b, guptadeepak.com — ShinyHunters
   breached Google/Qantas/LVMH users via device flow): codes alone are phishable.
   Defense = channel binding (the code only works on the real endpoint, attempts
   are visible to the owner) + short expiry. FARcontrol advantage: session
   password only unlocks the CURRENT session on the owner's own daemon — a
   phished password dies with the session, and login attempts are audited
   (v1.1 already audits auth.*).
4. **Entropy split** (spec §7.2, v1.1): Device ID FAR-XXXX-XXXX ≈ 40 bits — an
   identifier, never a secret. Session Password must carry the entropy:
   v1.1's diceware-style (`harbor-tiger-42-blue-quantum`, ~4 chars/word) is both
   typeable by humans and safe for chat-paste to an AI operator. Keep the format;
   per-session generation already satisfies "never a static machine secret".
5. **Entry UX** (v1.1 observed, keep): hidden prompt by default, env var
   (`FARCONTROL_PASSWORD`) for script/AI mode, NEVER a CLI flag (shell history +
   process listing leak, spec §29). v1.2 renames the env to match the session
   model (`FARCONTROL_SESSION_PASSWORD`) with the old one accepted during the
   migration window.

## FARcontrol v1.2 adoption decisions

- Session Password = diceware-style, generated per `frtrol start`, valid only for
  that session, stored only as an Argon2id verifier (reuse v1.1 password path).
- Device ID stays stable (spec §4 of master prompt); `frtrol agent` prompts for
  exactly two things: Device ID, Session Password.
- Show "this password dies when the session ends" on the start panel (r6).
- Failed logins keep feeding the backoff window + audit (SE-09, v1.1 behavior) —
  this is the anti-phish visibility the device-flow attackers exploited others
  for.
- Admin/Web token = separate session-bound credential (master prompt §10), not
  the same as the agent password.
