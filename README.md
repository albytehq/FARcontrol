# FARcontrol

**Let an AI agent work on your machine — without ever handing it the keys.**

FARcontrol is a small, self-hosted control plane that sits between you and an external AI
agent. The agent can ask for access, you approve it, it works — and the access **dies on a
timer** (5 to 72 hours), whether anyone remembers to clean up or not. You can kill it in
one keystroke. Everything it does is written down.

> The core idea: **authentication is not authorization.** An agent that knows your
> password has proven *who it is*. It still hasn't proven that *you said it could do
> anything*. FARcontrol is the thing that makes the second half explicit.

- One static binary, ~8 MB, starts in under 150 ms, ~10 MB of RAM
- Linux (x86_64), no cloud account, no tunnel service, no telemetry
- Rust, ~10K lines, 33 ADRs, 15 research notes, 104 unit tests, **262 end-to-end checks** — see
  [Why you can trust it](#why-you-can-trust-it)

---

## The 60-second version

```
you     frtrol start                          ← mints the session: device id + session password
you     (hand those two lines to the agent's operator)
agent   frtrol agent                          ← connects with exactly those two — nothing else
agent   frtrol agent request myai terminal_only 12 fix the nginx config
you     frtrol approve req_7KJyfWu39pCwW...    ← you decide, for how long
agent   frtrol agent exec ses_... systemctl status nginx
you     frtrol stop                           ← session over: every credential it printed is dead
```

Three parties are involved: an agent that wants to work, you at the machine, and a
5-minute window in which your decision is required. Miss the window and the request
evaporates. No approval, no session, no access — that simple.

The agent's entire identity is a **device id + session password** — two lines `frtrol
start` prints (once). Connecting exchanges the password for this run's session key,
pins the daemon's certificate SSH-style (TOFU fingerprint), and leaves a small background
runtime behind — close the terminal, the agent stays connected. **Every credential dies
when the owner's session ends**: a restart or `frtrol stop` rotates the password, the key
*and* the admin token; old ones never silently regain access. Mid-session hygiene?
`frtrol rotate` re-mints the password + admin token without touching connected agents.
Suspicious activity? `frtrol panic` kills everything at once.

`frtrol start` prints the whole story — the session box (keep it secret, it *is* the
access) plus, with `--verbose`, the operator detail including the certificate fingerprint
your agents can verify out-of-band:

```
FARcontrol 1.2.0 — session started  (first run)
  device id        : FAR-7K2M-QX94
  session password : harbor-tiger-42-blue-quantum-mango
  web console      : https://127.0.0.1:7789/   (login: the token on the next line)
  admin token      : b3f1c9d2e8a04f6db9c35e7a2f1d8b06c4e9f7a3

  hand those two lines to your AI agent's operator, then on the
  agent machine run:   frtrol agent

  everything above dies when this process stops (Ctrl-C, or: frtrol stop).
```

---

## Quickstart (owner side)

```bash
# from a release binary — or see "Install" below
frtrol start
```

That's it. First run auto-initializes everything — config, SQLite state, TLS certificate,
the stable device id — and prints the **session box**: the device id, the session password,
the web-console URL and the admin token. That box is the whole onboarding: the agent
gets the first two lines, you keep the rest. (Upgrading from 1.1 or 1.0? The old registry
is migrated at first start — legacy devices are locked, keys rotated, grants revoked;
agents simply reconnect with the new session password. See CHANGELOG.)

From then on, your entire side of the conversation:

| You run | What happens |
|---|---|
| `frtrol status` | The session: device id, uptime, **live agents** (heartbeat map), pending/active counts |
| `frtrol list` | Pending requests + live sessions — gh-style tables, live countdowns |
| `frtrol approve <req-id>` | **Grants access.** You can shorten: `--hours 2` (never extend) |
| `frtrol deny <req-id>` | Refuses. No session is ever created. |
| `frtrol revoke <ses-id>` | Kills access *now* — the next request fails |
| `frtrol rotate` | Re-mints the session password + admin token (shown once) — connected agents keep working |
| `frtrol stop` | **Session over.** Graceful shutdown — every credential from this run is dead |
| `frtrol fingerprint` | The daemon cert fingerprint (compare with the agent's TOFU pin) |
| `frtrol panic [reason]` | **Emergency stop:** every session revoked, terminals killed, pending expired, **password + key + admin token rotated** |
| `frtrol doctor` | Health checks: DB, audit chain, certs, keyring, clock — exit 0 = all green |
| `frtrol audit` | The full security trail, metadata only |
| `frtrol backup / frtrol restore` | Full state, tar.gz, 0600, restore refuses to run live |
| `frtrol` | Forgot everything? Bare `frtrol` prints a cheat sheet |

Every command also takes `--json` for machine-readable output (stable schema, no
styling — made for scripts and AI agents). Typing `frtrol` with no arguments prints the
quick guide. Commands are positional — no `--flags` gymnastics.

## Quickstart (agent side — built for an AI)

The agent CLI is deliberately boring, so an LLM can drive it blind:

```bash
frtrol agent                                 # connect: asks device id + session password (env or prompt)
frtrol agent request myai full_access 12 fix the nginx config   # ask (positional)
frtrol agent status                          # runtime state: connected? reconnecting? expired?
frtrol agent status req_7KJy...              # poll a request / session (auto-detects)
frtrol agent exec ses_7KJy... ls -la        # run a command
frtrol agent term ses_7KJy... bash          # interactive terminal
frtrol agent read  ses_7KJy... /var/log/nginx/error.log          # full_access only
frtrol agent write ses_7KJy... /tmp/notes.txt "hello"            # or pipe stdin
frtrol agent ls / ps / kill / app / shot / type ...              # full_access adapters
frtrol agent revoke ses_7KJy...             # agents can always give up access
frtrol agent stop                            # stop the background runtime + clear credentials
```

Connecting is the only onboarding step — and it leaves a **background runtime** behind
(own process group, its own log): close the terminal, log out, the agent keeps its
connection, heartbeating every 15 s so the owner console shows it alive. Network down?
The runtime retries with capped backoff and keeps the credentials. Session dead (owner
stopped, restarted, or panicked)? The runtime reaches a terminal state, **erases its own
credentials**, and exits — no lingering backdoor. First connect captures the daemon
certificate (SSH-style TOFU: the fingerprint is printed and pinned; add
`--expect-fp SHA256:...` to verify it strictly — a mismatch aborts *before* the password
is sent). The password comes from `FARCONTROL_SESSION_PASSWORD`, a `--password-file`, or
a hidden prompt — never a CLI flag (no shell-history leaks).

Credentials come from the environment (`FARCONTROL_SESSION_PASSWORD`,
`FARCONTROL_DEVICE`, `--password-file`), so it works in CI and headless agents. Every
response is **one line of JSON**; every error is `{"error":{"code":"..."}}` with a
*stable* code the agent can branch on (`scope_denied`, `session_expired`,
`rate_limited`, `invalid_credentials`, …). Exit codes are the stable 0–7 contract:

```
0 ok · 2 bad usage · 3 auth failed · 4 not allowed · 5 timeout · 6 unavailable · 7 conflict
```

Or skip the CLI and speak raw HTTPS (HMAC-SHA256 request signing, spec in the README's
[API section](docs/adr/0007-agent-interface.md) and `frtrol agent ping` as a reference
client):

```python
# the whole protocol in ~10 lines: see README §API in docs/ or scripts/e2e.sh §3
requests.post(f"{url}/v1/exec", json=..., headers=signed_headers(token, body))
```

The agent never learns your password, never gets a shell it can keep, and never holds
anything that survives expiry.

---

## What an approved session can actually do

| Scope | Capabilities | Enforced by |
|---|---|---|
| `terminal_only` | one-shot commands, interactive PTY terminal | output capped 256 KiB, timeouts 30s/5min, destructive-command denylist |
| `full_access` | everything above + files under **your $HOME** (read/write/list), process list & kill (guarded), launch apps, screenshots/typing (if a display exists) | path-traversal guard, PID guards (never PID 1, never the daemon), scope gate on every request |

Desktop actions **fail closed** (`desktop_unavailable`) on headless machines — the scope
gate runs *before* the availability check, so a headless box never pretends to have a
desktop.

## The security model, in eight sentences

1. **No approval → no access.** Requests live 5 minutes, then evaporate.
2. **Expired → no access.** Checked lazily on every request and by a sweeper.
3. **Revoked → no access.** The very next request fails; the token isn't cached anywhere.
4. **Missing capability → denied.** `terminal_only` physically cannot touch files.
5. **Your secret ≠ a session token.** The session password authenticates; only *your*
   approval authorizes — and the password dies with the owner's session anyway.
6. **Identity ≠ authority.** The agent may *declare* "I'm GLM from Z.ai" — the UI labels
   it *"declared, not verified"* and nothing ever grants it extra rights.
7. **Network failure → closed.** Daemon down, DB broken, keyring unreadable, clock
   insane? Every one of those paths denies, never allows.
8. **Every security action is audited.** Tamper-evident hash chain in `audit.jsonl`,
   verified by `frtrol doctor`.

On top of that: both planes speak TLS (self-signed, pinned by the agent CLI — no
certificate authority involved), the admin plane **rejects foreign Host headers**
(DNS-rebinding guard, loopback names only), auth failures get **progressive lockout**
(10 strikes → 60 s, doubling to a 1-hour ceiling; hammering makes it worse, only a
*successful* auth resets it), and the session key can live in the **Linux kernel
keyring** — never written to disk at all:

```toml
# ~/.farcontrol/config.toml
[identity]
secret_store = "keyring"   # or "file" (default): 0600 file + SQLite meta

[policy]                    # the "standard package", tunable — stricter is fine
session_max_hours = 24
extra_denylist = ["steamroller"]

[audit]
max_events = 10000          # 0/absent = keep everything, forever
```

A bad config is a startup error (exit code 2, `config_invalid: ...`), not a Tuesday
surprise at 2 a.m.

---

## Remote access without a cloud

FARcontrol is self-hosted by conviction: your machine, your rules, no account, no relay
in someone else's datacenter. For remote agents, the boring tools are the right tools:

- **SSH tunnel:** `ssh -L 7788:127.0.0.1:7788 you@box`, point the agent at
  `https://127.0.0.1:7788`
- **WireGuard / Tailscale:** expose `--bind 0.0.0.0:7788` on the tunnel interface only
- The agent CLI pins the daemon's self-signed cert (TOFU), so the tunnel carries
  HMAC-authenticated, TLS-wrapped traffic — no extra CA, no cloudflared, no ngrok.

The **admin plane stays loopback-only, always.** The daemon refuses to bind it anywhere
else. Approvals and revocations never travel.

## The web console (optional, same security model)

`https://127.0.0.1:7789/` — login with the admin token (the login label tells you it's
the one `frtrol start` printed — it is per-session now). The v1.2 console is
**session-first**: the header always answers *this is the current session* — device id,
version, uptime, **live agent chips** fed by the runtime heartbeats (aria-live), and the
big red PANIC button stays in view. Tabs: Activity (pending requests, sessions,
approve/deny/revoke), Audit (searchable, hash-chain status chip), Advanced
(fingerprint, **rotate**, stop). It polls every 3 s while the tab is visible — no
websockets, no extra ports. Cookies are HttpOnly + SameSite=Strict, CSRF is a JS-only
header, the whole UI remains one dependency-free HTML file rendered via `textContent`
(no HTML string sinks to sanitize, no CDN, works fully offline). A restart logs you out
— fail closed.

---

## Why you can trust it

Because every claim above is backed by a machine check that runs in CI, and the things
that *aren't* covered are listed in [Limitations](#honest-limitations) instead of
hand-waved.

| Evidence | Where |
|---|---|
| **104 unit tests** (crypto vectors, Argon2, device ids, policy, state machine, auth, config, lockout math, session model) | `cargo test` |
| **262 end-to-end checks** — the full session lifecycle + agent connect + background runtime + reconnect/expiry + host allowlist + console v1.2 + v1.1 registry migration + TOFU + backoff + panic under load, both planes, kill/restart mid-flight, TLS, tamper, chaos fuzz, backup/restore | `scripts/e2e.sh` |
| **13 mutation checks** — we *broke* CSRF, the kill-guard, the fuzz panic-handler, the backoff escalation, config validation, the keyring probe, the device lock, the login backoff, the TOFU compare, the session model, **the Host-header guard, the password verify, and the v1.1 migration lock** on purpose, watched the suite go red, and reverted | `tracking/evidence/` |
| Fuzzing: the §75 corpus + 2,000 seeded-random requests + 50-way concurrent chaos against the *real* router, in-process, every `cargo test` run | ADR-0019 |
| Console v1.2: browser-driven login → session view → agent chips → Advanced (rotate/stop), zero console errors | `reports/verification-output.txt` |
| Supply chain: `cargo audit` (0 CVEs), SPDX SBOM, secret scan, clippy at 0 warnings | `scripts/sbom.sh`, `scripts/secret-scan.sh` |
| Design record: 33 ADRs + 15 research notes, one per decision, each accepted or rejected on the record | `docs/adr/`, `docs/research/` |
| Mission tracking: per-requirement status with evidence links — including the honest PARTIALs | `tracking/PROGRESS.md` |

The release artifacts ship with `SHA256SUMS` and a GPG detached signature; the public key
lives in the repo (`docs/RELEASE_KEY.asc`).

### The 1.2.0 verification wall (as of release day)

```
unit tests ......... 104 passed
smoke §50 DoD ..... 37 passed (session lifecycle end-to-end, by hand)
e2e checks ......... 262 passed, 0 failed      (39 sections, incl. v1.2 session model)
mutation checks .... 13 total (9 prior + session model / Host guard / password verify / migration lock)
browser console .... v1.2 flows verified (login, session header, agent chips, Advanced), zero JS errors
clippy ............. 0 warnings
cargo audit ........ 0 vulnerabilities (1 pre-existing allowed advisory)
secret scan ........ clean
```

## Honest limitations

- **Linux x86_64 only.** No Windows, no macOS. (ADR-0002)
- The **desktop adapter** works only where a real X display and tools exist; its
  on-display path was **not verifiable** in the headless build environment — it fails
  closed rather than pretending.
- The kernel-**keyring** secret store runs where the kernel implements it fully; on
  gVisor-style sandboxes (partial keyring) FARcontrol *refuses to start in keyring mode*
  rather than store something it can't read back. The default `file` mode works
  everywhere.
- Brute-force lockout and web-console sessions are **in-memory** — a daemon restart
  clears them (documented trade-off: an attacker shouldn't be able to poison persistent
  state, and you should always be able to log in after a restart).
- Exec is one-shot per call with timeout+output caps; the **in-flight** command isn't
  killed mid-byte by a revoke — it's bounded by its timeout, then the session is dead.
- No multi-device fan-out, no org mode, no TPM, no hosted control plane, no session
  recording. Those are explicitly out of scope (spec §101, D-042).
- Single logical session by design: one owner, one machine — but the session credential
  is deliberately shareable among several agents (Wi-Fi-password model); per-agent
  attribution stays at the audit layer and is labeled *declared, not verified*.

Full, unfiltered status per requirement: [`tracking/PROGRESS.md`](tracking/PROGRESS.md).

---

## Install

**From the release** (recommended):

```bash
curl -LO https://github.com/albytehq/FARcontrol/releases/download/v1.2.0/frtrol-linux-amd64
chmod +x frtrol-linux-amd64 && sudo mv frtrol-linux-amd64 /usr/local/bin/frtrol
# verify: check SHA256SUMS + SHA256SUMS.asc against docs/RELEASE_KEY.asc
```

**Debian/Ubuntu (.deb):**

```bash
sudo dpkg -i frtrol_1.2.0_amd64.deb
sudo systemctl enable --now frtrol@$(id -un)   # hardened unit included
```

**From source:**

```bash
git clone https://github.com/albytehq/FARcontrol && cd FARcontrol
cargo build --release           # Rust 1.75+, no system SQLite needed (bundled)
cargo test && bash scripts/e2e.sh   # the same 104+262 wall, on YOUR machine
```

Requirements: Linux x86_64, `tar` (for backup/restore). That's the list.

## Project layout

```
src/            the whole daemon + both CLIs, one crate, no workspace ceremony
docs/adr/       33 decision records — read these to understand WHY anything is the way it is
docs/           language comparison, incident-response runbook, release key
scripts/        e2e.sh (the verification wall), sbom.sh, secret-scan.sh, build-deb.sh
tracking/       PROGRESS.md (per-requirement status), DECISIONS.md, evidence reports
reports/        the last full verification output + SBOM
```

## Contributing & security

- PRs that want to be taken seriously run the wall: `cargo clippy --all-targets -- -D
  warnings && cargo test && bash scripts/e2e.sh`. Security-relevant changes need a
  mutation check (break it on purpose, show the suite going red). See
  [CONTRIBUTING.md](CONTRIBUTING.md).
- Found something that shouldn't be possible? [SECURITY.md](SECURITY.md) — private
  disclosure, fast response, and the incident runbook is already written
  ([docs/incident-response.md](docs/incident-response.md)).
- Design questions start in an ADR, not in a diff.

## License

MIT — see [LICENSE](LICENSE). One clause of honesty instead of legalese: this software
lets an AI act on a real machine. Read the security model before you point it at
anything you care about.

---

*FARcontrol is built with the discipline that "it runs" is not "it works": every claim
either has a check that fails loudly, or it's on the limitations list. If you find a
claim in either category that's wrong, that's a bug — the best kind to report.*
