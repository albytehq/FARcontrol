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
- Rust, ~7,300 lines, 25 ADRs, 78 unit tests, **172 end-to-end checks** — see
  [Why you can trust it](#why-you-can-trust-it)

---

## The 60-second version

```
you     frtrol start                          ← run it once, that's the whole setup
agent   frtrol agent request myai full_access 12 fix the nginx config
you     frtrol approve req_7KJyfWu39pCwW...    ← you decide, for how long
agent   frtrol agent exec ses_... systemctl status nginx
you     frtrol revoke ses_...                  ← or just... wait. it expires.
```

Three people are involved: an agent that wants to work, you at the machine, and a
5-minute window in which your decision is required. Miss the window and the request
evaporates. No approval, no session, no access — that simple.

When the daemon starts, it prints the agent token **once** and stores the rest locally:

```
[2026-10-02 09:30:12 UTC] FARcontrol 1.0.0 daemon ready | pid 12345
  data dir  : /home/you/.farcontrol
  os/arch   : linux / x86_64
  agent API : https://127.0.0.1:7788  (TLS, cert-pinned by the agent CLI)
  admin API : https://127.0.0.1:7789  (loopback only — approvals never touch the network)
  web UI    : https://127.0.0.1:7789/ui  (login = the admin token)
```

---

## Quickstart (owner side)

```bash
# from a release binary — or see "Install" below
frtrol start
```

That's it. First run auto-initializes everything: config, SQLite state, TLS certificate,
and two random 256-bit tokens — one for the agent, one for you. The agent token is shown
once and written to `~/.farcontrol/agent-token` (mode 0600). Hand it to your AI agent over
a secure channel; that token is its *identity*, nothing more.

From then on, your entire side of the conversation:

| You run | What happens |
|---|---|
| `frtrol status` | Is the daemon alive? Anything pending? |
| `frtrol list` | Pending requests + live sessions (with countdown) |
| `frtrol approve <req-id>` | **Grants access.** You can shorten: `--hours 2` (never extend) |
| `frtrol deny <req-id>` | Refuses. No session is ever created. |
| `frtrol revoke <ses-id>` | Kills access *now* — the next request fails |
| `frtrol rotate` | New agent token; the old one dies mid-flight |
| `frtrol panic [reason]` | **Emergency stop:** every session revoked, terminals killed, pending expired, token rotated |
| `frtrol doctor` | Health checks: DB, audit chain, certs, keyring, clock — exit 0 = all green |
| `frtrol audit` | The full security trail, metadata only |
| `frtrol backup / frtrol restore` | Full state, tar.gz, 0600, restore refuses to run live |
| `frtrol` | Forgot everything? Bare `frtrol` prints a 4-line cheat sheet |

Typing `frtrol` with no arguments prints the quick guide. Every command is positional —
no `--flags` gymnastics, no symbols to mistype.

## Quickstart (agent side — built for an AI)

The agent CLI is deliberately boring, so an LLM can drive it blind:

```bash
frtrol agent request myai full_access 12 fix the nginx config   # ask (positional)
frtrol agent status req_7KJy...                                  # poll (auto-detects req/ses)
frtrol agent exec ses_7KJy... ls -la                             # run a command
frtrol agent term ses_7KJy... bash                               # interactive terminal
frtrol agent read  ses_7KJy... /var/log/nginx/error.log          # full_access only
frtrol agent write ses_7KJy... /tmp/notes.txt "hello"            # or pipe stdin
frtrol agent ls / ps / kill / app / shot / type ...              # full_access adapters
frtrol agent revoke ses_7KJy...                                  # agents can always give up access
```

Credentials come from the environment (`FARCONTROL_TOKEN`, `FARCONTROL_URL`), so it works
in CI and headless agents. Every response is **one line of JSON**; every error is
`{"error":{"code":"..."}}` with a *stable* code the agent can branch on (`scope_denied`,
`session_expired`, `rate_limited`, …). Exit codes are the stable 0–7 contract:

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
5. **Your secret ≠ a session token.** The agent token authenticates; only *your* approval
   authorizes.
6. **Identity ≠ authority.** The agent may *declare* "I'm GLM from Z.ai" — the UI labels
   it *"declared, not verified"* and nothing ever grants it extra rights.
7. **Network failure → closed.** Daemon down, DB broken, keyring unreadable, clock
   insane? Every one of those paths denies, never allows.
8. **Every security action is audited.** Tamper-evident hash chain in `audit.jsonl`,
   verified by `frtrol doctor`.

On top of that: both planes speak TLS (self-signed, pinned by the agent CLI — no
certificate authority involved), auth failures get **progressive lockout** (10 strikes →
60 s, doubling to a 1-hour ceiling; hammering makes it worse, only a *successful* auth
resets it), and your agent token can live in the **Linux kernel keyring** — never written
to disk at all:

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

`https://127.0.0.1:7789/ui` — login with the admin token. Pending requests with duration
picker, live session cards (who / what / until), one-click revoke, the last 50 audit
events, and a big red PANIC button. Cookies are HttpOnly + SameSite=Strict, CSRF is a
JS-only header, the whole UI is one HTML file rendered via `textContent` (no HTML string
sinks to sanitize). A restart logs you out — fail closed.

---

## Why you can trust it

Because every claim above is backed by a machine check that runs in CI, and the things
that *aren't* covered are listed in [Limitations](#honest-limitations) instead of
hand-waved.

| Evidence | Where |
|---|---|
| 78 unit tests (crypto vectors, policy, state machine, auth, config, lockout math) | `cargo test` |
| **172 end-to-end checks** — the full lifecycle, both planes, kill/restart mid-flight, TLS, tamper, chaos fuzz, backup/restore, panic under load | `scripts/e2e.sh` |
| 6 mutation checks — we *broke* CSRF, the kill-guard, the fuzz panic-handler, the backoff escalation, config validation and the keyring probe on purpose, watched the suite go red, and reverted | `tracking/evidence/EVIDENCE-00{1,2}.md` |
| Fuzzing: the §75 corpus + 2,000 seeded-random requests + 50-way concurrent chaos against the *real* router, in-process, every `cargo test` run | ADR-0019 |
| Supply chain: `cargo audit` (0 CVEs), SPDX SBOM (220 crates), secret scan, clippy at 0 warnings | `scripts/sbom.sh`, `scripts/secret-scan.sh` |
| Design record: 25 ADRs, one per decision, each accepted or rejected on the record | `docs/adr/` |
| Mission tracking: per-requirement status with evidence links — including the honest PARTIALs | `tracking/PROGRESS.md` |

The release artifacts ship with `SHA256SUMS` and a GPG detached signature; the public key
lives in the repo (`docs/RELEASE_KEY.asc`).

### The 1.0.0 verification wall (as of release day)

```
unit tests ......... 78 passed
e2e checks ......... 172 passed, 0 failed      (32 sections, incl. stress-panic)
clippy ............. 0 warnings
cargo audit ........ 0 vulnerabilities
secret scan ........ clean
mutation checks .... 6/6 caught (test goes red when the control is broken)
SBOM ............... 220 crates (SPDX), offline-reproducible from Cargo.lock
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
- Single-user by design: one owner, one machine, one agent token at a time.

Full, unfiltered status per requirement: [`tracking/PROGRESS.md`](tracking/PROGRESS.md).

---

## Install

**From the release** (recommended):

```bash
curl -LO https://github.com/albytehq/FARcontrol/releases/download/v1.0.0/frtrol-linux-amd64
chmod +x frtrol-linux-amd64 && sudo mv frtrol-linux-amd64 /usr/local/bin/frtrol
# verify: check SHA256SUMS + SHA256SUMS.asc against docs/RELEASE_KEY.asc
```

**Debian/Ubuntu (.deb):**

```bash
sudo dpkg -i frtrol_1.0.0_amd64.deb
sudo systemctl enable --now frtrol@$(id -un)   # hardened unit included
```

**From source:**

```bash
git clone https://github.com/albytehq/FARcontrol && cd FARcontrol
cargo build --release           # Rust 1.75+, no system SQLite needed (bundled)
cargo test && bash scripts/e2e.sh   # the same 78+172 wall, on YOUR machine
```

Requirements: Linux x86_64, `tar` (for backup/restore). That's the list.

## Project layout

```
src/            the whole daemon + both CLIs, one crate, no workspace ceremony
docs/adr/       25 decision records — read these to understand WHY anything is the way it is
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
