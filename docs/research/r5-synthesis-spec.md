# R5 — Synthesis: FARcontrol 1.1.0 Design Spec (CLI + Console)

> Research pass 5/5 · Mission 1.1.0 · Synthesizes R1–R4 into buildable specs.
> This file is the contract ADR-0025/0026/0027 implement against.

## A. CLI design language ("gh-style")

### A.1 Status glyphs (colorblind-safe: shape + color + word)

| State | Glyph | Color | Used for |
|---|---|---|---|
| ok/active | `●` | green | active session, device active, doctor pass |
| warn | `◐` | amber | expiring <1h, backoff engaged, strikes>0 |
| dead | `○` | dim | expired/pending-quiet |
| revoked/err | `●` | red | revoked, denied, doctor fail |
| pending | `◐` | cyan | waiting request |

### A.2 Command → output contracts (pretty / --json schema)

```
frtrol status
  FARcontrol 1.1.0 — up 3h 12m (pid 1234)
  ● daemon healthy        https://127.0.0.1:7789 (admin, loopback)
  ● agent plane listening https://0.0.0.0:7788   (HMAC + TLS)
  1 pending request · 1 active session · 3 devices

  Pending requests
  ID           AGENT        SCOPE          ASKED      REASON
  req_ab12cd   myagent      terminal_only  4m ago     fix the nginx
  tip: frtrol approve req_ab12cd [hours]

  Active sessions
  ID           AGENT        SCOPE          LEFT       DEVICE
  ses_ef34gh   myagent      terminal_only  4h 51m     FAR-7K2M-QX94
  tip: frtrol revoke ses_ef34gh kills access now
  --json: {"version":"1.1.0","uptime_secs":…,"pending":[…],"sessions":[…]}
```

```
frtrol device add <name>
  ✓ device created — FAR-7K2M-QX94 "office-laptop"
  PASSWORD (shown once, store it now):
    harbor-tiger-42-blue-quantum
  Agent needs ONLY: this device ID + password.
  frtrol agent login FAR-7K2M-QX94   (password prompted)
  --json: {"device_id":"FAR-7K2M-QX94","password":"…","name":"…"}
```

```
frtrol device list
  ID             NAME           STATUS  LAST SEEN   SESSIONS  STRIKES
  FAR-7K2M-QX94  office-laptop  ●       2m ago      1         0
  FAR-LEGACY-1   legacy         ○       never       0         0   [key-only]
```

```
frtrol audit | frtrol doctor | approve/deny/revoke/panic → receipt lines:
  ✓ approved req_ab12cd → ses_cd34ef (5h, terminal_only, device FAR-7K2M-QX94)
  ✗ revoked  ses_ef34gh — access died, 2 terminals killed
```

### A.3 Agent side (unchanged syntax + new login)

```
frtrol agent login FAR-7K2M-QX94            # password hidden-prompt, or
FARCONTROL_PASSWORD=… frtrol agent login …   # script/AI mode
  first connect: shows cert fingerprint → pins (TOFU), then logs in
  optional strict: --expect-fp SHA256:abcd…
frtrol agent request myagent terminal_only 5 fix the nginx
  → 202 pending req_ab12cd (approve on the owner side)
  → 201 session ses_… (auto after approval poll? NO — stays: agent status <id>)
```

### A.4 Rules

- `--json` global: owner commands + `agent ping/status/request/login`.
  Machine JSON only, no ANSI, nonzero exit on error, error = existing envelope.
- exec/read/term output = byte passthrough (never tabled). `--raw` kept.
- Not a TTY or NO_COLOR → ASCII tables, no color. Glyphs always shown (shape-carried).
- Tables max width 100 cols; middle-truncate long reason/message (full in --json).

## B. Web console v2 ("localhost console")

Single HTML file, vanilla JS, zero external assets, textContent-only rendering,
X-Far-Ui CSRF + SameSite=Strict cookie + login backoff — all preserved (ADR-0017).

### B.1 Design tokens

```
bg #0b0e14 · panel #11151f · panel2 #161b27 · border #232a3a
text #e6e9f0 · dim #8b93a7 · accent #4f8cff (blue) · ok #34d399 ·
warn #fbbf24 · danger #f87171 · mono: ui-monospace, ids/tokens
radius 10px · spacing 8/16/24 · max-width 1200px content
```

### B.2 Layout

- Left sidebar (220px): logo "FARCONTROL", nav: Dashboard, Sessions, Devices,
  Audit, Danger. Bottom: version + doctor chip.
- Top of content: page title + subtitle + (contextual action button).
- Polling 3s on open pages; optimistic updates on actions with rollback on error.

### B.3 Pages

1. **Dashboard** — 4 KPI cards (pending / active sessions / devices / audit 24h),
   "Pending requests" list w/ approve (duration dropdown 5/8/12/24/48/72h) + deny,
   "Active sessions" list w/ revoke, recent audit (8 rows).
2. **Sessions** — full table: id, agent, scope badge, device, remaining (live),
   expires_at; revoke buttons; empty state.
3. **Devices** — cards: ID (mono, copy), name, status dot, last seen, strikes,
   active sessions count; actions: lock/unlock, rotate password (shows once in
   modal w/ copy), remove (confirm). "Add device" → name input → modal shows
   ID + PASSWORD once with copy buttons + fingerprint line.
4. **Audit** — table (time, actor, action, level chip, device, message), search
   input, level filter, hash-chain status chip (verified/tampered), last-100.
5. **Danger** — big red PANIC card (modal confirm: "revoke everything?"),
   rotate-all-device-keys card.

### B.4 Component inventory (DOM-built, no HTML strings)

card(), kpiCard(), table(), row(), badge(scope), dot(status), modal(),
copyButton(), durationSelect(), toast(). All set via textContent/className
(inline on* handlers never carry interpolated strings).

## C. Non-goals (kept honest)

- No websocket/SSE (polling only), no light theme toggle, no i18n layer,
  no external font/CDN, no web UI login rate-limit page (server enforces),
  no agent-side device listing (agent is single-device by design).
