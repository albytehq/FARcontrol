# ADR-0027 — v1.1.0: Web console v2 — total redesign (localhost, dark, device panel)

- Status: ACCEPTED (owner instruction 2026-10-02: "tambah web UI yang lebih proper dan
  lengkap. pakai localhost, dan lebih enak dilihat. tampilannya redesign total")
- Date: 2026-10-02
- Research: docs/research/r3-web-console-design.md, r5-synthesis-spec.md §B
- Supersedes: ADR-0017 layout (its SECURITY architecture is carried over unchanged)

## Context

The 0.3.0 console proved the security model but visually it is a utilitarian page
stack (dark text on plain background, no navigation model, no device concept). The
owner wants a proper, complete, pleasant console for daily use on localhost.

## Decision

### 1. Non-negotiable carryovers (ADR-0017, all still e2e-enforced)

- Served by the **admin plane** (loopback-only, TLS) — no new listener.
- **Single self-contained HTML file**, zero external assets (no CDN, no fonts, no
  supply-chain surface, works offline).
- **No HTML-string sinks**: every render is `textContent` / DOM API (structural XSS
  immunity; grep-e2e must keep proving it).
- CSRF: JS-only `X-Far-Ui` header + `SameSite=Strict` cookie; login failures feed the
  backoff window.

### 2. Design tokens (research R3, self-hosted aesthetic)

`bg #0b0e14 · panel #11151f · border #232a3a · text #e6e9f0 · dim #8b93a7 ·
accent #4f8cff · ok #34d399 · warn #fbbf24 · danger #f87171`, radius 10px, spacing
8/16/24, system font stack, `ui-monospace` for IDs/tokens, content max-width 1200px.
Dark-first (long ops sessions); contrast pairs checked (never hue alone — status
uses dot + word).

### 3. Layout & pages

Sidebar (220px): FARCONTROL mark + nav — **Dashboard, Sessions, Devices, Audit,
Danger**; footer: version + doctor chip. Content area: page title + contextual
action. Polling 3s while a page is open; optimistic action updates with rollback.

- **Dashboard**: 4 KPI cards (pending / active sessions / devices / audit events 24h);
  pending-request cards with approve (duration dropdown 5/8/12/24/48/72h) + deny;
  active-session rows with revoke; recent audit (8 rows).
- **Sessions**: full table (id, agent, scope badge, device, remaining live-countdown,
  expires) + revoke; informative empty state.
- **Devices**: device cards (mono ID + copy, name, status dot, last seen, strikes,
  active session count; lock/unlock, rotate-password, remove with confirm). **Add
  device** modal → shows device ID + password ONCE with copy buttons + the daemon
  fingerprint line.
- **Audit**: table (time, actor, action, level chip, device, message), text search,
  level filter, hash-chain status chip (verified / tampered), last 100 events.
- **Danger**: PANIC card (confirm modal: "revoke every session, kill terminals,
  rotate every device key?") + rotate-all-keys card.

### 4. New admin endpoints (same auth, CSRF header for UI mutations)

`GET /admin/devices` · `POST /admin/devices/add {name}` → `{device_id, password}`
(once) · `POST /admin/devices/lock {id}` · `POST /admin/devices/unlock {id}` ·
`POST /admin/devices/passwd {id}` → `{password}` (once) · `POST /admin/devices/remove
{id}`. Sessions/audit listings gain `device_id`. All mutations audited
(`owner:webui` actor) and reuse the CLI's state-layer functions (one code path).

### 5. Component inventory (all DOM-built)

`card, kpiCard, table, row, badge, dot, modal, copyButton, durationSelect, toast` —
no template strings anywhere; handlers attached via `addEventListener`.

## Consequences

- webui_index.html grows from ~300 to ~1000+ lines but stays one dependency-free
  file; e2e §web gains: device add→login→approve flow via UI endpoints, CSRF
  enforcement on new routes, textContent-only grep, backoff on bad logins.
- KPI cards double as doctor summary (owner sees health without terminal).
- v1.x additive: page structure is versioned by the `X-Console-Version` served with
  the HTML (bump per layout change).
