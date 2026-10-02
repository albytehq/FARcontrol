# R3 — Web Admin Console Design (self-hosted, localhost)

> Research pass 3/5 · Mission 1.1.0 · Sources: adminlte.io design guide, navbar.gallery
> sidebar patterns, 2025/2026 dashboard best-practice writeups, awesome-selfhosted
> (glance/homarr family). Raw: raw/r3a.json, raw/r3b.json

## Convergent industry pattern for owner consoles

1. **Dark-first theme** for long operations sessions (eye strain), with high-contrast
   active states; never rely on hue alone — pair with weight/shape.
2. **Sidebar navigation** is the dominant layout: fixed left rail (icons + labels),
   content area with page header. Top-bar variants exist but sidebars win for >4 pages.
3. **KPI cards row** at top of dashboard: 3–4 stat cards (pending, active sessions,
   devices, audit events) with delta/subtext.
4. **Cards over tables for "live" entities** (requests, sessions) and tables for
   historical logs (audit) with filter + search.
5. **Destructive actions**: distinct danger zone (PANIC) — red, isolated, confirm step.
6. **Self-hosted aesthetics** (glance/homarr): generous whitespace, rounded corners
   (8–12px), soft elevation, muted background (#0b0e14-class), one accent color,
   system font stack, monospace for IDs/tokens.
7. **Responsive down to ~768px** (sidebar collapses to icons) — owner may open it on
   a phone over LAN/VPN.
8. **Live-ish updates via polling** (2–5s) is the self-hosted norm vs websockets —
   simpler, no extra ports. Keep REST GET endpoints, poll from JS.

## FARcontrol hard constraints (from ADR-0017, non-negotiable)

- Still ONE self-contained HTML file served by the daemon — **no CDN, no external
  assets** (offline localhost product; no supply-chain surface, no IP leak).
- **No HTML-string sinks**: all rendering via `textContent` / DOM API only
  (structural XSS immunity — proven by grep-e2e in 0.3.0; must keep passing).
- CSRF: JS-only custom header `X-Far-Ui` + `SameSite=Strict` cookie stays.
- Login failure feeds the existing backoff window (SE-09).

## Page map (v2 console)

- **Dashboard**: KPI cards, pending requests (approve w/ duration select), recent audit.
- **Sessions**: active sessions w/ scope badge, remaining humanized, revoke.
- **Devices**: device cards (ID, name, last seen, strikes), add-device wizard (prints
  ID + password ONCE with copy buttons), lock/unlock, rotate password.
- **Audit**: filterable table (actor/action/level), search, hash-chain status chip.
- **Danger zone**: PANIC (confirm modal), token rotate.
- Footer: version, uptime, doctor summary chip.
