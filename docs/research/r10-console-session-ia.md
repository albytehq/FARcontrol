# R10 — Session-Oriented Web Console: Information Architecture

> Research pass 10/15 · Mission 1.2.0 · Sources: dashboard design patterns
> (r10a: pencilandpaper.io, Bach et al. dashboard design patterns paper — 381
> cites, dashboarddesignpatterns.github.io, uxpilot 12 principles), self-hosted
> console examples (r10b: Portainer/Tailscale mentions — weak snippets, honest),
> v1.1 baseline (webui_index.html observed), master prompt §§9, 32.
> Raw: raw/r10a.json, raw/r10b.json

## What changes: from "admin dashboard" to "session cockpit"

1. **The master prompt is explicit** (§32): the console "should not look like a
   permanent cloud account dashboard" — it represents THIS session. The v1.1
   console (observed: sidebar + KPI cards + tables) reads as a management
   dashboard because v1.1 IS a long-lived control plane. v1.2's product model
   (ephemeral session) flips the IA: the session is the frame, everything else
   is a tab inside it.
2. **5-second rule / cognitive load** (r10a): a dashboard succeeds if the
   primary question is answerable in 5 seconds. FARcontrol's primary questions
   are now: *is a session active, until when, is my agent connected, what is it
   doing right now.* All four belong ABOVE THE FOLD, persistently.
3. **Structure patterns** (r10a, Bach et al.): flow/monitor pattern fits — one
   hero status object + drill-down lists. Progressive disclosure (uxpilot):
   summary first, detail on demand (matches v1.1's cards → modals).
4. **Live entities = cards, history = tables** (v1.1 r3 conclusion, unchanged):
   pending requests and the connected agent are cards; audit stays a filterable
   table.
5. **Devices demoted**: v1.2's default connection model needs NO device
   management (session credentials printed at start; master prompt §7). The
   Devices page becomes an "Advanced / trusted devices" section — present (the
   API/rows exist and are useful) but not primary navigation.
6. **PANIC is persistent, not a page** (v1.1 has it 4 clicks deep — observed
   nav: Dashboard/Sessions/Devices/Audit/Danger). An emergency stop that
   requires navigating to a page is hidden. Keep the confirm modal, move the
   button to the session header (always visible, r13 countdown adjacent).

## FARcontrol v1.2 adoption decisions

- **Layout**: persistent session header (Device ID + copy, state chip, expiry
  countdown, agent connection state, PANIC red button) + tabs: Activity |
  Audit | Advanced (devices/policy). Login = Admin Token from `frtrol start`.
- **Activity tab**: pending requests (approve/deny, duration select) + active
  operations + agent card (who, since when, last action, live reconnect state).
- **Empty session state** (before first start / after end): a clear
  "no active session — run `frtrol start`" terminal screen, not a login loop.
- Session-ended state is explicit and loud: banner "SESSION ENDED — these
  credentials are dead" (master prompt §50).
- Keep ADR-0027 non-negotiables: one file, no external assets, DOM+textContent
  rendering only, X-Far-Ui + SameSite=Strict, backoff integration.

## Honest gaps

- r10b snippets were weak (MCP lists, no direct Portainer IA analysis) — Portainer/Tailscale
  claims here rest on the author's product knowledge (INFERRED) + r3's earlier
  self-hosted research, not fresh screenshots. If needed, verify specific
  layouts before copying any pattern.
