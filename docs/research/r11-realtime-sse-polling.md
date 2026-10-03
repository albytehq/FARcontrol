# R11 — Real-Time Updates: Polling vs SSE vs WebSocket (localhost console)

> Research pass 11/15 · Mission 1.2.0 · Sources: SSE vs WS comparisons (r11a:
> index.dev — SSE 30–40% lower resource for unidirectional, codercops.com,
> cadence.withremote.ai), connection-indicator patterns (r11b: weak snippets,
> honest), v1.1 baseline (3s polling observed in webui_index.html), master
> prompt §§9, 32, 38.
> Raw: raw/r11a.json, raw/r11b.json

## The decision inputs

1. **The console's data flow is one-way** (r11a): server→client state pushes
   (agent connect/disconnect, new pending request, session tick, audit append).
   The client already sends actions over plain REST POSTs. WebSockets buy
   nothing here and cost a second protocol, connection state machine, and proxy
   complexity; SSE is the standard answer for unidirectional streams
   (index.dev: 30–40% lower server resource vs WS in one-way scenarios).
2. **EventSource gives reconnect for free**: built-in auto-reconnect +
   `Last-Event-ID` resumption — the client-side "RECONNECTING…" indicator falls
   out almost for free (onerror fires, readyState flips). This matches r8's
   state-machine requirement and the master prompt's connection-health ask.
3. **v1.1's 3s polling is acceptable but lossy-feeling**: approve → agent
   connects can be seen up to 3s late; countdowns only refresh on poll. With
   SSE, countdowns are computed client-side from `expires_at` + server clock
   offset (no per-second traffic) and discrete events arrive instantly.
4. **Keep the REST GET as source of truth**: initial load = `GET /ui/state`
   (unchanged shape), then `GET /ui/events` (SSE) for deltas. If SSE fails
   (exotic browser/proxy), fall back to v1.1 polling — same payloads, so the
   fallback is ~15 lines (honest, cheap insurance; master prompt §47 don't
   fake capability — a fallback is the opposite).
5. **Idle cost**: one held connection + heartbeat every 25–30s (SSE needs
   keep-alive through proxies). Fine on localhost; the daemon already holds
   TLS agent connections, this is one more fd.

## FARcontrol v1.2 adoption decisions

- Console transport: initial `GET /ui/state` + `EventSource /ui/events`;
  events: `agent_connected`, `agent_disconnected`, `request_new`,
  `request_resolved`, `session_tick` (30s, server clock), `audit_append`,
  `session_ended`. Polling (2.5s) as automatic fallback when SSE errors on
  connect. No WebSockets (Rule 1: no second protocol for one-way data).
- Connection chip in console: `live` / `reconnecting…` driven by EventSource
  state (r11b concept corroborated only generically — pattern is standard).
- Countdowns computed locally between ticks (r13); no layout shift while
  ticking (reserve width for the countdown span).
- Event payloads never contain secrets; events are metadata-only (§95).

## Honest gaps

- r11b (status-indicator snippets) was mostly noise; the indicator pattern
  claim rests on ubiquitous convention (INFERRED), not a cited study.
- No load numbers for OUR daemon with N SSE clients — irrelevant at N=1
  (localhost, single owner) but stated for honesty.
