# R15 — Terminal Compatibility & Accessibility (CLI + console)

> Research pass 15/15 · Mission 1.2.0 · Sources: terminal-compat standards
> (r15a: NO_COLOR spec via LLVM/clang docs, picocli 80-col usage width,
> Windows-safe Unicode guidance grizzlypeaksoftware, ftui capability-detection
> crates), accessibility references (r15b: W3C WAI colors, WebAIM contrast,
> section508.gov color usage, dark-mode WCAG accessibilitychecker),
> local KB: ui-ux-pro-max data/ux-guidelines.csv (99 audited rules — focus
> states, loading buttons, reduced motion, touch targets, ARIA).
> Raw: raw/r15a.json, raw/r15b.json · Contrast figures COMPUTED this session
> (WCAG relative-luminance formula, discipline §8.7).

## Terminal compatibility (CLI)

1. **NO_COLOR is the standard** (r15a): defined-and-not-empty disables color;
   not-a-TTY also disables it. v1.1 ships this via owo-colors (ADR-0026) —
   keep; verify no new print path in v1.2 bypasses out.rs helpers.
2. **80 columns is the contract floor** (r15a, picocli default; v1.1 r5 rule:
   tables max 100 cols, middle-truncate). v1.2's start panel must fit 80 cols
   (fixed-width secrets like a 4-word diceware password fit comfortably).
3. **Windows/Unicode discipline** (r15a): status glyphs must degrade to ASCII
   (`●`→`*`, `✓`→`+`) — v1.1 already carries shape-based meaning (r5 §A.1);
   keep the glyph set exactly as-is, add none.
4. **Credential lines never styled inside the secret**: no color codes around
   the password span (scrollback/copy safety, master prompt §29).

## Web console accessibility (computed, not eyeballed)

5. **Contrast audit of the v1.2 palette (ADR-0027 tokens)** — computed with
   the WCAG 2.x relative-luminance formula this session:
   - text/bg 15.89:1, text/panel 15.01:1 — AAA ✓
   - dim/bg 6.28:1, dim/panel 5.93:1 — AA ✓ (AAA ✗ — acceptable for secondary
     text; do not use dim for critical info like expiry countdowns)
   - accent/bg 6.00:1, ok 10.05:1, warn 11.57:1, danger 6.98:1 — AA ✓
   - buttons: primary 9.75:1, good 7.62:1, danger 5.94:1 — AA ✓ (all use
     tinted-dark bg + colored text — this pattern is sound; do not "brighten"
     buttons with white text, which FAILS: white-on-danger = 2.77:1 ✗)
   - **FINDING: nav badge (accent text #4F8CFF on accent2 bg #1D3153) =
     4.04:1 → FAILS AA for its 11px text.** Fix: lighten badge text to
     #CFE0FF (9.75:1 ✓) or darken the badge background. v1.2 must fix this.
6. **Never color alone** (r15b, section508 + WAI): v1.1 already pairs dot+
   word; the session header countdown must also carry a word (`4h 51m left`,
   amber → "expiring", red → "critical"), not just hue.
7. **From the local KB (ui-ux-pro-max, cited rules)**: visible `:focus-visible`
   rings (rule 28 — v1.1 console currently has NONE for keyboard nav: observed
   `input:focus` but no `button:focus-visible`); loading/disable state on
   approve buttons to prevent double-submit (rule 32 — v1.1 approve button
   stays clickable during the POST: observed); `prefers-reduced-motion`
   (rule 9 — v1.1 has one 0.15s transition, acceptable, add the media query
   anyway); 44px touch targets (rule 22 — mostly met, mini buttons are
   borderline; owner-on-laptop is the primary case, phone is secondary r3).
8. **Screen-reader basics for the console**: aria-labels on icon-only buttons
   (copy buttons, nav), heading hierarchy (one h1 per page — currently true),
   live region for the connection chip (`aria-live=polite`) so state changes
   are announced.

## FARcontrol v1.2 adoption decisions

- Console: fix badge contrast (5); add `:focus-visible` + keyboard nav;
  disable+spinner on in-flight actions; aria-labels + one polite live region;
  countdowns in mono fixed-width spans with word+color state.
- CLI: keep NO_COLOR + TTY + 80-col rules; all new output through out.rs.
- Re-verify computed contrast if any token changes (record the ratios in
  ADR when tokens are finalized).

## Honest gaps

- Touch-target and screen-reader claims are from guidelines/KB, not tested
  with assistive tech (no NVDA/VoiceOver in this sandbox) — mark NOT
  VERIFIED until a manual pass happens post-implementation.
