# oauthenticator — result page redesign spec

For the coding agent applying this to `oauthenticator.py`'s `ResultPage` (the `TEMPLATE` string.Template, the `NOTICE` template, and the render helpers). Ship both themes via `prefers-color-scheme` as today, plus a manual override (see Theme toggle).

## Fonts
Google Fonts, add to `<head>`:
```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
```
- `Space Grotesk` — UI text, headings, buttons.
- `IBM Plex Mono` — anything technical: the title, tab labels, claim keys/JSON, token values, timestamps, chip labels.

## Color tokens
Replace the existing `:root` / dark-media block with:
```css
:root {
  --bg: #f7f3ec; --bg-raised: #efe6d4; --bg-sunken: #f1e9d8;
  --border: #e6dcc8; --border-soft: #ddcfb0;
  --fg: #241f18; --muted: #7c7364; --faint: #a89d89;
  --accent: #a86e2b; --accent-ink: #fbf6ec;
  --info: #3f6f95; --danger: #a8543a; --ok: #4f8a56;
  --grid: rgba(168,110,43,0.05);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #181410; --bg-raised: #221c17; --bg-sunken: #130f0c;
    --border: #2a2420; --border-soft: #332c25;
    --fg: #f1ece2; --muted: #8a8177; --faint: #5c5348;
    --accent: #e2b468; --accent-ink: #181410;
    --info: #7fa5c9; --danger: #d98a6b; --ok: #8fbf8f;
    --grid: rgba(226,180,104,0.04);
  }
}
html[data-theme="light"] { color-scheme: light; /* re-declare the :root light values here so the override wins */ }
html[data-theme="dark"] { color-scheme: dark; /* re-declare the dark values here */ }
```
(Simplest real implementation: duplicate the two blocks as `html[data-theme="light"] {…}` / `html[data-theme="dark"]{…}` with `!important` or higher specificity than the media query, so the manual toggle overrides OS preference.)

Body background gets a faint grid on the main result page only:
```css
body { background-image: linear-gradient(var(--grid) 1px, transparent 1px), linear-gradient(90deg, var(--grid) 1px, transparent 1px); background-size: 26px 26px; }
```

## Icons
Consistent stroke set (Lucide-style: `viewBox 0 0 24 24`, `fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round`), inlined as `<svg>` — no icon font/CDN runtime dependency. One icon per action, never reused for two different actions:

| action | icon | source |
|---|---|---|
| Refresh | refresh-cw | `<path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 16h5v5"/>` |
| End session | log-out | `<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>` |
| Quit | power | `<path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.77.04"/>` |
| Copy as curl | terminal | `<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>` |
| Introspect | search | `<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>` |
| Revoke | trash-2 | `<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/>` |
| copy value | copy | `<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>` |
| expand token | chevron-right (rotate 90° when open) | `<polyline points="9 18 15 12 9 6"/>` |
| verified check | check | `<polyline points="20 6 9 17 4 12"/>` (stroke `var(--ok)`, `opacity:0.85`, ~12px, no circle/badge) |
| error | alert-triangle | `<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>` |
| notice page | terminal (same as curl icon) | see above |
| theme toggle | sun (light active) / moon (dark active) — swap on click | sun: `<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M6.3 17.7l-1.4 1.4M19.1 4.9l-1.4 1.4"/>` · moon: `<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79Z"/>` |

## Layout changes vs. current template

### Toolbar (`.bar`)
One row, in this order: title, spacer, status dot, Refresh, End session, Quit, theme toggle.
- Title: `$ oauthenticator` — `IBM Plex Mono 600`, `color: var(--accent)`, ~14px. (Drop the `<h1>The CLI runs while this page is open</h1>`/`.note` pairing — see status dot below.)
- **Status dot**: replaces the old `.note` text entirely. `8px` circle, `background: var(--ok)`. While the CLI is reachable (ping loop succeeding), animate the *ring only*, never the dot's own opacity/size:
  ```css
  @keyframes cli-pulse { 0% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--ok) 50%, transparent); } 70%, 100% { box-shadow: 0 0 0 6px transparent; } }
  .status-dot.live { animation: cli-pulse 2.4s ease-in-out infinite; }
  ```
  On `Finish` success (or once idle), swap to `background: var(--faint)`, drop the `.live` class (no animation, no label needed — the dot alone carries state).
- **Refresh** / **End session** / **Quit**: icon + label, quiet outline style (no fill on any of them — Quit is not more "primary" than the others, it's just the same button family). Colors: Refresh `var(--muted)` text/border, End session `var(--danger)` text with a matching soft border tint, Quit `var(--muted)` (same neutral as Refresh).
  - Refresh only renders when a `refresh_token` is present (unchanged from today).
  - End session only renders when discovery advertises `end_session_endpoint` (unchanged).
  - **New:** once the CLI has stopped (Quit succeeded, or — best-effort — the client stops getting ping responses), the title and Refresh/End session/Quit get the `disabled` attribute and a dimmed style instead of being removed from the DOM — the toolbar itself is not dimmed, and the theme toggle stays fully active:
    ```css
    .title:disabled, button:disabled { opacity: 0.55; cursor: not-allowed; }
    ```
- **Theme toggle**: square icon-only button, no label, sits at the far right after Quit — stays enabled even when the CLI has stopped. Click toggles `document.documentElement.dataset.theme` between `light`/`dark` and persists to `localStorage`; icon swaps sun/moon to show the *current* theme.

### Identity block (`.identity`)
Drop the badge (`id_token`/`access_token` source pill) and the expiry line entirely — expiry belongs to the token panel, not the identity summary.
```
[avatar]  name  ✓(if verified)  ·  email        <- only if email present & != name
          sub xxxxx                              <- only if claim present
          iss https://...                        <- only if claim present
```
- Avatar: square, `border-radius: 6px` (not a circle), sized in `rem` (not px) to match the text block's height — e.g. `width/height: 3.4rem`. Use the existing `<img>` when `identity.picture` is set; otherwise render a new fallback — initials (first letters of `name`, or `?` if unavailable) on `background: var(--bg-raised)`, `color: var(--accent)`, `font: 13px 'IBM Plex Mono'`.
- Row uses `align-items: flex-start` (not `center`) — with 2 or 3 lines the block should always start flush with the top of the avatar, not center inside it.
- Line 1: name (`14px 500`), inline check icon right after it when `email_verified`, then muted email.
- Lines 2–3 (`sub`, `iss`): `10.5px`, `IBM Plex Mono`, `var(--faint)`, only rendered when the claim exists — so the block is naturally 1–3 lines depending on what the tokens carry.

### Tabs (`.tabs button`)
Uppercase, `IBM Plex Mono`, active tab gets `background: var(--accent); color: var(--accent-ink)` with squared-off top corners (`border-radius: 3px 3px 0 0`) instead of the current underline treatment.

### Token panel (`.token`)
Value row: chevron-right (expand) → mono value → "expires in …" (muted, unchanged countdown logic) → copy icon, on `background: var(--bg-sunken)`.
Actions (`.actions`): icon + label pills, same quiet-outline family as the toolbar buttons — Copy as curl (`var(--muted)`), Introspect (`var(--info)`), Revoke (`var(--danger)`).

### JSON claims (header/payload)
**Always pretty-print with 2-space indentation — never the single-line/compact form currently used for the header object.** Add minimal syntax coloring: keys `var(--info)`, string values `var(--accent)`, numeric values `var(--ok)`. Section labels (`— HEADER —` / `— PAYLOAD —`) in `IBM Plex Mono`, small caps, `var(--faint)`, with a `border-left: 2px solid var(--border)` rail on the `<pre>` instead of a filled background.

### Error screen (`_render_error`)
Same toolbar as the success screen (Refresh/End session disabled since there are no tokens; Quit stays enabled). Body: a square icon tile (`alert-triangle`, `var(--danger)` on a tinted `var(--danger)` background) + headline (`error` code) + description + small `source: callback` mono caption, replacing the current plain-text block. Raw error string still shown below in a `<pre>` on `var(--bg-sunken)`.

### Notice / `--stdout` page
Centered card: `terminal` icon, message line, "You can close this tab." — no toolbar on this page (it has no interactive session to control).

## Demo file
`Design.dc.html` in this project shows all of the above, dark and light side by side, including the disabled-toolbar and error states.
