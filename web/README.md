# PicoNS web UI

Static single-page app for the PicoNS management API. Plain HTML/CSS/vanilla JS
(ES modules), no build step, no external resources. The whole directory is meant
to be embedded into the PicoNS binary via `rust-embed` and served from `/`.
Unknown non-`/api` paths should fall back to `index.html` (the app uses hash
routing, e.g. `#/zones`, so this is proxy-friendly).

## Serving / embedding

Embed this directory and serve it at `/`. A minimal rust-embed setup:

```rust
#[derive(rust_embed::RustEmbed)]
#[folder = "web/"]
struct WebAssets;
```

Serve `index.html` for `/` and for any unknown non-`/api` route; serve other
files by their path. All asset references in `index.html` are relative and local
(`styles.css`, `app.js`, the icon is an inline data URI), so nothing is fetched
from the network at runtime.

## Structure

```
web/
  index.html        App shell (loads styles.css + app.js as a module)
  styles.css        All styling. Light/dark via prefers-color-scheme + manual
                    toggle; palette is CSS custom properties.
  api.js            Centralized fetch client: injects X-CSRF-Token on mutations,
                    sends credentials: "same-origin", parses the error envelope,
                    throws a typed ApiError { status, code, message, fields }.
  ui.js             DOM builder (h), inline SVG icons, toasts, <dialog> modals,
                    formatting helpers, form/field error helpers.
  app.js            Bootstrap, hash router, app shell (sidebar/topbar), theme.
  views/
    auth.js         Login + first-run setup screens.
    dashboard.js    Status cards, listeners, live stats (polls every 5s).
    zones.js        Zone list with create/delete.
    zone-detail.js  SOA/zone settings editor + records CRUD + export link.
    views.js        Views list with create/edit/delete (CIDR rows).
    settings.js     Forwarders, forwarding toggle, cache, DNSSEC.
    account.js      Change password + logout.
```

## Auth / CSRF

- `api.js` reads the non-HttpOnly `picons_csrf` cookie and sends it as the
  `X-CSRF-Token` header on every `POST`/`PUT`/`PATCH`/`DELETE`. All requests use
  `credentials: "same-origin"`.
- On startup the app calls `GET /api/auth/me`. `401` shows the login screen;
  `409`/`setup_required` shows the first-run "create admin account" screen
  (`POST /api/setup`).
- Any `401` from a later call routes back to login.

## Theming

`data-theme` on `<html>` is `system` (default), `light`, or `dark`, persisted in
`localStorage` under `picons-theme`. The topbar toggle flips between light and
dark; `system` follows `prefers-color-scheme`.
