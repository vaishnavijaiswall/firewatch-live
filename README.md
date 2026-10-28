# FireWatch Live v2.1

Original phone-style UI preserved (demo model, scenarios, Predict/System tabs), extended with a small Node backend.
v2.1 fixes the map and adds a desktop layout, guest map access, separate administrator login and alert editing.

## Run locally
```bash
npm install                 # installs express only (needs Node >= 22.5; uses built-in node:sqlite)
cp .env.example .env        # set ADMIN_EMAIL, ADMIN_PASSWORD, FIRMS_MAP_KEY
npm start                   # then open http://localhost:3000
```
**Open `http://localhost:3000`, not `public/index.html` from disk.** Opened as a file, OpenStreetMap refuses tile requests
(no Referer) and login cannot work. The page now detects the missing server and shows the map in guest mode with a banner
that says so. If `ADMIN_PASSWORD` is empty a random admin password is printed once on first start.

## What changed in v2.1
**Map**
- Leaflet 1.9.4 is now served by the app itself (`public/vendor/leaflet`, BSD-2 licence included): no CDN, works offline, and a
  blocked CDN can no longer leave you with an empty map. Leaflet's CSS loads before the app CSS, and the app's global
  `canvas`/`img` rules can no longer reach Leaflet's elements.
- The map is no longer hidden behind the login overlay. Guests can use the map, weather, place search and layer switch;
  satellite detections and alerts still need an account. If the backend is unreachable the map still shows, with a banner.
- Tile failure shows a message with **Retry** and **Try the other layer**; a loading indicator shows while tiles load.
- Desktop/laptop (>= 980 px): full-width dashboard with a side rail and a large map. Phones keep the original layout.
- Map refreshes correctly after tab switches, resize and login (size observer + explicit refresh).

**Weather / risk**: temperature chips are outlined by a *weather-only fire-danger heuristic* (temperature, humidity, wind,
current rain). It is a transparent rule, **not** the ML model and **not** validated; popups say so. It works anywhere on
Earth, unlike the demo model, which only covers the Western Ghats grid.

**Accounts**: separate *Local user* and *Administrator* login portals (server-checked: a user cannot sign in through the
admin portal and vice versa). Administrators can now **edit** a published alert (wording, severity, safety actions; the
audience is locked). Malformed cookies and malformed JSON no longer cause 500s/HTML error pages.

Already present in v2 and kept: scrypt password hashing, httpOnly sessions, server-side role checks, rate limits, persistent
alerts/read-state in SQLite, geographic targeting (country/state/district/area), NASA FIRMS proxy with the key kept server-side,
open-meteo weather, Nominatim place search, demo ML model with explicit "synthetic data" labelling.

## Environment variables
| Var | Purpose |
|---|---|
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | Seeds the first administrator (only if no admin exists). Registration can never create admins. |
| `FIRMS_MAP_KEY` | Free NASA FIRMS key (https://firms.modaps.eosdis.nasa.gov/api/map_key/). Stays server-side. Without it the UI says detections are unavailable; nothing is invented. |
| `PORT`, `DB_FILE`, `NODE_ENV=production` | Port, SQLite path, enables `Secure` cookies (serve over HTTPS). |

Esri street tiles, Esri imagery, Open-Meteo and Nominatim need no key. Existing databases are migrated automatically (`alerts.updated_at`).

## Deploy
Any Node >= 22.5 host (Render, Railway, Fly.io, a VPS): set the env vars, run `node server.js`, put HTTPS in front, mount a
persistent disk for `DB_FILE`. The frontend is served by the same server, so there is no separate frontend deploy. For several
instances or heavy load, move to PostgreSQL/PostGIS and a shared rate-limit store.

## Tests
`node tests/api.test.js` (41 checks; start the server first on :3111 with a fresh DB, `ADMIN_EMAIL=admin@test.dev ADMIN_PASSWORD=AdminPass123`)
and, on a *fresh* server, `python3 tests/ui_test.py` (38 checks, Playwright; mocks tile/weather/geocoder hosts).
The API test intentionally exhausts the login rate limit, so restart the server between the two.

**How these were run for this release:** the build sandbox could not reach the npm registry or any map/weather host, so
(1) the backend tests ran against a minimal local stand-in for Express, and (2) all external hosts were mocked in the browser
tests. They prove the app logic, layout and error handling; they do **not** prove live tile loading, real Open-Meteo/Nominatim
responses, real FIRMS data or the real Express runtime. Please run the checklist below once on your machine.

### Smoke checklist for your machine (2 minutes)
1. `npm install && npm start`, open http://localhost:3000 -> OSM tiles appear; switch Standard/Satellite.
2. Continue as guest -> temperature chips appear; search "Kodagu" -> map moves, popup shows weather.
3. Register a user with an area, log in -> Messages tab; log in via the Administrator portal -> send an alert for that area.
4. Set `FIRMS_MAP_KEY`, restart -> red markers appear for detections in view.
5. Browser console shows no errors.

## Known limitations
- Predicted-risk heat layer and ML metrics come from the **demo model on synthetic data** (Western Ghats grid). Replace with a
  model trained on real, validated fire records before relying on it.
- Fire detections need a FIRMS key; satellite data lags overpasses by hours. FIRMS queries are capped to ~25x25 degrees (zoom in).
- Alert targeting matches place *names* from OpenStreetMap (e.g. "Bengaluru Urban" vs "Bangalore" will not match); delivery is
  in-app only. Email/SMS/push need a provider (Twilio, SES, FCM...) and are not wired up.
- Weather values are Open-Meteo model analysis, not station observations (labelled as such in the UI).
- SQLite and in-memory rate limiting suit one instance only.
