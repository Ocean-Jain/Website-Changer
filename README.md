Link to the deployed website:website-changer.onrender.com

# Changewatch

Changewatch watches publicly accessible web pages, filters routine noise, and keeps a timeline of meaningful changes. Each account has its own private watchlist and saved history.

## Run locally

Requires Node.js 24.15 or newer.

```sh
npm ci
npx playwright install chromium
npm start
```

Open `http://localhost:3000`, create an account, then add a public URL and choose an interval from 15 minutes to 24 hours. Account passwords are hashed with scrypt; sessions use random, HTTP-only cookies. Email addresses are normalized and unique, enforced by SQLite. To store data elsewhere, set `DATA_DIR` before starting the server.

## Deploy on Render

The root `render.yaml` is a Blueprint. Push the repository to a Git provider, select **New > Blueprint** in Render, then choose the repository. The build installs the Node dependencies; Render starts the app and checks `/healthz`.

The Blueprint uses a paid Standard web instance and a 1 GB persistent disk mounted at `/var/data`. SQLite accounts, snapshots, and history use that disk so they survive deploys. Render Free web services do not have persistent disks, so their local files are lost on restart.

Render uses `CHANGEWATCH_RENDER_MODE=static`: scheduled checks fetch public server-rendered HTML or RSS/Atom feeds using Node's built-in `fetch`, with no Chromium installation or launch required. A monitor saved as the Google News homepage is automatically read through its public top-stories RSS endpoint in this mode. This uses Google's feed format rather than repeatedly requesting the blocked HTML homepage. Pages that require client-side JavaScript may not expose their content in static mode; screenshot diffs and the visual picker are unavailable there, while text snapshots, text comparisons, and alerts continue to work. For browser-rendered pages, run outside static mode on a host where Playwright Chromium is installed.


## Detection and alerts

- Checks run through a bounded queue with retries, timeouts, and per-host cooldowns. Identical URLs with the same watch settings share one render while concurrent and recent checks are active.
- Only public HTTP and HTTPS targets are accepted. Local/private network targets and URLs containing credential-like query parameters are rejected. The browser does not store target-site credentials.
- Successful checks save normalized page text. Browser-mode checks also save screenshots; Render static-mode checks do not. A version is created only when the normalized text hash changes. Noise filters handle common timestamps, counters, advertisements, rotating banners, and random tokens; sensitivity can be low, medium, or high.
- Watch and ignore selectors can be entered directly. Browser-mode deployments can also use the visual picker. The page timeline supports text diffs, check status, and charts for labeled numbers such as `Price: 12.50`; screenshot comparisons are available for snapshots that include screenshots.
- Email needs `SMTP_HOST` and `SMTP_FROM`; optional settings are `SMTP_PORT` (587 by default), `SMTP_SECURE=true`, `SMTP_USER`, and `SMTP_PASS`. Discord uses the server setting `DISCORD_WEBHOOK_URL`. Telegram uses `TELEGRAM_BOT_TOKEN` and a per-page chat ID. Alerts are deduplicated by version and channel, with a sensitivity-based cooldown. Daily email digests are optional.
- Each page can create a private RSS link. The link contains a revocable secret token; treat it like a password. Only its hash is stored. Anyone with that link can read that page's feed.
- Changewatch always stores a short local summary with each change. If `OPENAI_API_KEY` is configured, it can replace that with an AI-written summary using the Responses API. `OPENAI_MODEL` selects the model; the default is `gpt-6-astra`. Up to 3,500 characters from each version are sent with response storage disabled.
- The optional Chrome extension in `extension/` opens the add-page form with the current HTTP or HTTPS page prefilled.

## Core requirement answers

- **Outage or CAPTCHA vs. a change:** HTTP 401, 403, 429 responses and detected access challenges are marked `blocked`; HTTP errors and network failures are marked `error`. Neither status creates a content version or a change alert.
- **Rate limited pages and feeds:** The checker does not retry a 429 immediately. If the site supplies `Retry-After`, that cooldown is stored as the earliest next check (up to seven days); use the publisher's RSS/Atom feed or official API when one is available. RSS/Atom URLs can be monitored directly in Render static mode.
- **Many users watching one URL:** Concurrent checks and checks made within 60 seconds share a fetched result when URL and watch settings match. This is an in-process cache, so different selectors/sensitivity or multiple app instances can cause separate requests.
- **Pages that change on every load:** Text normalization removes common timestamps, counters, and token noise; ignore selectors can remove volatile regions. Sensitivity controls number filtering and alert cooldown. Keyword filters match only text added or removed by a version change, and version/channel deduplication prevents duplicate alerts. A genuinely changing page can still alert again after its cooldown.
- **Avoiding excess requests:** Monitors run no more often than every 15 minutes, the queue caps concurrency at two and limits queued work, and requests to the same host are spaced by at least 15 seconds unless a shared result is available. Navigation and browser actions have timeouts and transient errors retry up to three times.

## Operations

- Database: `DATA_DIR/changewatch.sqlite` (defaults to `./data/changewatch.sqlite`). Back up this directory to preserve history and screenshots.
- Unchanged check records are purged after seven days by default; snapshots remain in the timeline. Set `CHECK_RETENTION_DAYS` from 1 to 365 to change the retention period.
- Secrets for SMTP, Discord, Telegram, and OpenAI belong in the hosting provider's environment settings, not in source control.
- Set `APP_URL` to the service's public base URL when self-hosting so change alerts and digests include working comparison links. Render's `RENDER_EXTERNAL_HOSTNAME` is used automatically.
- `GET /healthz` is public for service health checks. Dashboard APIs require a signed-in account; RSS feeds require their per-page token.
- Run unit tests with `npm test`.

## Project layout

```text
server.js          Express API, authentication, and app lifecycle
src/auth.js        Password hashing and token utilities
src/store.js       SQLite users, sessions, pages, checks, and snapshots
src/checker.js     HTTP/HTML and Chromium checks, normalization, comparisons, and alerts
src/scheduler.js   Bounded job queue, host cooldown, and digest schedule
public/            Dashboard, account pages, styles, and self-hosted fonts
extension/         Optional Chrome extension
test/              URL safety, storage, authentication, and change logic
render.yaml        Render Blueprint
```
