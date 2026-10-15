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

The root `render.yaml` is a Blueprint. Push the repository to a Git provider, select **New > Blueprint** in Render, then choose the repository. The build installs dependencies and Chromium; Render starts the app and checks `/healthz`.

The Blueprint uses a paid Standard web instance and a 1 GB persistent disk mounted at `/var/data`. Chromium needs memory to render pages, and SQLite snapshots need persistent storage to survive deploys. Render Free web services do not have persistent disks, so their local files are lost on restart.

## Detection and alerts

- Checks run through a bounded queue with retries, timeouts, and per-host cooldowns. Identical URLs with the same watch settings share one render while concurrent and recent checks are active.
- Only public HTTP and HTTPS targets are accepted. Local/private network targets and URLs containing credential-like query parameters are rejected. The browser does not store target-site credentials.
- Successful checks save normalized page text and a screenshot. A version is created only when the normalized text hash changes. Noise filters handle common timestamps, counters, advertisements, rotating banners, and random tokens; sensitivity can be low, medium, or high.
- Watch and ignore selectors can be entered directly or selected in the visual picker. The page timeline supports text diffs, highlighted screenshot diffs, side-by-side comparisons, check status, and charts for labeled numbers such as `Price: 12.50`.
- Email needs `SMTP_HOST` and `SMTP_FROM`; optional settings are `SMTP_PORT` (587 by default), `SMTP_SECURE=true`, `SMTP_USER`, and `SMTP_PASS`. Discord uses the server setting `DISCORD_WEBHOOK_URL`. Telegram uses `TELEGRAM_BOT_TOKEN` and a per-page chat ID. Alerts are deduplicated by version and channel, with a sensitivity-based cooldown. Daily email digests are optional.
- Each page can create a private RSS link. The link contains a revocable secret token; treat it like a password. Only its hash is stored. Anyone with that link can read that page's feed.
- If `OPENAI_API_KEY` is configured, Changewatch can write a short change summary using the Responses API. `OPENAI_MODEL` selects the model; the default is `gpt-6-astra`. Up to 3,500 characters from each version are sent with response storage disabled. Summaries are skipped when the key is absent.
- The optional Chrome extension in `extension/` opens the add-page form with the current HTTP or HTTPS page prefilled.

## Operations

- Database: `DATA_DIR/changewatch.sqlite` (defaults to `./data/changewatch.sqlite`). Back up this directory to preserve history and screenshots.
- Unchanged check records are purged after seven days by default; snapshots remain in the timeline. Set `CHECK_RETENTION_DAYS` from 1 to 365 to change the retention period.
- Secrets for SMTP, Discord, Telegram, and OpenAI belong in the hosting provider's environment settings, not in source control.
- `GET /healthz` is public for service health checks. Dashboard APIs require a signed-in account; RSS feeds require their per-page token.
- Run unit tests with `npm test`.

## Project layout

```text
server.js          Express API, authentication, and app lifecycle
src/auth.js        Password hashing and token utilities
src/store.js       SQLite users, sessions, pages, checks, and snapshots
src/checker.js     Chromium checks, normalization, comparisons, and alerts
src/scheduler.js   Bounded job queue, host cooldown, and digest schedule
public/            Dashboard, account pages, styles, and self-hosted fonts
extension/         Optional Chrome extension
test/              URL safety, storage, authentication, and change logic
render.yaml        Render Blueprint
```
