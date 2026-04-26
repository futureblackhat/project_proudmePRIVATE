# Deploying the ProudMe backend

This document covers what the README does not: env vars, local setup, and the Render deploy pipeline.

## Architecture overview

- **Single Node.js HTTP server** at [server/server.js](server/server.js).
- **One-shot daily script** at [server/cron.js](server/cron.js) that creates the previous day's default behavior rows for every user. Run automatically inside `server.js` via `node-cron` (it does NOT need to be invoked separately on Render).
- **Mongoose models** in [server/models/](server/models/) — `User.js` and `Behavior.js`. These are used by `cron.js`. The same schemas are also defined inline in `server.js` so the running server can register them on its own connection. **Both definitions must stay in sync** (see [todo.md](../project-proudme-mobile-dev/todo.md) M24).
- **Auth middleware** at [server/authMiddleware.js](server/authMiddleware.js) — verifies HS256 JWTs and rejects revoked tokens.
- **No build step.** `node ./server/server.js` is the entire startup sequence.

## Required environment variables

Copy [.env.example](.env.example) to `.env` for local development and fill in real values. On Render, set the same keys via the dashboard's Environment tab.

| Variable | Purpose |
|---|---|
| `REACT_APP_MONGODB_URI` | MongoDB Atlas connection string. Historical name — predates the React → Flutter migration. |
| `SENDGRID_API_KEY` | SendGrid API key. Use a Restricted-Access key with only the `Mail Send` scope. |
| `OPEN_AI_API_KEY` | OpenAI API key for the chatbot feedback feature. |
| `JWT_SECRET` | High-entropy secret for HS256 JWT signing. Generate with `openssl rand -hex 64`. |
| `PORT` | Optional; Render injects its own value. Defaults to 3001 locally. |

## Local development

Prerequisites: Node 20+, npm 10+, a MongoDB Atlas cluster (free tier is fine), a SendGrid sandbox account, an OpenAI API key.

```bash
# From the repo root:
cd project_proudme_backend
npm install
cp .env.example .env
# fill in the four required values in .env

# Start the server with auto-reload:
npm run server   # uses nodemon

# Or start it without auto-reload:
npm start
```

Server boots on `http://localhost:3001`. Liveness check:

```bash
curl -s http://localhost:3001/health
# {"ok":true,"uptime":1.234}
```

The mobile app talks to this URL when you pass `--dart-define=API_BASE_URL=http://localhost:3001` to `flutter run` (see [project-proudme-mobile-dev/lib/endpoints.dart](../project-proudme-mobile-dev/lib/endpoints.dart)).

## Render deploy

The production backend runs on Render at `https://project-proudme-1.onrender.com`.

### Service config

- **Name:** `project_proudme_mobile_backend`
- **Plan:** Starter ($7/mo) — required for production. Free tier cold-starts after 15 min idle, which fails Apple App Review.
- **Build command:** `npm install`
- **Start command:** `npm start` (resolves to `cd ./server && node server.js`).
- **Auto-deploy branch:** `main` (the user manually triggers redeploys when the auto-deploy hook is flaky — check the Render dashboard's Manual Deploy button).
- **Env vars:** all 4 required vars set via the Environment tab. Renders the dyno on save.
- **Health check path:** `/health` (M21). Wire this into Render's health-check setting AND any external uptime monitor (UptimeRobot free tier is sufficient).

### Deploy flow

1. Commit and push to `main`.
2. If auto-deploy is on: wait for Render to detect the push (usually < 30s) and watch the build log.
3. If auto-deploy is off: open the Render dashboard → Manual Deploy → "Deploy latest commit".
4. Watch the deploy log for "Connected to MongoDB" and the `Server running at http://localhost:<port>` line.
5. Sanity-check live: `curl -s https://project-proudme-1.onrender.com/health`.

### Rollback

Render's dashboard keeps the last several builds. Deploys → click an older build → "Redeploy". Useful when a bad merge hits `main`.

## Rate limits

- `chatbotLimiter` — 20 calls per hour, keyed by authenticated user id. Bounds OpenAI cost.
- `loginLimiter` — 10 attempts per 15 minutes per IP. Stops credential stuffing.
- `verifyLimiter` — 5 attempts per 15 minutes per IP. Stops 6-digit-code brute force.
- `sendCodeLimiter` — 3 calls per 15 minutes per IP. Stops SendGrid quota burn.

If a legitimate test run is rate-limited, wait the window out (don't try to clear it). The `RateLimit-Remaining` response header tells you how many calls you have left in the current window.

## Trust proxy setting

The traffic chain in front of the dyno is **client → Cloudflare → Render LB → app**, so [server.js](server/server.js) does `app.set("trust proxy", 2)`. Without this, the rate limiters key against rotating Cloudflare edge IPs and never fire. If Render or Cloudflare ever changes their proxy setup, this number must be updated.

## Logs

- **Render dashboard → Logs tab** is the live tail for the running dyno.
- Server logs use plain `console.log` / `console.error` (no log shipper yet — see todo M28 for the audit-logging gap).
- User emails are NOT logged — the `/login` handler logs the user id only (M5). Don't add email to logs in new handlers.

## Common gotchas

1. **Manual redeploys** — Render's auto-deploy hook has been flaky on this account. If you push and the dashboard doesn't show a new build within a minute, hit Manual Deploy.
2. **Mongoose 6 EOL** — currently on Mongoose 6.x. Upgrade to 7.x or 8.x is on the roadmap (todo M11) but not done.
3. **CORS allowlist** — only `http://localhost:*` and `http://127.0.0.1:*` browser origins are accepted. Native mobile passes through (no Origin header). Rogue browser-side embeds are rejected.
4. **JWT secret rotation** — rotating `JWT_SECRET` on Render invalidates every issued token instantly. Users will see "Token has been revoked" or "Invalid token" until they re-login. Do this only when responding to a credential exposure.
5. **Atlas password rotation** — paste the new password into the connection string in `REACT_APP_MONGODB_URI` carefully. URL-encode any special characters in the password (`@` becomes `%40`, etc.). After saving, watch the deploy log for "Connected to MongoDB" — if it 500s instead, the encoding is wrong.

## Related

- Security model + per-route invariants: [project-proudme-mobile-dev/workdone.md](../project-proudme-mobile-dev/workdone.md) → "Security invariants" section.
- Open issues / cleanup: [project-proudme-mobile-dev/todo.md](../project-proudme-mobile-dev/todo.md).
- Pre-TestFlight checklist: [project-proudme-mobile-dev/workdone.md](../project-proudme-mobile-dev/workdone.md) → "PRE-TESTFLIGHT CHECKLIST".
