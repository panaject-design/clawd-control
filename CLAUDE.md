# Clawd Control — Project Context for Claude

## Repository Setup

This is a **fork** of `Temaki-AI/clawd-control` with Windows and SPA bug fixes.

- `origin` = `panaject-design/clawd-control` (our fork — push here)
- `upstream` = `Temaki-AI/clawd-control` (original repo — pull updates from here)

## Custom Fixes Applied

The following files contain our patches on top of upstream. During merges, preserve these changes:

### Server-side (Windows-specific)
- **`server.mjs`** (lines 12-13, 22) — `fileURLToPath()` + `dirname()` instead of `new URL().pathname` to fix doubled Windows paths (`C:\C:\...`)
- **`discover.mjs`** — Uses `~/.openclaw/openclaw.json` (not `~/.clawdbot/clawdbot.json`), port fallback, `localhost` instead of `127.0.0.1`
- **`collector.mjs`** — Client ID `gateway-client`, origin header, platform `win32`

### Frontend (all platforms — SPA navigation fixes)
- **`layout.js`** — `cache: 'no-store'` on SPA fetch, AbortController cleanup for page listeners
- **`dashboard.html`** — Null guards on `renderAll/renderAgent/renderStats/renderHost/renderFleetHealth`, window exports for onclick functions, immediate render on SPA back-navigation
- **`agent-detail.html`** — `window.switchTab/doAction/runSecurityAudit` exports
- **`crons.html`** — Window exports for `setView/changeMonth/toggleJob/scrollToJob`
- **`traces.html`** — Window export for `setViewMode`
- **`tokens.html`**, **`analytics.html`** — Abort signal on event listeners

## Merge Upstream Command

When the user says **"merge upstream updates"** (or similar), execute this workflow:

```bash
cd C:\Users\Edgar\Clawdbot\clawd-control

# 1. Fetch latest from Temaki-AI
git fetch upstream

# 2. Show what's new
git log --oneline main..upstream/main

# 3. Merge (if there are new commits)
git merge upstream/main

# 4. If conflicts: resolve keeping our fixes, then:
#    git add . && git commit

# 5. Push to our fork
git push origin main
```

### Conflict resolution rules
- If upstream modifies the same lines we patched, **keep our fix** unless the upstream change makes our fix unnecessary
- If upstream adds new pages with `onclick` handlers, add `window.functionName = functionName` exports
- If upstream adds new event listeners in page scripts, add `{ signal: window._pageAbort.signal }` option

## Running the Server

```bash
cd C:\Users\Edgar\Clawdbot\clawd-control
npm start
# Opens at http://localhost:3100
# Password in auth.json
```

Gateway must be running first: `openclaw gateway restart`
