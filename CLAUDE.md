# Clawd Control — Project Context for Claude

## Repository Setup

This is a **fork** of `Temaki-AI/clawd-control` with Windows and SPA bug fixes.

- `origin` = `panaject-design/clawd-control` (our fork — push here)
- `upstream` = `Temaki-AI/clawd-control` (original repo — pull updates from here)

## Custom Fixes Applied

The following files contain our patches on top of upstream. During merges, preserve these changes:

### Server-side (Windows-specific)
- **`server.mjs`** — `fileURLToPath()` + `dirname()` for Windows paths; `runCLI()` helper with `shell:true` on Windows so `execFileSync` can find npm-installed `.cmd` wrappers; all `clawdbot` refs → `openclaw`, all `.clawdbot/` → `.openclaw/`
- **`create-agent.mjs`** — Same `runCLI()` helper + Windows path fix; replaced `pgrep`/`kill -USR1` Linux commands with `openclaw gateway reload`; all `clawdbot` refs → `openclaw`
- **`discover.mjs`** — Uses `~/.openclaw/openclaw.json` (not `~/.clawdbot/clawdbot.json`), port fallback, `localhost` instead of `127.0.0.1`
- **`collector.mjs`** — `fileURLToPath()` + `dirname()` Windows path fix (was causing "Connecting to agents..." hang); client ID `gateway-client`, origin header, platform `win32`; cross-platform `_collectHostMetrics()` using `os` module + PowerShell `Get-PSDrive` for disk (replaces Linux-only `/proc` reads and deprecated `wmic`)
- **`check.mjs`** — Config path `.clawdbot/clawdbot.json` → `.openclaw/openclaw.json`
- **`security-lib/checks/gateway.js`** — Config path `.clawdbot/clawdbot.json` → `.openclaw/openclaw.json`

### Frontend (all platforms — SPA navigation fixes)
- **`layout.js`** — `cache: 'no-store'` on SPA fetch, AbortController cleanup for page listeners, removed overly broad `text.includes('layout.js')` script filter that was skipping dashboard script execution during SPA navigation, added SSE state replay (dispatches `layout:snapshot` + `layout:host-update`) after SPA page swap so new listeners receive cached data
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
- If upstream adds new `execFileSync('clawdbot', ...)` calls, change to `runCLI([...])` and rename `clawdbot` → `openclaw`
- If upstream adds new `.clawdbot/` paths, change to `.openclaw/`
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
