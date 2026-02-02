# Cost Analytics Feature

## Overview
Production-ready cost analytics page for Clawd Control that aggregates token usage and costs across all agents.

## Files Created/Modified

### New Files
- **analytics.html** - Cost analytics dashboard page with:
  - Summary stats cards (total cost, tokens, API calls, cache hits)
  - Cost breakdown by agent (CSS bar chart)
  - Token usage breakdown (input/output/cache)
  - Cost over time (canvas line chart)
  - Top expensive sessions
  - Model usage distribution

### Modified Files
- **server.mjs** - Added:
  - `/api/analytics` endpoint with query params:
    - `range`: 7, 30, 90, or "all" (days)
    - `agent`: agent ID or "all"
  - `getAnalytics()` function that efficiently parses JSONL files
  
- **layout.js** - Added:
  - Navigation link to analytics page in sidebar
  - Page detection for analytics page

## API Endpoint

### GET /api/analytics?range=7&agent=all

**Query Parameters:**
- `range` (optional, default: 7): Time range in days or "all"
- `agent` (optional, default: "all"): Filter by agent ID

**Response:**
```json
{
  "range": "7",
  "agentFilter": "all",
  "totalCost": 12.3456,
  "totalTokens": 1234567,
  "inputTokens": 500000,
  "outputTokens": 700000,
  "cacheReadTokens": 34567,
  "apiCalls": 1234,
  "byAgent": [
    { "agentId": "main", "cost": 8.5, "tokens": 850000 }
  ],
  "overTime": [
    { "date": "2026-02-01", "cost": 2.5, "tokens": 250000 }
  ],
  "byModel": [
    { "model": "anthropic/claude-sonnet-4-5", "cost": 10.0, "tokens": 1000000 }
  ],
  "topSessions": [
    { "agentId": "main", "sessionId": "abc123", "cost": 3.5, "tokens": 350000 }
  ]
}
```

## Features

### Charts & Visualizations
1. **Cost by Agent** - Horizontal bar chart (pure CSS)
2. **Token Breakdown** - Horizontal bars showing input/output/cache split
3. **Cost Over Time** - Line chart with canvas (7-90 day view)
4. **Top Expensive Sessions** - Ranked list with cost and token counts
5. **Model Distribution** - Percentage breakdown by model

### Performance Optimizations
- Streams JSONL files efficiently (doesn't load entire files)
- Filters by date at file stat level before parsing
- Skips archived/deleted sessions
- Uses mtime to avoid parsing old files
- Caches nothing in memory (stateless)

### UI Features
- Dark/light theme support (matches existing design)
- Responsive grid layout
- Amber accent color (#c9a44a)
- Lucide icons
- SSE integration for live agent list
- Smooth animations

## Data Source
Parses session JSONL files at: `~/.clawdbot/agents/{agentId}/sessions/*.jsonl`

Extracts from each message:
- `message.usage.cost.total` - Cost in USD
- `message.usage.input` - Input tokens
- `message.usage.output` - Output tokens
- `message.usage.cacheRead` - Cache read tokens
- `timestamp` - For time-based filtering
- `type: model_change` - For model tracking

## Testing

To test the analytics endpoint:
```bash
curl http://localhost:3100/api/analytics?range=7&agent=all
```

To test the page, navigate to:
```
http://localhost:3100/analytics.html
```

## Next Steps (Optional Enhancements)
- Export to CSV/JSON
- Cost projections/forecasting
- Cost alerts/budgets
- Per-session drill-down
- Model cost comparison
- Cost per channel breakdown

## Notes
- All costs are estimates based on token usage
- Cache reads are tracked separately (they're cheaper)
- Shared gateway costs are not double-counted
- Old sessions are filtered by file mtime for performance
