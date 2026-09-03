# NEXUS-STRIKE Web Dashboard

A Strix-style local security platform interface for NEXUS-STRIKE.

## Features

- **Dashboard**: Real-time security score, severity breakdown, and agent topology graph.
- **Reports**: In-browser PDF viewing and JSON report inspection.
- **Live scan progress**: WebSocket streaming of scan output as it runs.
- **Local & Secure**: Binds to `127.0.0.1` by default; set `NEXUS_ENV=production` to
  require a dashboard token (see [Security](#security) below) before anything else.

## Installation

```bash
pip install fastapi uvicorn[standard] websockets
```

## Usage

1. Start the dashboard server:
   ```bash
   python web/server.py
   ```
2. Open your browser and navigate to:
   ```
   http://127.0.0.1:8765
   ```

## Security

- Set `NEXUS_DASHBOARD_TOKEN` to require `Authorization: Bearer <token>` on every
  `/api/*` route and both WebSocket endpoints. **Required** when `NEXUS_ENV=production`
  — the server refuses to start without one in that mode.
- State-changing `POST` routes also require an `X-Requested-With: NEXUS-Dashboard`
  header (the bundled frontend sends this automatically) as a lightweight CSRF
  defense appropriate for this token-authenticated JSON API.
- CORS is same-origin-only by default; set `NEXUS_DASHBOARD_CORS_ORIGINS`
  (comma-separated) to allow specific additional origins.
- `/api/scan/start` requires `NEXUS_LEGAL_ACK` to already be set in the server's
  environment — it is not auto-injected per request.

## API Endpoints

- `GET /api/stats` — dashboard statistics from the latest scan.
- `GET /api/reports` — list all available PDF/JSON reports.
- `GET /api/reports/{filename}` — serve a specific report file.
- `GET /api/agents` — agents grouped by tier.
- `GET /api/skills` — registered skills.
- `GET /api/tools` — tool counts grouped by domain.
- `GET /api/findings` — findings from the most recent JSON report.
- `GET|POST /api/config` — read platform config (POST is a placeholder; not yet persisted).
- `POST /api/scan/start` — launch a scan against `{"target": "..."}`.
- `POST /api/scan/stop` — terminate the active scan.
- `GET /api/scan/status` — current scan status.
- `WS /ws/scan` — real-time scan progress/output streaming.
- `WS /ws/steer` — accepted for future live scan steering; currently
  acknowledges messages only and does not act on them.