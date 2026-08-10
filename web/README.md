# NEXUS-STRIKE Web Dashboard

A Strix-style local security platform interface for NEXUS-STRIKE.

## Features

- **Dashboard**: Real-time security score, severity breakdown, and agent topology graph.
- **Reports**: In-browser PDF viewing and JSON report inspection.
- **Live Steering**: WebSocket endpoint for real-time scan control.
- **Local & Secure**: Binds to `127.0.0.1` by default.

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

## API Endpoints

- `GET /api/stats`: Get dashboard statistics from the latest scan.
- `GET /api/reports`: List all available PDF and JSON reports.
- `GET /api/reports/{filename}`: Serve a specific report file.
- `WS /ws/steer`: WebSocket endpoint for live scan steering.