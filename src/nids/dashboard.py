from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread


class DashboardServer:
    def __init__(self, host: str, port: int, alert_log: Path):
        self.host = host
        self.port = port
        self.alert_log = alert_log
        self.server = ThreadingHTTPServer((host, port), self._handler())
        self.thread = Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> str:
        self.thread.start()
        return f"http://{self.host}:{self.port}"

    def stop(self) -> None:
        self.server.shutdown()

    def _handler(self):
        alert_log = self.alert_log

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/api/alerts":
                    self._send_json(_read_recent_alerts(alert_log))
                    return
                self._send_html(_dashboard_html())

            def log_message(self, format: str, *args) -> None:
                return

            def _send_json(self, payload: object) -> None:
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _send_html(self, html: str) -> None:
                raw = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        return Handler


def _read_recent_alerts(path: Path, limit: int = 200) -> list[dict[str, object]]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
    alerts = []
    for line in lines:
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return alerts


def _dashboard_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Live NIDS Dashboard</title>
  <style>
    :root {
      --bg: #101314;
      --panel: #f4efe7;
      --ink: #17201d;
      --muted: #65716c;
      --line: #d8cec1;
      --critical: #b42318;
      --high: #b54708;
      --medium: #175cd3;
      --low: #067647;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: #101314;
      color: var(--ink);
      font-family: "Segoe UI", Tahoma, sans-serif;
    }
    header {
      color: #fff7ed;
      padding: 24px clamp(16px, 4vw, 48px);
      border-bottom: 1px solid rgba(255,255,255,0.14);
    }
    header h1 { margin: 0 0 6px; font-size: 28px; }
    header p { margin: 0; color: #c7d2c9; }
    main {
      padding: 24px clamp(16px, 4vw, 48px);
      display: grid;
      grid-template-columns: 280px 1fr;
      gap: 18px;
    }
    .metric, .table-wrap {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
    }
    .metric { margin-bottom: 12px; }
    .metric span {
      display: block;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .metric strong { display: block; margin-top: 8px; font-size: 28px; }
    table { width: 100%; border-collapse: collapse; }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 10px;
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .sev { font-weight: 700; }
    .critical { color: var(--critical); }
    .high { color: var(--high); }
    .medium { color: var(--medium); }
    .low { color: var(--low); }
    @media (max-width: 880px) {
      main { grid-template-columns: 1fr; }
      table { min-width: 820px; }
      .table-wrap { overflow-x: auto; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Live Network Intrusion Detection</h1>
    <p id="status">Waiting for alerts...</p>
  </header>
  <main>
    <aside>
      <div class="metric"><span>Total Alerts</span><strong id="total">0</strong></div>
      <div class="metric"><span>Critical</span><strong id="critical">0</strong></div>
      <div class="metric"><span>High</span><strong id="high">0</strong></div>
      <div class="metric"><span>Last Refresh</span><strong id="refresh">-</strong></div>
    </aside>
    <section class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Category</th>
            <th>Alert</th>
          </tr>
        </thead>
        <tbody id="alerts"></tbody>
      </table>
    </section>
  </main>
  <script>
    async function refresh() {
      const res = await fetch('/api/alerts', { cache: 'no-store' });
      const alerts = await res.json();
      const counts = alerts.reduce((acc, alert) => {
        acc[alert.severity] = (acc[alert.severity] || 0) + 1;
        return acc;
      }, {});
      document.getElementById('total').textContent = alerts.length;
      document.getElementById('critical').textContent = counts.critical || 0;
      document.getElementById('high').textContent = counts.high || 0;
      document.getElementById('refresh').textContent = new Date().toLocaleTimeString();
      document.getElementById('status').textContent = alerts.length ? 'Monitoring live packet capture' : 'Monitoring live packet capture, no alerts yet';
      document.getElementById('alerts').innerHTML = alerts.slice().reverse().map(alert => `
        <tr>
          <td>${alert.timestamp}</td>
          <td class="sev ${alert.severity}">${alert.severity.toUpperCase()}</td>
          <td>${alert.confidence}</td>
          <td>${alert.src_ip}</td>
          <td>${alert.dst_ip}</td>
          <td>${alert.category}</td>
          <td><strong>${alert.title}</strong><br>${alert.reasons.join('; ')}</td>
        </tr>
      `).join('');
    }
    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
"""
