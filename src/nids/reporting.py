from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from .models import Alert, DetectionReport, FlowRecord


def build_report(flows: list[FlowRecord], alerts: list[Alert]) -> DetectionReport:
    return DetectionReport(
        generated_at=datetime.now(),
        processed_flows=len(flows),
        alerts=sorted(alerts, key=lambda item: (item.timestamp, item.alert_id)),
        severity_counts=dict(Counter(alert.severity for alert in alerts)),
        category_counts=dict(Counter(alert.category for alert in alerts)),
        protocol_counts=dict(Counter(flow.app or flow.protocol for flow in flows)),
        top_talkers=_top_talkers(flows),
    )


def write_report(report: DetectionReport, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"nids_report_{report.generated_at.strftime('%Y%m%d_%H%M%S')}"
    json_path = output_dir / f"{stem}.json"
    html_path = output_dir / f"{stem}.html"
    json_path.write_text(json.dumps(_report_to_dict(report), indent=2), encoding="utf-8")
    html_path.write_text(_render_html(report), encoding="utf-8")
    return json_path, html_path


def _top_talkers(flows: list[FlowRecord]) -> list[dict[str, object]]:
    totals: dict[str, int] = {}
    for flow in flows:
        totals[flow.src_ip] = totals.get(flow.src_ip, 0) + flow.total_bytes
    top = sorted(totals.items(), key=lambda item: item[1], reverse=True)[:5]
    return [{"src_ip": src_ip, "total_bytes": total_bytes} for src_ip, total_bytes in top]


def _report_to_dict(report: DetectionReport) -> dict[str, object]:
    return {
        "generated_at": report.generated_at.isoformat(),
        "processed_flows": report.processed_flows,
        "severity_counts": report.severity_counts,
        "category_counts": report.category_counts,
        "protocol_counts": report.protocol_counts,
        "top_talkers": report.top_talkers,
        "alerts": [
            {
                "alert_id": alert.alert_id,
                "timestamp": alert.timestamp.isoformat(),
                "severity": alert.severity,
                "category": alert.category,
                "title": alert.title,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "confidence": round(alert.confidence, 2),
                "reasons": alert.reasons,
                "evidence": alert.evidence,
            }
            for alert in report.alerts
        ],
    }


def _render_html(report: DetectionReport) -> str:
    cards = "".join(
        f"<div class='card'><span>{label}</span><strong>{value}</strong></div>"
        for label, value in [
            ("Flows Processed", report.processed_flows),
            ("Alerts Raised", len(report.alerts)),
            ("Critical Alerts", report.severity_counts.get("critical", 0)),
            ("Protocols Seen", len(report.protocol_counts)),
        ]
    )
    rows = "".join(
        "<tr>"
        f"<td>{alert.timestamp.isoformat(sep=' ', timespec='seconds')}</td>"
        f"<td>{alert.alert_id}</td>"
        f"<td>{alert.severity.upper()}</td>"
        f"<td>{alert.confidence:.2f}</td>"
        f"<td>{alert.category}</td>"
        f"<td>{alert.src_ip}</td>"
        f"<td>{alert.dst_ip}</td>"
        f"<td>{alert.title}</td>"
        f"<td>{'; '.join(alert.reasons)}</td>"
        "</tr>"
        for alert in report.alerts
    )
    talkers = "".join(
        f"<li><strong>{item['src_ip']}</strong><span>{item['total_bytes']:,} bytes</span></li>"
        for item in report.top_talkers
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>NIDS Report</title>
  <style>
    :root {{
      --bg: #0f172a;
      --panel: #111827;
      --panel-alt: #172033;
      --text: #e5eef9;
      --muted: #98a7c2;
      --accent: #f97316;
      --danger: #ef4444;
      --ok: #22c55e;
      --line: rgba(148, 163, 184, 0.16);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, sans-serif;
      background:
        radial-gradient(circle at top left, rgba(249, 115, 22, 0.18), transparent 26%),
        linear-gradient(180deg, #020617 0%, var(--bg) 100%);
      color: var(--text);
    }}
    .wrap {{ width: min(1180px, calc(100% - 32px)); margin: 32px auto; }}
    .hero {{
      background: linear-gradient(135deg, rgba(249,115,22,0.18), rgba(17,24,39,0.92));
      border: 1px solid var(--line);
      border-radius: 24px;
      padding: 28px;
      margin-bottom: 24px;
    }}
    .hero h1 {{ margin: 0 0 8px; font-size: 32px; }}
    .hero p {{ margin: 0; color: var(--muted); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .card, .panel {{
      background: rgba(17, 24, 39, 0.82);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 20px;
      backdrop-filter: blur(10px);
    }}
    .card span {{ display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
    .card strong {{ display: block; margin-top: 12px; font-size: 30px; }}
    .two-up {{
      display: grid;
      grid-template-columns: 320px 1fr;
      gap: 24px;
      margin-bottom: 24px;
    }}
    ul {{ list-style: none; margin: 0; padding: 0; }}
    li {{
      display: flex;
      justify-content: space-between;
      padding: 12px 0;
      border-bottom: 1px solid var(--line);
      color: var(--muted);
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{
      text-align: left;
      padding: 12px 10px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      font-size: 14px;
    }}
    th {{ color: var(--muted); font-weight: 600; }}
    .footer {{ color: var(--muted); font-size: 13px; margin-top: 18px; }}
    @media (max-width: 900px) {{
      .two-up {{ grid-template-columns: 1fr; }}
      .hero h1 {{ font-size: 26px; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>Network Intrusion Detection Report</h1>
      <p>Generated {report.generated_at.isoformat(sep=' ', timespec='seconds')} with layered signature, anomaly, and campaign correlation analytics.</p>
    </section>
    <section class="grid">{cards}</section>
    <section class="two-up">
      <div class="panel">
        <h2>Top Talkers</h2>
        <ul>{talkers}</ul>
      </div>
      <div class="panel">
        <h2>Alert Distribution</h2>
        <ul>
          <li><strong>Severity</strong><span>{json.dumps(report.severity_counts)}</span></li>
          <li><strong>Category</strong><span>{json.dumps(report.category_counts)}</span></li>
          <li><strong>Protocols</strong><span>{json.dumps(report.protocol_counts)}</span></li>
        </ul>
      </div>
    </section>
    <section class="panel">
      <h2>Alert Timeline</h2>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>ID</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>Category</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Title</th>
            <th>Reasons</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
      <div class="footer">This sample project analyzes flow records rather than full packet payloads, making it lightweight and practical for baseline detection engineering.</div>
    </section>
  </div>
</body>
</html>
"""
