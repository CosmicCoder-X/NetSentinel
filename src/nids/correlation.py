from __future__ import annotations

from collections import Counter, defaultdict

from .models import Alert

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def correlate_alerts(alerts: list[Alert], threshold: int, start_sequence: int) -> list[Alert]:
    grouped: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        grouped[alert.src_ip].append(alert)

    campaign_alerts: list[Alert] = []
    sequence = start_sequence
    for src_ip, src_alerts in grouped.items():
        if len(src_alerts) < threshold:
            continue
        ordered = sorted(src_alerts, key=lambda item: item.timestamp)
        categories = Counter(item.category for item in ordered)
        max_severity = max(ordered, key=lambda item: SEVERITY_RANK[item.severity]).severity
        campaign_alerts.append(
            Alert(
                alert_id=f"CORR-{sequence:04d}",
                timestamp=ordered[-1].timestamp,
                severity=max_severity,
                category="correlation",
                title="Multi-stage intrusion campaign",
                src_ip=src_ip,
                dst_ip="multiple",
                confidence=min(0.6 + len(src_alerts) * 0.08, 0.98),
                reasons=[
                    f"{len(src_alerts)} alerts from the same source exceeded the campaign threshold",
                    f"alert mix: {', '.join(f'{key}={value}' for key, value in sorted(categories.items()))}",
                ],
                evidence={
                    "first_seen": ordered[0].timestamp.isoformat(),
                    "last_seen": ordered[-1].timestamp.isoformat(),
                    "related_alert_ids": [item.alert_id for item in ordered],
                },
            )
        )
        sequence += 1
    return campaign_alerts
