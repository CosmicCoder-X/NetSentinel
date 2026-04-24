from __future__ import annotations

import json
from pathlib import Path

from .models import Alert


class AlertLogger:
    def __init__(self, path: Path, append: bool = False):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not append:
            self.path.write_text("", encoding="utf-8")

    def write(self, alert: Alert) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert_to_dict(alert)) + "\n")


def alert_to_dict(alert: Alert) -> dict[str, object]:
    return {
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
