from __future__ import annotations

from collections import defaultdict
from statistics import mean, pstdev

from .models import Alert, FlowRecord

SEVERITY_ORDER = ("low", "medium", "high", "critical")


class AnomalyDetector:
    def __init__(self, baseline_window: int, zscore_threshold: float):
        self.baseline_window = baseline_window
        self.zscore_threshold = zscore_threshold

    def evaluate(self, flows: list[FlowRecord], start_sequence: int) -> list[Alert]:
        baseline = flows[: self.baseline_window]
        monitored = flows[self.baseline_window :]
        if not baseline:
            return []

        port_stats = self._build_stats(baseline)
        alerts: list[Alert] = []
        sequence = start_sequence
        recent_ports: dict[str, set[int]] = defaultdict(set)

        for flow in monitored:
            reasons: list[str] = []
            evidence: dict[str, object] = {}
            key = (flow.protocol, flow.dst_port)
            if key in port_stats:
                stats = port_stats[key]
                for metric in ("bytes_out", "duration_ms", "packets_out"):
                    score = _zscore(getattr(flow, metric), stats[metric])
                    if score >= self.zscore_threshold:
                        reasons.append(f"{metric} z-score {score:.2f} exceeded threshold")
                        evidence[f"{metric}_zscore"] = round(score, 2)

            port_bucket = recent_ports[flow.src_ip]
            port_bucket.add(flow.dst_port)
            if len(port_bucket) >= 4 and flow.protocol == "TCP":
                reasons.append("source touched at least 4 distinct destination ports")
                evidence["distinct_dst_ports"] = len(port_bucket)

            if flow.protocol == "UDP" and flow.dst_port == 53 and len(flow.dns_query) > 35:
                reasons.append("oversized DNS query consistent with covert channeling")
                evidence["dns_query_length"] = len(flow.dns_query)

            if flow.bytes_out > flow.bytes_in * 50 and flow.bytes_out > 1_000_000:
                reasons.append("egress-heavy flow suggests possible exfiltration")
                evidence["egress_ratio"] = round(flow.bytes_out / max(flow.bytes_in, 1), 2)

            if reasons:
                severity = self._severity_from_reasons(reasons)
                alerts.append(
                    Alert(
                        alert_id=f"ANOM-{sequence:04d}",
                        timestamp=flow.timestamp,
                        severity=severity,
                        category="anomaly",
                        title="Behavioral anomaly detected",
                        src_ip=flow.src_ip,
                        dst_ip=flow.dst_ip,
                        confidence=self._confidence_for_count(len(reasons)),
                        reasons=reasons,
                        evidence={
                            **evidence,
                            "protocol": flow.protocol,
                            "dst_port": flow.dst_port,
                            "bytes_out": flow.bytes_out,
                            "bytes_in": flow.bytes_in,
                        },
                    )
                )
                sequence += 1

        return alerts

    def _build_stats(self, flows: list[FlowRecord]) -> dict[tuple[str, int], dict[str, tuple[float, float]]]:
        grouped: dict[tuple[str, int], dict[str, list[float]]] = defaultdict(
            lambda: {"bytes_out": [], "duration_ms": [], "packets_out": []}
        )
        for flow in flows:
            metrics = grouped[(flow.protocol, flow.dst_port)]
            metrics["bytes_out"].append(flow.bytes_out)
            metrics["duration_ms"].append(flow.duration_ms)
            metrics["packets_out"].append(flow.packets_out)

        compiled: dict[tuple[str, int], dict[str, tuple[float, float]]] = {}
        for key, metrics in grouped.items():
            compiled[key] = {
                name: (mean(values), max(pstdev(values), 1.0))
                for name, values in metrics.items()
            }
        return compiled

    def _severity_from_reasons(self, reasons: list[str]) -> str:
        if len(reasons) >= 3:
            return "critical"
        if len(reasons) == 2:
            return "high"
        return "medium"

    def _confidence_for_count(self, count: int) -> float:
        return min(0.48 + count * 0.16, 0.95)


def _zscore(value: float, stat: tuple[float, float]) -> float:
    avg, deviation = stat
    return abs(value - avg) / deviation
