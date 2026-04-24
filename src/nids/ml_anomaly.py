from __future__ import annotations

from dataclasses import dataclass, field
from math import sqrt

from .models import Alert, FlowRecord


@dataclass(slots=True)
class OnlineAnomalyModel:
    warmup_samples: int = 150
    threshold: float = 8.0
    count: int = 0
    means: list[float] = field(default_factory=list)
    m2: list[float] = field(default_factory=list)

    def evaluate(self, flow: FlowRecord, sequence: int) -> Alert | None:
        vector = _feature_vector(flow)
        if not self.means:
            self.means = [0.0 for _ in vector]
            self.m2 = [0.0 for _ in vector]

        score = self._distance(vector) if self.count >= self.warmup_samples else 0.0
        self._learn(vector)

        if score < self.threshold:
            return None

        return Alert(
            alert_id=f"ML-{sequence:04d}",
            timestamp=flow.timestamp,
            severity="medium" if score < self.threshold * 1.5 else "high",
            category="ml_anomaly",
            title="Online anomaly model outlier",
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            confidence=min(0.55 + score / 20, 0.9),
            reasons=[f"online feature-distance score {score:.2f} exceeded threshold"],
            evidence={
                "score": round(score, 2),
                "threshold": self.threshold,
                "app": flow.app,
                "protocol": flow.protocol,
                "dst_port": flow.dst_port,
                "bytes_out": flow.bytes_out,
                "bytes_in": flow.bytes_in,
                "packets_out": flow.packets_out,
            },
        )

    def _distance(self, vector: list[float]) -> float:
        total = 0.0
        for index, value in enumerate(vector):
            variance = self.m2[index] / max(self.count - 1, 1)
            deviation = sqrt(max(variance, 1.0))
            total += ((value - self.means[index]) / deviation) ** 2
        return sqrt(total)

    def _learn(self, vector: list[float]) -> None:
        self.count += 1
        for index, value in enumerate(vector):
            delta = value - self.means[index]
            self.means[index] += delta / self.count
            delta2 = value - self.means[index]
            self.m2[index] += delta * delta2


def _feature_vector(flow: FlowRecord) -> list[float]:
    return [
        float(flow.bytes_out),
        float(flow.bytes_in),
        float(flow.packets_out),
        float(flow.packets_in),
        float(flow.duration_ms),
        float(flow.dst_port),
        float(len(flow.dns_query)),
        float(len(flow.http_uri)),
    ]
