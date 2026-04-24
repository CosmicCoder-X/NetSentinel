from __future__ import annotations

from .anomaly import AnomalyDetector
from .context import NetworkContext
from .correlation import correlate_alerts
from .models import Alert, FlowRecord
from .precision import refine_alerts
from .protocols import ProtocolHeuristicDetector
from .rules import load_rules


class DetectionEngine:
    def __init__(self, config: dict):
        self.config = config
        self.context = NetworkContext.from_config(config)
        self.rules = load_rules(config)
        self.protocol_detector = ProtocolHeuristicDetector(config, self.context)
        self.anomaly_detector = AnomalyDetector(
            baseline_window=int(config.get("baseline_window", 10)),
            zscore_threshold=float(config.get("anomaly_zscore_threshold", 3.0)),
        )
        self.campaign_threshold = int(config.get("campaign_alert_threshold", 3))
        self.min_confidence = float(config.get("min_confidence", 0.5))

    def analyze(self, flows: list[FlowRecord]) -> list[Alert]:
        alerts: list[Alert] = []
        sequence = 1

        signature_alerts, sequence = self.analyze_signatures(flows, sequence)
        alerts.extend(signature_alerts)

        behavioral_alerts, sequence = self.analyze_behavioral(flows, sequence)
        alerts.extend(behavioral_alerts)

        alerts = refine_alerts(alerts, self.context, min_confidence=self.min_confidence)

        correlation_alerts = correlate_alerts(
            alerts,
            threshold=self.campaign_threshold,
            start_sequence=sequence,
        )
        alerts.extend(correlation_alerts)
        return refine_alerts(alerts, self.context, min_confidence=self.min_confidence)

    def analyze_signatures(self, flows: list[FlowRecord], start_sequence: int = 1) -> tuple[list[Alert], int]:
        alerts: list[Alert] = []
        sequence = start_sequence
        for flow in flows:
            for rule in self.rules:
                if rule.match(flow):
                    alerts.append(rule.to_alert(flow, sequence))
                    sequence += 1
        return refine_alerts(alerts, self.context, min_confidence=self.min_confidence), sequence

    def analyze_behavioral(self, flows: list[FlowRecord], start_sequence: int = 1) -> tuple[list[Alert], int]:
        alerts: list[Alert] = []
        sequence = start_sequence
        anomaly_alerts = self.anomaly_detector.evaluate(flows, start_sequence=sequence)
        alerts.extend(anomaly_alerts)
        sequence += len(anomaly_alerts)

        protocol_alerts = self.protocol_detector.evaluate(flows, start_sequence=sequence)
        alerts.extend(protocol_alerts)
        sequence += len(protocol_alerts)
        return refine_alerts(alerts, self.context, min_confidence=self.min_confidence), sequence
