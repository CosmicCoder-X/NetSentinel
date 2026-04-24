from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from pathlib import Path

from .alert_log import AlertLogger
from .correlation import correlate_alerts
from .engine import DetectionEngine
from .live_capture import ScapyCapture, packet_to_flow
from .ml_anomaly import OnlineAnomalyModel
from .models import Alert, FlowRecord
from .precision import refine_alerts


class RealTimeNIDS:
    def __init__(
        self,
        config: dict,
        alert_log_path: Path,
        interface: str | None = None,
        bpf_filter: str = "ip or ip6",
        window_size: int = 120,
        append_alert_log: bool = False,
    ):
        self.engine = DetectionEngine(config)
        self.logger = AlertLogger(alert_log_path, append=append_alert_log)
        self.capture = ScapyCapture(interface, bpf_filter, self.handle_packet)
        self.flows: deque[FlowRecord] = deque(maxlen=window_size)
        self.active_flows: dict[tuple[object, ...], FlowRecord] = {}
        self.recent_alerts: deque[Alert] = deque(maxlen=300)
        self.seen: set[tuple[object, ...]] = set()
        self.last_seen: dict[tuple[object, ...], datetime] = {}
        self.last_emitted: dict[tuple[object, ...], datetime] = {}
        self.sequence = 1
        live_config = config.get("live", {})
        self.analysis_interval = timedelta(seconds=float(live_config.get("analysis_interval_seconds", 10)))
        self.flow_idle_timeout = timedelta(seconds=float(live_config.get("flow_idle_seconds", 12)))
        self.alert_cooldown = timedelta(seconds=float(live_config.get("alert_cooldown_seconds", 60)))
        self.last_analysis_at: datetime | None = None
        ml_config = config.get("live_ml", {})
        self.ml_model = OnlineAnomalyModel(
            warmup_samples=int(ml_config.get("warmup_samples", 150)),
            threshold=float(ml_config.get("threshold", 8.0)),
        )

    def start(self) -> None:
        self.capture.start()

    def handle_packet(self, packet) -> None:
        flow = packet_to_flow(packet)
        if flow is None:
            return

        now = flow.timestamp
        aggregated = self._aggregate_packet_flow(flow)
        self._flush_idle_flows(now)
        if self.last_analysis_at and now - self.last_analysis_at < self.analysis_interval:
            return
        self.last_analysis_at = now

        emitted: list[Alert] = []

        analysis_flows = list(self.flows) + list(self.active_flows.values())

        # Phase 1: signatures run first, but against aggregated short-lived flows.
        signature_alerts, self.sequence = self.engine.analyze_signatures([aggregated], self.sequence)
        emitted.extend(signature_alerts)

        ml_alert = self.ml_model.evaluate(aggregated, self.sequence)
        if ml_alert:
            emitted.append(ml_alert)
            self.sequence += 1

        # Phase 2: anomaly, protocol, and correlation analytics use rolling context.
        if len(analysis_flows) >= max(3, int(self.engine.config.get("baseline_window", 10))):
            behavioral_alerts, self.sequence = self.engine.analyze_behavioral(analysis_flows, self.sequence)
            emitted.extend(behavioral_alerts)

        for alert in refine_alerts(emitted, self.engine.context, self.engine.min_confidence):
            self._emit(alert)

        correlation_alerts = correlate_alerts(
            list(self.recent_alerts),
            threshold=self.engine.campaign_threshold,
            start_sequence=self.sequence,
        )
        self.sequence += len(correlation_alerts)
        for alert in refine_alerts(correlation_alerts, self.engine.context, self.engine.min_confidence):
            self._emit(alert)

    def _remember(self, alert: Alert) -> bool:
        key = (
            alert.category,
            alert.title,
            alert.src_ip,
            alert.dst_ip,
            tuple(alert.reasons),
        )
        now = alert.timestamp
        previous = self.last_emitted.get(key)
        if previous and now - previous < self.alert_cooldown:
            return False
        self.last_emitted[key] = now
        self.seen.add(key)
        return True

    def _emit(self, alert: Alert) -> None:
        if not self._remember(alert):
            return
        self.recent_alerts.append(alert)
        self.logger.write(alert)
        print(
            f"[{alert.severity.upper()}] {alert.title} "
            f"{alert.src_ip} -> {alert.dst_ip} confidence={alert.confidence:.2f}"
        )

    def _aggregate_packet_flow(self, packet_flow: FlowRecord) -> FlowRecord:
        key = (
            packet_flow.protocol,
            packet_flow.src_ip,
            packet_flow.dst_ip,
            packet_flow.src_port,
            packet_flow.dst_port,
            packet_flow.app,
        )
        existing = self.active_flows.get(key)
        self.last_seen[key] = packet_flow.timestamp
        if existing is None:
            self.active_flows[key] = packet_flow
            return packet_flow

        existing.bytes_out += packet_flow.bytes_out
        existing.bytes_in += packet_flow.bytes_in
        existing.packets_out += packet_flow.packets_out
        existing.packets_in += packet_flow.packets_in
        existing.duration_ms = max(1, int((packet_flow.timestamp - existing.timestamp).total_seconds() * 1000))
        existing.tcp_flags = "".join(sorted(set(existing.tcp_flags + packet_flow.tcp_flags)))
        existing.dns_query = existing.dns_query or packet_flow.dns_query
        existing.http_method = existing.http_method or packet_flow.http_method
        existing.http_uri = existing.http_uri or packet_flow.http_uri
        existing.user_agent = existing.user_agent or packet_flow.user_agent
        return existing

    def _flush_idle_flows(self, now: datetime) -> None:
        expired = [
            key
            for key, seen_at in self.last_seen.items()
            if now - seen_at >= self.flow_idle_timeout
        ]
        for key in expired:
            flow = self.active_flows.pop(key, None)
            self.last_seen.pop(key, None)
            if flow is not None:
                self.flows.append(flow)
