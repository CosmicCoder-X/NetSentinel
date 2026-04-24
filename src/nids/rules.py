from __future__ import annotations

from dataclasses import dataclass

from .models import Alert, FlowRecord

SEVERITY_SCORE = {
    "low": 0.35,
    "medium": 0.55,
    "high": 0.75,
    "critical": 0.92,
}


@dataclass(slots=True)
class SignatureRule:
    rule_id: str
    name: str
    description: str
    severity: str
    conditions: dict[str, object]

    def match(self, flow: FlowRecord) -> bool:
        for key, value in self.conditions.items():
            if key == "protocol" and flow.protocol != value:
                return False
            if key == "app" and flow.app.lower() != str(value).lower():
                return False
            if key == "dst_port_in" and flow.dst_port not in value:
                return False
            if key == "src_port_in" and flow.src_port not in value:
                return False
            if key == "bytes_out_gte" and flow.bytes_out < value:
                return False
            if key == "bytes_in_gte" and flow.bytes_in < value:
                return False
            if key == "bytes_in_lte" and flow.bytes_in > value:
                return False
            if key == "packets_out_gte" and flow.packets_out < value:
                return False
            if key == "packets_in_gte" and flow.packets_in < value:
                return False
            if key == "packets_in_lte" and flow.packets_in > value:
                return False
            if key == "duration_ms_gte" and flow.duration_ms < value:
                return False
            if key == "tcp_flags_contains" and str(value) not in flow.tcp_flags:
                return False
            if key == "dns_query_len_gte" and len(flow.dns_query) < value:
                return False
            if key == "http_status_in" and flow.http_status not in value:
                return False
            if key == "auth_result" and flow.auth_result.lower() != str(value).lower():
                return False
        return True

    def to_alert(self, flow: FlowRecord, sequence: int) -> Alert:
        return Alert(
            alert_id=f"{self.rule_id}-{sequence:04d}",
            timestamp=flow.timestamp,
            severity=self.severity,
            category="signature",
            title=self.name,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            confidence=SEVERITY_SCORE[self.severity],
            reasons=[self.description],
            evidence={
                "rule_id": self.rule_id,
                "protocol": flow.protocol,
                "dst_port": flow.dst_port,
                "bytes_out": flow.bytes_out,
                "packets_out": flow.packets_out,
            },
        )


def load_rules(config: dict) -> list[SignatureRule]:
    return [
        SignatureRule(
            rule_id=item["rule_id"],
            name=item["name"],
            description=item["description"],
            severity=item["severity"],
            conditions=item["conditions"],
        )
        for item in config.get("rules", [])
    ]
