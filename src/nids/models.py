from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class FlowRecord:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_out: int
    bytes_in: int
    packets_out: int
    packets_in: int
    duration_ms: int
    tcp_flags: str = ""
    dns_query: str = ""
    http_method: str = ""
    http_uri: str = ""
    http_status: int = 0
    user_agent: str = ""
    tls_sni: str = ""
    tls_ja3: str = ""
    tls_version: str = ""
    smb_command: str = ""
    smb_share: str = ""
    rdp_event: str = ""
    icmp_type: int = -1
    icmp_code: int = -1
    dhcp_message: str = ""
    auth_result: str = ""
    country: str = ""
    app: str = "unknown"

    @property
    def total_bytes(self) -> int:
        return self.bytes_out + self.bytes_in

    @property
    def total_packets(self) -> int:
        return self.packets_out + self.packets_in


@dataclass(slots=True)
class Alert:
    alert_id: str
    timestamp: datetime
    severity: str
    category: str
    title: str
    src_ip: str
    dst_ip: str
    confidence: float
    reasons: list[str] = field(default_factory=list)
    evidence: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class DetectionReport:
    generated_at: datetime
    processed_flows: int
    alerts: list[Alert]
    severity_counts: dict[str, int]
    category_counts: dict[str, int]
    protocol_counts: dict[str, int]
    top_talkers: list[dict[str, object]]
