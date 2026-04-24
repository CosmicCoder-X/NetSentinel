from __future__ import annotations

import json
from pathlib import Path

from .models import FlowRecord


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_flows(path: Path) -> list[FlowRecord]:
    records: list[FlowRecord] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        item = json.loads(line)
        records.append(
            FlowRecord(
                timestamp=_parse_timestamp(item["timestamp"]),
                src_ip=item["src_ip"],
                dst_ip=item["dst_ip"],
                src_port=int(item["src_port"]),
                dst_port=int(item["dst_port"]),
                protocol=str(item["protocol"]).upper(),
                bytes_out=int(item["bytes_out"]),
                bytes_in=int(item["bytes_in"]),
                packets_out=int(item["packets_out"]),
                packets_in=int(item["packets_in"]),
                duration_ms=int(item["duration_ms"]),
                tcp_flags=str(item.get("tcp_flags", "")),
                dns_query=str(item.get("dns_query", "")),
                http_method=str(item.get("http_method", "")),
                http_uri=str(item.get("http_uri", "")),
                http_status=int(item.get("http_status", 0)),
                user_agent=str(item.get("user_agent", "")),
                tls_sni=str(item.get("tls_sni", "")),
                tls_ja3=str(item.get("tls_ja3", "")),
                tls_version=str(item.get("tls_version", "")),
                smb_command=str(item.get("smb_command", "")),
                smb_share=str(item.get("smb_share", "")),
                rdp_event=str(item.get("rdp_event", "")),
                icmp_type=int(item.get("icmp_type", -1)),
                icmp_code=int(item.get("icmp_code", -1)),
                dhcp_message=str(item.get("dhcp_message", "")),
                auth_result=str(item.get("auth_result", "")),
                country=str(item.get("country", "")),
                app=str(item.get("app", "unknown")),
            )
        )
    return records


def _parse_timestamp(value: str):
    return __import__("datetime").datetime.fromisoformat(value)
