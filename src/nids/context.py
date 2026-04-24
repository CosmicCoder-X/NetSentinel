from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network

from .models import FlowRecord


@dataclass(slots=True)
class NetworkContext:
    internal_networks: tuple[object, ...]
    critical_assets: frozenset[str]
    approved_scanners: frozenset[str]
    authorized_dns_servers: frozenset[str]
    authorized_dhcp_servers: frozenset[str]
    suspicious_ja3: frozenset[str]

    @classmethod
    def from_config(cls, config: dict) -> "NetworkContext":
        assets = config.get("assets", {})
        return cls(
            internal_networks=tuple(
                ip_network(item) for item in assets.get("internal_cidrs", ["10.0.0.0/8"])
            ),
            critical_assets=frozenset(assets.get("critical_assets", [])),
            approved_scanners=frozenset(assets.get("approved_scanners", [])),
            authorized_dns_servers=frozenset(assets.get("authorized_dns_servers", [])),
            authorized_dhcp_servers=frozenset(assets.get("authorized_dhcp_servers", [])),
            suspicious_ja3=frozenset(assets.get("suspicious_ja3", [])),
        )

    def is_internal(self, ip_value: str) -> bool:
        try:
            parsed = ip_address(ip_value)
        except ValueError:
            return False
        return any(parsed in network for network in self.internal_networks)

    def is_external_to_internal(self, flow: FlowRecord) -> bool:
        return not self.is_internal(flow.src_ip) and self.is_internal(flow.dst_ip)

    def is_internal_to_external(self, flow: FlowRecord) -> bool:
        return self.is_internal(flow.src_ip) and not self.is_internal(flow.dst_ip)

    def destination_is_critical(self, flow: FlowRecord) -> bool:
        return flow.dst_ip in self.critical_assets

    def source_is_approved_scanner(self, flow: FlowRecord) -> bool:
        return flow.src_ip in self.approved_scanners
