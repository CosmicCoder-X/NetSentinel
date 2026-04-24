from __future__ import annotations

from collections import defaultdict

from .context import NetworkContext
from .models import Alert, FlowRecord


class ProtocolHeuristicDetector:
    def __init__(self, config: dict, context: NetworkContext):
        self.config = config.get("protocol_heuristics", {})
        self.context = context

    def evaluate(self, flows: list[FlowRecord], start_sequence: int) -> list[Alert]:
        alerts: list[Alert] = []
        sequence = start_sequence
        scan_state: dict[str, set[str]] = defaultdict(set)
        icmp_state: dict[str, set[str]] = defaultdict(set)
        failed_auth_state: dict[tuple[str, str, int], int] = defaultdict(int)

        for flow in flows:
            findings = self._flow_findings(flow)
            self._update_state(flow, scan_state, icmp_state, failed_auth_state, findings)

            if findings:
                alerts.append(self._to_alert(flow, sequence, findings))
                sequence += 1

        return alerts

    def _flow_findings(self, flow: FlowRecord) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []
        app = flow.app.lower()

        if app in {"http", "https"}:
            findings.extend(self._http_findings(flow))
        if app in {"https", "tls"} or flow.dst_port == 443:
            findings.extend(self._tls_findings(flow))
        if app == "dns" or flow.dst_port == 53:
            findings.extend(self._dns_findings(flow))
        if app == "smb" or flow.dst_port in {139, 445}:
            findings.extend(self._smb_findings(flow))
        if app == "rdp" or flow.dst_port == 3389:
            findings.extend(self._rdp_findings(flow))
        if app == "ssh" or flow.dst_port == 22:
            findings.extend(self._ssh_findings(flow))
        if flow.protocol == "ICMP":
            findings.extend(self._icmp_findings(flow))
        if app == "dhcp" or flow.dst_port in {67, 68}:
            findings.extend(self._dhcp_findings(flow))
        if app == "smtp" or flow.dst_port == 25:
            findings.extend(self._smtp_findings(flow))
        if app == "ntp" or flow.dst_port == 123:
            findings.extend(self._ntp_findings(flow))
        if app == "ldap" or flow.dst_port in {389, 636}:
            findings.extend(self._ldap_findings(flow))

        return findings

    def _update_state(
        self,
        flow: FlowRecord,
        scan_state: dict[str, set[str]],
        icmp_state: dict[str, set[str]],
        failed_auth_state: dict[tuple[str, str, int], int],
        findings: list[dict[str, object]],
    ) -> None:
        if flow.protocol == "TCP" and not self.context.source_is_approved_scanner(flow):
            scan_key = f"{flow.dst_ip}:{flow.dst_port}"
            scan_state[flow.src_ip].add(scan_key)
            if len(scan_state[flow.src_ip]) >= int(self.config.get("scan_distinct_services", 5)):
                findings.append(
                    self._finding(
                        "Lateral movement probe",
                        "source contacted many distinct internal services",
                        "high",
                        0.82,
                        {"distinct_services": len(scan_state[flow.src_ip])},
                    )
                )

        if flow.protocol == "ICMP" and flow.icmp_type == 8:
            icmp_state[flow.src_ip].add(flow.dst_ip)
            if len(icmp_state[flow.src_ip]) >= int(self.config.get("icmp_sweep_hosts", 4)):
                findings.append(
                    self._finding(
                        "ICMP sweep",
                        "echo requests touched many hosts",
                        "medium",
                        0.68,
                        {"distinct_hosts": len(icmp_state[flow.src_ip])},
                    )
                )

        if flow.auth_result.lower() == "failed" and flow.dst_port in {22, 3389, 389, 636}:
            key = (flow.src_ip, flow.dst_ip, flow.dst_port)
            failed_auth_state[key] += 1
            if failed_auth_state[key] >= int(self.config.get("failed_auth_threshold", 3)):
                findings.append(
                    self._finding(
                        "Repeated failed authentication",
                        "multiple failed logins against the same service",
                        "high",
                        0.8,
                        {"failed_attempts": failed_auth_state[key]},
                    )
                )

    def _http_findings(self, flow: FlowRecord) -> list[dict[str, object]]:
        uri = flow.http_uri.lower()
        user_agent = flow.user_agent.lower()
        exploit_terms = ("../", "%2e%2e", "wp-admin", "phpmyadmin", "cmd=", "union+select", "etc/passwd")
        scanner_agents = ("sqlmap", "nikto", "nmap", "masscan", "python-requests", "curl")
        findings = []
        if any(term in uri for term in exploit_terms):
            findings.append(self._finding("HTTP exploit attempt", "URI contains exploit-like payload markers", "high", 0.84, {"uri": flow.http_uri}))
        if user_agent and any(agent in user_agent for agent in scanner_agents):
            findings.append(self._finding("Suspicious HTTP client", "user agent is commonly used by scanners or automation", "medium", 0.65, {"user_agent": flow.user_agent}))
        if flow.http_method.upper() in {"PUT", "DELETE", "TRACE"} and self.context.destination_is_critical(flow):
            findings.append(self._finding("Risky HTTP method", "write-capable method targeted a critical asset", "high", 0.78, {"method": flow.http_method}))
        return findings

    def _tls_findings(self, flow: FlowRecord) -> list[dict[str, object]]:
        findings = []
        if flow.tls_ja3 and flow.tls_ja3 in self.context.suspicious_ja3:
            findings.append(self._finding("Suspicious TLS fingerprint", "JA3 fingerprint matches configured threat profile", "high", 0.86, {"ja3": flow.tls_ja3}))
        if flow.tls_version in {"SSLv3", "TLS1.0", "TLS1.1"}:
            findings.append(self._finding("Deprecated TLS version", "legacy TLS version increases downgrade and interception risk", "medium", 0.62, {"tls_version": flow.tls_version}))
        if not flow.tls_sni and self.context.is_internal_to_external(flow) and flow.bytes_out > 500_000:
            findings.append(self._finding("Opaque TLS egress", "large outbound TLS flow has no SNI for attribution", "medium", 0.66, {"bytes_out": flow.bytes_out}))
        return findings

    def _dns_findings(self, flow: FlowRecord) -> list[dict[str, object]]:
        findings = []
        labels = [label for label in flow.dns_query.split(".") if label]
        longest = max((len(label) for label in labels), default=0)
        if flow.dst_ip not in self.context.authorized_dns_servers and self.context.is_internal(flow.src_ip):
            findings.append(self._finding("Unapproved DNS resolver", "internal host queried a DNS server outside the approved resolver set", "medium", 0.7, {"resolver": flow.dst_ip}))
        if longest >= int(self.config.get("dns_long_label_len", 35)):
            findings.append(self._finding("Encoded DNS label", "DNS query contains an unusually long label", "high", 0.82, {"longest_label": longest}))
        return findings

    def _smb_findings(self, flow: FlowRecord) -> list[dict[str, object]]:
        findings = []
        admin_shares = {"admin$", "c$", "ipc$"}
        if self.context.is_external_to_internal(flow):
            findings.append(self._finding("External SMB access", "external source attempted SMB access to an internal host", "critical", 0.9, {"dst_port": flow.dst_port}))
        if flow.smb_share.lower() in admin_shares and not self.context.source_is_approved_scanner(flow):
            findings.append(self._finding("Administrative SMB share access", "SMB flow referenced an administrative share", "high", 0.78, {"share": flow.smb_share}))
        return findings

    def _rdp_findings(self, flow: FlowRecord) -> list[dict[str, object]]:
        if self.context.is_external_to_internal(flow):
            return [self._finding("External RDP attempt", "RDP was attempted from outside internal networks", "high", 0.8, {"dst_port": flow.dst_port})]
        return []

    def _ssh_findings(self, flow: FlowRecord) -> list[dict[str, object]]:
        if flow.auth_result.lower() == "failed" and flow.packets_out >= 18:
            return [self._finding("SSH brute-force pressure", "failed SSH flow carried elevated packet volume", "high", 0.79, {"packets_out": flow.packets_out})]
        return []

    def _icmp_findings(self, flow: FlowRecord) -> list[dict[str, object]]:
        if flow.packets_out >= int(self.config.get("icmp_packet_burst", 20)):
            return [self._finding("ICMP burst", "high-volume echo traffic may indicate reconnaissance or tunneling", "medium", 0.63, {"packets_out": flow.packets_out})]
        return []

    def _dhcp_findings(self, flow: FlowRecord) -> list[dict[str, object]]:
        if flow.dhcp_message.upper() in {"OFFER", "ACK"} and flow.src_ip not in self.context.authorized_dhcp_servers:
            return [self._finding("Rogue DHCP server", "DHCP offer or acknowledgement came from an unauthorized server", "critical", 0.92, {"dhcp_message": flow.dhcp_message})]
        return []

    def _smtp_findings(self, flow: FlowRecord) -> list[dict[str, object]]:
        if self.context.is_internal_to_external(flow) and flow.dst_port == 25 and flow.packets_out >= 100:
            return [self._finding("Possible SMTP spam relay", "internal host sent high-volume outbound SMTP directly to the internet", "high", 0.77, {"packets_out": flow.packets_out})]
        return []

    def _ntp_findings(self, flow: FlowRecord) -> list[dict[str, object]]:
        ratio = flow.bytes_in / max(flow.bytes_out, 1)
        if flow.protocol == "UDP" and flow.dst_port == 123 and ratio >= 20:
            return [self._finding("NTP amplification pattern", "NTP response volume greatly exceeded request volume", "medium", 0.64, {"response_ratio": round(ratio, 2)})]
        return []

    def _ldap_findings(self, flow: FlowRecord) -> list[dict[str, object]]:
        if self.context.is_external_to_internal(flow):
            return [self._finding("External LDAP access", "directory service reached from outside internal networks", "high", 0.76, {"dst_port": flow.dst_port})]
        return []

    def _to_alert(self, flow: FlowRecord, sequence: int, findings: list[dict[str, object]]) -> Alert:
        confidence = min(sum(float(item["confidence"]) for item in findings) / len(findings) + (len(findings) - 1) * 0.05, 0.98)
        severity = _max_severity(str(item["severity"]) for item in findings)
        if severity == "critical" and len(findings) == 1 and confidence < 0.95:
            severity = "high"
        evidence: dict[str, object] = {
            "protocol": flow.protocol,
            "app": flow.app,
            "dst_port": flow.dst_port,
            "findings": [item["title"] for item in findings],
        }
        for item in findings:
            evidence.update(item["evidence"])
        return Alert(
            alert_id=f"PROTO-{sequence:04d}",
            timestamp=flow.timestamp,
            severity=severity,
            category="protocol",
            title="Protocol-aware threat indicator",
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            confidence=confidence,
            reasons=[str(item["reason"]) for item in findings],
            evidence=evidence,
        )

    def _finding(self, title: str, reason: str, severity: str, confidence: float, evidence: dict[str, object]) -> dict[str, object]:
        return {
            "title": title,
            "reason": reason,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
        }


def _max_severity(values) -> str:
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return max(values, key=lambda item: rank[item])
