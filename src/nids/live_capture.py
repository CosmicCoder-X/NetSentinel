from __future__ import annotations

from datetime import datetime
from typing import Any

from .models import FlowRecord


class ScapyCapture:
    def __init__(self, interface: str | None, bpf_filter: str, packet_callback):
        self.interface = interface or None
        self.bpf_filter = bpf_filter
        self.packet_callback = packet_callback

    def start(self) -> None:
        try:
            from scapy.all import sniff
            from scapy.config import conf
        except ImportError as exc:
            raise RuntimeError(
                "Scapy is not installed. Run `pip install -e .` or `pip install scapy` first."
            ) from exc

        interface = _resolve_capture_interface(self.interface)
        _ensure_capture_backend(conf)
        sniff_args = {
            "iface": interface,
            "prn": self.packet_callback,
            "store": False,
        }
        if self.bpf_filter:
            sniff_args["filter"] = self.bpf_filter

        try:
            sniff(**sniff_args)
        except RuntimeError as exc:
            if _is_missing_windows_capture_driver(exc):
                raise RuntimeError(_windows_capture_driver_message()) from exc
            raise
        except Exception:
            if not self.bpf_filter:
                raise
            print("BPF filtering is unavailable on this system; retrying capture without --bpf.")
            sniff_args.pop("filter", None)
            sniff(**sniff_args)


def capture_backend_status() -> dict[str, object]:
    try:
        from scapy.config import conf
    except ImportError:
        return {
            "ready": False,
            "reason": "Scapy is not installed.",
        }

    l2_available = getattr(conf, "L2listen", None) is not None
    l3_available = getattr(conf, "L3socket", None) is not None
    return {
        "ready": l2_available or l3_available,
        "use_pcap": bool(getattr(conf, "use_pcap", False)),
        "use_npcap": bool(getattr(conf, "use_npcap", False)),
        "l2_available": l2_available,
        "l3_available": l3_available,
        "reason": "" if l2_available or l3_available else _windows_capture_driver_message(),
    }


def _ensure_capture_backend(conf: Any) -> None:
    l2_available = getattr(conf, "L2listen", None) is not None
    l3_available = getattr(conf, "L3socket", None) is not None
    if l2_available or l3_available:
        return
    raise RuntimeError(_windows_capture_driver_message())


def _is_missing_windows_capture_driver(exc: RuntimeError) -> bool:
    message = str(exc).lower()
    return "winpcap is not installed" in message or "not available at layer 2" in message


def _windows_capture_driver_message() -> str:
    return (
        "Scapy cannot open a live capture socket on this Windows install.\n"
        "Install or repair Npcap, then enable these installer options:\n"
        "- Install Npcap in WinPcap API-compatible Mode\n"
        "- Support loopback traffic capture, if you want local traffic too\n"
        "After installing, close this terminal, open PowerShell as Administrator, and rerun the live command.\n"
        "You can still use batch mode with sample JSONL data while capture support is unavailable."
    )


def _resolve_capture_interface(interface: str | None) -> Any:
    if not interface:
        return None

    try:
        from scapy.config import conf
    except ImportError as exc:
        raise RuntimeError("Scapy is required for live capture.") from exc

    candidates = list(conf.ifaces.values())
    requested = interface.strip()
    if requested.isdigit():
        index = int(requested)
        if 1 <= index <= len(candidates):
            return candidates[index - 1]
        raise ValueError(f"Interface index {requested} is outside the available range 1-{len(candidates)}.")

    exact_match = _match_interface(candidates, requested, exact=True)
    if exact_match is not None:
        return exact_match

    fuzzy_matches = [
        iface
        for iface in candidates
        if _normalized(requested) in _normalized(" ".join(_interface_labels(iface)))
    ]
    if len(fuzzy_matches) == 1:
        return fuzzy_matches[0]
    if len(fuzzy_matches) > 1:
        choices = "\n".join(_format_interface_choice(iface) for iface in fuzzy_matches[:8])
        raise ValueError(
            f"Interface '{interface}' matched multiple adapters. Use a number from --list-interfaces or one exact name:\n{choices}"
        )

    choices = "\n".join(_format_interface_choice(iface) for iface in candidates[:12])
    raise ValueError(
        f"Interface '{interface}' not found. Run `python .\\run_nids.py --list-interfaces` and use a number or exact name.\n"
        f"First available interfaces:\n{choices}"
    )


def _match_interface(candidates: list[Any], requested: str, exact: bool) -> Any | None:
    for iface in candidates:
        for label in _interface_labels(iface):
            if exact and label == requested:
                return iface
            if not exact and _normalized(label) == _normalized(requested):
                return iface
    return None


def _interface_labels(iface: Any) -> list[str]:
    return [
        str(value)
        for value in (
            getattr(iface, "name", ""),
            getattr(iface, "description", ""),
            getattr(iface, "network_name", ""),
            getattr(iface, "guid", ""),
            str(iface),
        )
        if value
    ]


def _format_interface_choice(iface: Any) -> str:
    name = getattr(iface, "name", "") or str(iface)
    description = getattr(iface, "description", "") or ""
    ip = getattr(iface, "ip", "") or ""
    suffix = f" | {description}" if description else ""
    suffix += f" | ip={ip}" if ip else ""
    return f"- {name}{suffix}"


def _normalized(value: str) -> str:
    return "".join(character.lower() for character in value if character.isalnum())


def packet_to_flow(packet) -> FlowRecord | None:
    try:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.packet import Raw
    except ImportError as exc:
        raise RuntimeError("Scapy is required for live capture.") from exc

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    else:
        return None

    src_port = 0
    dst_port = 0
    protocol = packet.lastlayer().name.upper()
    tcp_flags = ""
    app = "unknown"
    dns_query = ""
    http_method = ""
    http_uri = ""
    user_agent = ""
    icmp_type = -1
    icmp_code = -1

    if TCP in packet:
        protocol = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
        tcp_flags = str(packet[TCP].flags)
        app = _infer_app(protocol, src_port, dst_port)
    elif UDP in packet:
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
        app = _infer_app(protocol, src_port, dst_port)
    elif ICMP in packet:
        protocol = "ICMP"
        app = "icmp"
        icmp_type = int(packet[ICMP].type)
        icmp_code = int(packet[ICMP].code)

    if DNS in packet and packet[DNS].qd and DNSQR in packet:
        app = "dns"
        dns_query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")

    if Raw in packet and app in {"http", "unknown"}:
        payload = bytes(packet[Raw].load)
        http_method, http_uri, user_agent = _parse_http_payload(payload)
        if http_method:
            app = "http"

    packet_len = len(packet)
    return FlowRecord(
        timestamp=datetime.now(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        bytes_out=packet_len,
        bytes_in=0,
        packets_out=1,
        packets_in=0,
        duration_ms=1,
        tcp_flags=tcp_flags,
        dns_query=dns_query,
        http_method=http_method,
        http_uri=http_uri,
        user_agent=user_agent,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        app=app,
    )


def _infer_app(protocol: str, src_port: int, dst_port: int) -> str:
    ports = {src_port, dst_port}
    if 53 in ports:
        return "dns"
    if 67 in ports or 68 in ports:
        return "dhcp"
    if 80 in ports or 8080 in ports:
        return "http"
    if 443 in ports:
        return "https"
    if 22 in ports:
        return "ssh"
    if 25 in ports:
        return "smtp"
    if 123 in ports:
        return "ntp"
    if 139 in ports or 445 in ports:
        return "smb"
    if 3389 in ports:
        return "rdp"
    if 389 in ports or 636 in ports:
        return "ldap"
    return protocol.lower()


def _parse_http_payload(payload: bytes) -> tuple[str, str, str]:
    try:
        text = payload.decode("iso-8859-1", errors="ignore")
    except UnicodeDecodeError:
        return "", "", ""
    lines = text.splitlines()
    if not lines:
        return "", "", ""
    first = lines[0].split()
    if len(first) < 2 or first[0].upper() not in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "PATCH"}:
        return "", "", ""
    user_agent = ""
    for line in lines[1:]:
        if line.lower().startswith("user-agent:"):
            user_agent = line.split(":", 1)[1].strip()
            break
    return first[0].upper(), first[1], user_agent
