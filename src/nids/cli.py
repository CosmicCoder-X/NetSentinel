from __future__ import annotations

import argparse
from pathlib import Path

from .dashboard import DashboardServer
from .engine import DetectionEngine
from .live_capture import capture_backend_status
from .loader import load_flows, load_json
from .realtime import RealTimeNIDS
from .reporting import build_report, write_report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the network-based intrusion detection system."
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Capture live traffic with Scapy instead of reading a JSONL flow file.",
    )
    parser.add_argument(
        "--interface",
        default="",
        help="Network interface for live capture. Leave empty to let Scapy choose.",
    )
    parser.add_argument(
        "--bpf",
        default="",
        help="Berkeley Packet Filter expression for live capture. Leave empty on Windows if libpcap is unavailable.",
    )
    parser.add_argument(
        "--window-size",
        type=int,
        default=120,
        help="Number of recent live flows used by anomaly and protocol analytics.",
    )
    parser.add_argument(
        "--alert-log",
        default="logs/live_alerts.jsonl",
        help="JSONL file where live alerts should be written.",
    )
    parser.add_argument(
        "--append-alert-log",
        action="store_true",
        help="Append to an existing live alert log instead of starting clean.",
    )
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Start the simple live dashboard.",
    )
    parser.add_argument(
        "--dashboard-host",
        default="127.0.0.1",
        help="Host for the live dashboard.",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=8765,
        help="Port for the live dashboard.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List Scapy capture interfaces and exit.",
    )
    parser.add_argument(
        "--check-capture",
        action="store_true",
        help="Check whether Scapy has a usable live capture backend.",
    )
    parser.add_argument(
        "--input",
        default="data/sample_flows.jsonl",
        help="Path to the JSONL flow dataset.",
    )
    parser.add_argument(
        "--config",
        default="configs/detector_config.json",
        help="Path to the detector configuration JSON file.",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory where JSON and HTML reports should be written.",
    )
    args = parser.parse_args()

    if args.list_interfaces:
        return _list_interfaces()
    if args.check_capture:
        return _check_capture()

    input_path = Path(args.input)
    config_path = Path(args.config)
    output_dir = Path(args.output_dir)
    config = load_json(config_path)

    if args.live:
        alert_log = Path(args.alert_log)
        dashboard = None
        if args.dashboard:
            dashboard = DashboardServer(args.dashboard_host, args.dashboard_port, alert_log)
            print(f"Dashboard: {dashboard.start()}")
        print("Starting live Scapy capture. Press Ctrl+C to stop.")
        print(f"Alert log: {alert_log}")
        try:
            RealTimeNIDS(
                config=config,
                alert_log_path=alert_log,
                interface=args.interface,
                bpf_filter=args.bpf,
                window_size=args.window_size,
                append_alert_log=args.append_alert_log,
            ).start()
        except KeyboardInterrupt:
            print("\nLive capture stopped.")
        except RuntimeError as exc:
            print()
            print(str(exc))
            return 1
        finally:
            if dashboard:
                dashboard.stop()
        return 0

    flows = load_flows(input_path)
    engine = DetectionEngine(config)
    alerts = engine.analyze(flows)
    report = build_report(flows, alerts)
    json_path, html_path = write_report(report, output_dir)

    print(f"Processed flows: {len(flows)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"JSON report: {json_path}")
    print(f"HTML report: {html_path}")
    return 0


def _list_interfaces() -> int:
    try:
        from scapy.all import get_if_list
        from scapy.config import conf
    except ImportError:
        print("Scapy is not installed. Run `pip install -e .` or `pip install scapy` first.")
        return 1

    print("Available capture interfaces:")
    print()

    printed = False
    try:
        for index, iface in enumerate(conf.ifaces.values(), start=1):
            name = getattr(iface, "name", "") or str(iface)
            description = getattr(iface, "description", "") or ""
            ip = getattr(iface, "ip", "") or ""
            mac = getattr(iface, "mac", "") or ""
            guid = getattr(iface, "guid", "") or ""
            network_name = getattr(iface, "network_name", "") or ""
            print(f"[{index}] {name}")
            if description:
                print(f"    description: {description}")
            if ip:
                print(f"    ip: {ip}")
            if mac:
                print(f"    mac: {mac}")
            if network_name:
                print(f"    network_name: {network_name}")
            if guid:
                print(f"    guid: {guid}")
            print()
            printed = True
    except Exception:
        printed = False

    if not printed:
        for index, interface in enumerate(get_if_list(), start=1):
            print(f"[{index}] {interface}")

    print("Use the exact interface name shown above with --interface.")
    print("You can also use the number, for example: --interface 3")
    return 0


def _check_capture() -> int:
    status = capture_backend_status()
    print("Capture backend status:")
    for key, value in status.items():
        if key != "reason":
            print(f"{key}: {value}")
    if status.get("reason"):
        print()
        print(status["reason"])
    return 0 if status.get("ready") else 1


if __name__ == "__main__":
    raise SystemExit(main())
