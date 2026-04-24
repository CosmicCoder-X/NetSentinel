from __future__ import annotations

from pathlib import Path
import sys
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from nids.engine import DetectionEngine
from nids.loader import load_flows, load_json


class DetectionPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.flows = load_flows(PROJECT_ROOT / "data" / "sample_flows.jsonl")
        self.config = load_json(PROJECT_ROOT / "configs" / "detector_config.json")
        self.alerts = DetectionEngine(self.config).analyze(self.flows)

    def test_sample_dataset_keeps_protocol_coverage(self) -> None:
        evidence_text = "\n".join(str(alert.evidence) for alert in self.alerts)
        self.assertIn("HTTP exploit attempt", evidence_text)
        self.assertIn("Suspicious TLS fingerprint", evidence_text)
        self.assertIn("Rogue DHCP server", evidence_text)
        self.assertIn("External SMB access", evidence_text)
        self.assertIn("ICMP sweep", evidence_text)

    def test_normal_authorized_dhcp_is_not_alerted_as_rogue(self) -> None:
        false_positive = [
            alert
            for alert in self.alerts
            if alert.src_ip == "10.0.2.1" and "Rogue DHCP server" in str(alert.evidence)
        ]
        self.assertEqual([], false_positive)

    def test_precision_pass_keeps_low_signal_baseline_web_traffic_quiet(self) -> None:
        baseline_web_false_positive = [
            alert
            for alert in self.alerts
            if alert.src_ip == "10.0.1.10" and alert.dst_ip == "10.0.2.20" and alert.category == "signature"
        ]
        self.assertEqual([], baseline_web_false_positive)


if __name__ == "__main__":
    unittest.main()
