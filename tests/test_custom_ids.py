import unittest

from utils.custom_ids import CustomRuleEngine


class FakeClock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


class CustomRuleEngineTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.rules = [{
            "id": 1,
            "name": "Local packet burst",
            "rule_type": "packet_burst",
            "threshold": 3,
            "window_seconds": 5,
            "severity": "high",
            "source_ip": None,
            "protocol": "ANY",
        }]
        self.engine = CustomRuleEngine(
            rules_provider=lambda: self.rules,
            clock=self.clock,
            refresh_seconds=1,
            alert_cooldown=10,
        )

    def test_packet_burst_rule_matches_threshold_and_respects_cooldown(self):
        for _ in range(2):
            self.assertEqual(self.engine.observe(
                source_ip="192.0.2.10", destination_ip="192.0.2.1", protocol="TCP"
            ), [])

        alerts = self.engine.observe(
            source_ip="192.0.2.10", destination_ip="192.0.2.1", protocol="TCP"
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "Custom rule: Local packet burst")
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertEqual(self.engine.observe(
            source_ip="192.0.2.10", destination_ip="192.0.2.1", protocol="TCP"
        ), [])

    def test_rule_source_and_protocol_filters_are_respected(self):
        self.rules[0]["source_ip"] = "192.0.2.11"
        self.rules[0]["protocol"] = "TCP"

        for _ in range(3):
            self.assertEqual(self.engine.observe(source_ip="192.0.2.10", destination_ip="192.0.2.1", protocol="TCP"), [])
        for _ in range(2):
            self.assertEqual(self.engine.observe(source_ip="192.0.2.11", destination_ip="192.0.2.1", protocol="UDP"), [])
        for _ in range(2):
            self.assertEqual(self.engine.observe(source_ip="192.0.2.10", destination_ip="192.0.2.1", protocol="TCP"), [])
        for _ in range(2):
            self.assertEqual(self.engine.observe(source_ip="192.0.2.11", destination_ip="192.0.2.1", protocol="TCP"), [])
        self.assertEqual(len(self.engine.observe(source_ip="192.0.2.11", destination_ip="192.0.2.1", protocol="TCP")), 1)

    def test_port_scan_rule_counts_unique_ports(self):
        self.rules[0].update({
            "rule_type": "port_scan",
            "threshold": 3,
            "protocol": "TCP",
            "source_ip": None,
        })
        self.assertEqual(self.engine.observe(source_ip="192.0.2.10", destination_port=80, protocol="TCP"), [])
        self.assertEqual(self.engine.observe(source_ip="192.0.2.10", destination_port=80, protocol="TCP"), [])
        self.assertEqual(self.engine.observe(source_ip="192.0.2.10", destination_port=22, protocol="TCP"), [])
        alerts = self.engine.observe(source_ip="192.0.2.10", destination_port=443, protocol="TCP")
        self.assertEqual(len(alerts), 1)
        self.assertIn("3 distinct destination ports", alerts[0]["description"])

    def test_ping_activity_counts_only_echo_requests(self):
        self.rules[0].update({
            "rule_type": "ping_activity",
            "threshold": 3,
            "protocol": "ICMP",
        })
        self.assertEqual(self.engine.observe(
            source_ip="192.0.2.10", destination_ip="192.0.2.1", protocol="ICMP", icmp_type=0
        ), [])
        for _ in range(2):
            self.assertEqual(self.engine.observe(
                source_ip="192.0.2.10", destination_ip="192.0.2.1", protocol="ICMP", icmp_type=8
            ), [])
        alerts = self.engine.observe(
            source_ip="192.0.2.10", destination_ip="192.0.2.1", protocol="ICMP", icmp_type=8
        )
        self.assertEqual(len(alerts), 1)
        self.assertIn("3 ICMP echo requests", alerts[0]["description"])

    def test_new_device_event_matches_and_respects_source_filter(self):
        self.rules[0].update({
            "rule_type": "new_device",
            "threshold": 1,
            "window_seconds": 60,
            "source_ip": "192.0.2.10",
        })
        self.assertEqual(self.engine.observe_new_device("192.0.2.11", "aa:bb:cc:00:00:11"), [])

        alerts = self.engine.observe_new_device("192.0.2.10", "aa:bb:cc:00:00:10")

        self.assertEqual(len(alerts), 1)
        self.assertIn("newly discovered device", alerts[0]["description"])
        self.assertIn("aa:bb:cc:00:00:10", alerts[0]["description"])
        self.assertEqual(self.engine.observe_new_device("192.0.2.10", "aa:bb:cc:00:00:10"), [])

    def test_ping_sweep_counts_distinct_destination_addresses(self):
        self.rules[0].update({
            "rule_type": "ping_sweep",
            "metric": "unique_destinations",
            "threshold": 3,
            "protocol": "ICMP",
        })
        for destination in ("192.0.2.1", "192.0.2.1", "192.0.2.2"):
            self.assertEqual(self.engine.observe(
                source_ip="192.0.2.10", destination_ip=destination,
                protocol="ICMP", icmp_type=8,
            ), [])

        alerts = self.engine.observe(
            source_ip="192.0.2.10", destination_ip="192.0.2.3",
            protocol="ICMP", icmp_type=8,
        )

        self.assertEqual(len(alerts), 1)
        self.assertIn("3 distinct destination IPs", alerts[0]["description"])

    def test_arp_sweep_counts_requested_targets(self):
        self.rules[0].update({
            "rule_type": "arp_sweep",
            "metric": "unique_destinations",
            "threshold": 2,
            "protocol": "ARP",
        })
        self.assertEqual(self.engine.observe(
            source_ip="192.0.2.10", protocol="ARP", arp_op=2,
            arp_target_ip="192.0.2.1",
        ), [])
        self.assertEqual(self.engine.observe(
            source_ip="192.0.2.10", protocol="ARP", arp_op=1,
            arp_target_ip="192.0.2.1",
        ), [])

        alerts = self.engine.observe(
            source_ip="192.0.2.10", protocol="ARP", arp_op=1,
            arp_target_ip="192.0.2.2",
        )

        self.assertEqual(len(alerts), 1)
        self.assertIn("2 distinct destination IPs", alerts[0]["description"])

    def test_syn_scan_ignores_non_syn_and_counts_unique_ports(self):
        self.rules[0].update({
            "rule_type": "syn_scan",
            "metric": "unique_ports",
            "threshold": 2,
            "protocol": "TCP",
        })
        self.assertEqual(self.engine.observe(
            source_ip="192.0.2.10", destination_ip="192.0.2.1",
            destination_port=80, protocol="TCP", tcp_syn=False,
        ), [])
        self.assertEqual(self.engine.observe(
            source_ip="192.0.2.10", destination_ip="192.0.2.1",
            destination_port=80, protocol="TCP", tcp_syn=True,
        ), [])

        alerts = self.engine.observe(
            source_ip="192.0.2.10", destination_ip="192.0.2.1",
            destination_port=443, protocol="TCP", tcp_syn=True,
        )

        self.assertEqual(len(alerts), 1)
        self.assertIn("2 distinct destination ports", alerts[0]["description"])

    def test_target_flood_groups_packets_and_distinct_sources_by_target(self):
        self.rules[0].update({
            "rule_type": "target_flood",
            "metric": "count",
            "group_by": "destination_ip",
            "threshold": 3,
            "min_sources": 3,
            "protocol": "ANY",
            "mitre_id": "T1498.001",
        })
        for source in ("192.0.2.10", "192.0.2.10"):
            self.assertEqual(self.engine.observe(
                source_ip=source, destination_ip="192.0.2.50", protocol="UDP"
            ), [])
        self.assertEqual(self.engine.observe(
            source_ip="192.0.2.11", destination_ip="192.0.2.50", protocol="UDP"
        ), [])

        alerts = self.engine.observe(
            source_ip="192.0.2.12", destination_ip="192.0.2.50", protocol="UDP"
        )

        self.assertEqual(len(alerts), 1)
        self.assertIsNone(alerts[0]["source_ip"])
        self.assertEqual(alerts[0]["destination_ip"], "192.0.2.50")
        self.assertEqual(alerts[0]["mitre_id"], "T1498.001")

    def test_rule_excluded_ips_skip_only_matching_rule_events(self):
        self.rules[0]["excluded_ips"] = ["192.0.2.10"]
        for _ in range(3):
            self.assertEqual(self.engine.observe(
                source_ip="192.0.2.10", destination_ip="192.0.2.1", protocol="TCP"
            ), [])
        for _ in range(2):
            self.assertEqual(self.engine.observe(
                source_ip="192.0.2.11", destination_ip="192.0.2.1", protocol="TCP"
            ), [])
        alerts = self.engine.observe(
            source_ip="192.0.2.11", destination_ip="192.0.2.1", protocol="TCP"
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "192.0.2.11")

    def test_rule_excluded_ip_skips_new_device_event(self):
        self.rules[0].update({
            "rule_type": "new_device",
            "excluded_ips": ["192.0.2.10"],
        })

        self.assertEqual(self.engine.observe_new_device("192.0.2.10", "aa:bb:cc:00:00:10"), [])
        self.assertEqual(len(self.engine.observe_new_device("192.0.2.11", "aa:bb:cc:00:00:11")), 1)


if __name__ == "__main__":
    unittest.main()