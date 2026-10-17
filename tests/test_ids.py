import unittest

from utils.ids import IntrusionDetector


class FakeClock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


class IntrusionDetectorTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.detector = IntrusionDetector(
            port_scan_threshold=3,
            packet_burst_threshold=10,
            alert_cooldown=60,
            clock=self.clock,
        )

    def test_detects_distinct_destination_ports(self):
        alerts = []
        for port in (22, 80, 443):
            alerts.extend(self.detector.observe(
                source_ip="192.168.1.20",
                destination_port=port,
                protocol="TCP",
            ))

        self.assertEqual([alert["alert_type"] for alert in alerts], ["Port scan"])
        self.assertEqual(alerts[0]["severity"], "medium")

    def test_suppresses_repeated_alerts_during_cooldown(self):
        for port in (22, 80, 443):
            self.detector.observe(
                source_ip="192.168.1.20",
                destination_port=port,
                protocol="TCP",
            )

        self.assertEqual(self.detector.observe(
            source_ip="192.168.1.20",
            destination_port=8080,
            protocol="TCP",
        ), [])

    def test_detects_conflicting_arp_claim(self):
        self.assertEqual(self.detector.observe(
            arp_ip="192.168.1.1", arp_mac="00:11:22:33:44:55", arp_op=2
        ), [])

        alerts = self.detector.observe(
            arp_ip="192.168.1.1", arp_mac="aa:bb:cc:dd:ee:ff", arp_op=2
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "Conflicting ARP claim")
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertEqual(alerts[0]["mitre_id"], "T1557.002")

    def test_ignores_arp_requests_and_zero_mac_claims(self):
        self.assertEqual(self.detector.observe(
            arp_ip="192.168.1.1", arp_mac="00:11:22:33:44:55", arp_op=1
        ), [])
        self.assertEqual(self.detector.observe(
            arp_ip="192.168.1.1", arp_mac="00:00:00:00:00:00", arp_op=2
        ), [])


if __name__ == "__main__":
    unittest.main()