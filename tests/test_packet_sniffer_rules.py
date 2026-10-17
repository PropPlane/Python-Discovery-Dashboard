import unittest
from unittest.mock import patch

from scapy.all import ARP, ICMP, IP, TCP
from utils.custom_ids import CustomRuleEngine
from utils.packet_sniffer import PacketSniffer


class FakeClock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


class PacketSnifferRuleTests(unittest.TestCase):
    def test_interface_can_be_retargeted_and_paused(self):
        sniffer = PacketSniffer(iface="Wi-Fi")

        sniffer.set_interface("Ethernet")
        self.assertEqual(sniffer.iface, "Ethernet")

        sniffer.set_interface(None)
        self.assertIsNone(sniffer.iface)

    def test_matched_custom_rule_is_persisted_as_ids_alert(self):
        rule = {
            "id": 12,
            "name": "Test burst",
            "rule_type": "packet_burst",
            "threshold": 2,
            "window_seconds": 10,
            "severity": "medium",
            "source_ip": None,
            "protocol": "ANY",
        }
        sniffer = PacketSniffer()
        sniffer._custom_detector = CustomRuleEngine(
            rules_provider=lambda: [rule],
            clock=FakeClock(),
            alert_cooldown=60,
        )
        fields = {
            "source_ip": "192.0.2.20",
            "destination_ip": "192.0.2.1",
            "destination_port": 80,
            "protocol": "TCP",
            "arp_ip": None,
            "arp_mac": None,
        }

        with patch.object(sniffer, "_extract_fields", return_value=fields), \
                patch("database.db.save_ids_alert") as save_alert:
            sniffer._handle_packet(object())
            sniffer._handle_packet(object())

        self.assertEqual(save_alert.call_count, 1)
        alert = save_alert.call_args.args[0]
        self.assertEqual(alert["alert_type"], "Custom rule: Test burst")
        self.assertEqual(alert["source_ip"], "192.0.2.20")

    def test_extracts_icmp_echo_request_fields(self):
        packet = IP(src="192.0.2.30", dst="192.0.2.1") / ICMP(type=8)

        fields = PacketSniffer._extract_fields(packet)

        self.assertEqual(fields["source_ip"], "192.0.2.30")
        self.assertEqual(fields["protocol"], "ICMP")
        self.assertEqual(fields["icmp_type"], 8)

    def test_extracts_tcp_syn_flag_and_destination(self):
        packet = IP(src="192.0.2.30", dst="192.0.2.1") / TCP(dport=443, flags="S")

        fields = PacketSniffer._extract_fields(packet)

        self.assertEqual(fields["destination_ip"], "192.0.2.1")
        self.assertEqual(fields["destination_port"], 443)
        self.assertTrue(fields["tcp_syn"])

    def test_extracts_arp_request_target(self):
        packet = ARP(
            op=1,
            psrc="192.0.2.30",
            pdst="192.0.2.1",
            hwsrc="aa:bb:cc:00:00:30",
        )

        fields = PacketSniffer._extract_fields(packet)

        self.assertEqual(fields["protocol"], "ARP")
        self.assertEqual(fields["source_ip"], "192.0.2.30")
        self.assertEqual(fields["arp_target_ip"], "192.0.2.1")

    def test_new_device_events_are_persisted(self):
        rule = {
            "id": 13,
            "name": "New host arrives",
            "rule_type": "new_device",
            "threshold": 1,
            "window_seconds": 60,
            "severity": "medium",
            "source_ip": None,
            "protocol": "ANY",
        }
        sniffer = PacketSniffer()
        sniffer._custom_detector = CustomRuleEngine(rules_provider=lambda: [rule])

        with patch("database.db.save_ids_alert") as save_alert:
            sniffer.observe_new_device("192.0.2.40", "aa:bb:cc:00:00:40")

        self.assertEqual(save_alert.call_count, 1)
        alert = save_alert.call_args.args[0]
        self.assertIn("newly discovered device", alert["description"])


if __name__ == "__main__":
    unittest.main()