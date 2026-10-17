import threading
import unittest
from unittest.mock import call, patch

import main


class FakeSniffer:
    def __init__(self):
        self.iface = None
        self.interfaces = []

    def set_interface(self, iface):
        self.iface = iface
        self.interfaces.append(iface)

    def get_and_reset(self):
        return 0


class ScanCycleNetworkStateTests(unittest.TestCase):
    def test_waits_recovers_retargets_and_marks_hosts_offline(self):
        stop_event = threading.Event()
        networks = iter([
            (None, None),
            ("Wi-Fi", "10.20.0.14"),
            ("Ethernet", "192.168.44.27"),
            (None, None),
        ])

        def detect_next_network():
            network = next(networks)
            if network == (None, None) and detect_next_network.calls:
                stop_event.set()
            detect_next_network.calls += 1
            return network

        detect_next_network.calls = 0
        sniffer = FakeSniffer()

        with patch.object(main, "scan_network", side_effect=[RuntimeError("route changed"), []]) as scan, \
                patch.object(main, "get_new_devices", return_value=[]), \
                patch.object(main, "save_devices") as save_devices, \
                patch.object(main, "get_all_devices", return_value=[]), \
                patch.object(main, "push_live_update") as push_update, \
                patch.object(main, "record_packet_usage"), \
                patch.object(main, "check_internet"):
            main.run_scan_cycle(
                interval_seconds=0,
                packet_sniffer=sniffer,
                network_detector=detect_next_network,
                stop_event=stop_event,
            )

        self.assertEqual(scan.call_args_list, [
            call("10.20.0.14", iface="Wi-Fi"),
            call("192.168.44.27", iface="Ethernet"),
        ])
        self.assertEqual(save_devices.call_count, 3)
        self.assertEqual(save_devices.call_args_list[0], call([]))
        self.assertEqual(save_devices.call_args_list[1], call([], elapsed_seconds=0))
        self.assertEqual(save_devices.call_args_list[2], call([]))
        self.assertEqual(sniffer.interfaces, [None, "Wi-Fi", "Ethernet", None])
        self.assertEqual(push_update.call_count, 3)


if __name__ == "__main__":
    unittest.main()