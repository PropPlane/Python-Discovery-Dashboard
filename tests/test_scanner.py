import socket
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from collectors.scanner import _scan_target


class ScanTargetTests(unittest.TestCase):
    def test_uses_selected_interface_netmask(self):
        addresses = {
            "Wi-Fi": [SimpleNamespace(
                family=socket.AF_INET,
                address="192.168.12.144",
                netmask="255.255.255.0",
            )]
        }

        with patch("collectors.scanner.psutil.net_if_addrs", return_value=addresses):
            target = _scan_target("192.168.12.144", "Wi-Fi")

        self.assertEqual(target, "192.168.12.0/24")

    def test_manual_host_uses_existing_default_subnet(self):
        self.assertEqual(_scan_target("10.0.0.25", None), "10.0.0.25/24")


if __name__ == "__main__":
    unittest.main()