import unittest

from utils.network_info import _parse_netsh_interfaces


class NetworkInfoTests(unittest.TestCase):
    def test_returns_ssid_for_selected_connected_interface(self):
        output = """\
Name                   : Wi-Fi
State                  : connected
SSID                   : Home Network
BSSID                  : aa:bb:cc:dd:ee:ff

Name                   : Wi-Fi 2
State                  : connected
SSID                   : Guest Network
BSSID                  : 00:11:22:33:44:55
"""

        self.assertEqual(_parse_netsh_interfaces(output, "Wi-Fi 2"), "Guest Network")

    def test_returns_none_when_selected_interface_is_not_connected(self):
        output = """\
Name                   : Wi-Fi
State                  : disconnected
SSID                   :
"""

        self.assertIsNone(_parse_netsh_interfaces(output, "Wi-Fi"))


if __name__ == "__main__":
    unittest.main()