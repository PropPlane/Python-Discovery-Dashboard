import socket
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from utils.Lauto_detect import detect_interface


class FakeRouteSocket:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def connect(self, address):
        pass

    def getsockname(self):
        return ("192.168.44.27", 12345)


class InterfaceDetectionTests(unittest.TestCase):
    def test_uses_route_interface_only_when_adapter_is_up(self):
        addresses = {
            "Down Wi-Fi": [SimpleNamespace(family=socket.AF_INET, address="192.168.44.27")],
            "Active Wi-Fi": [SimpleNamespace(family=socket.AF_INET, address="192.168.44.27")],
        }
        stats = {
            "Down Wi-Fi": SimpleNamespace(isup=False),
            "Active Wi-Fi": SimpleNamespace(isup=True),
        }

        with patch("utils.Lauto_detect.psutil.net_if_addrs", return_value=addresses), \
                patch("utils.Lauto_detect.psutil.net_if_stats", return_value=stats), \
                patch("utils.Lauto_detect.socket.socket", FakeRouteSocket):
            result = detect_interface()

        self.assertEqual(result, ("Active Wi-Fi", "192.168.44.27"))

    def test_does_not_select_link_local_address(self):
        addresses = {
            "Wi-Fi Direct": [SimpleNamespace(family=socket.AF_INET, address="169.254.4.5")],
        }
        stats = {"Wi-Fi Direct": SimpleNamespace(isup=True)}
        route_socket = FakeRouteSocket()
        route_socket.getsockname = lambda: ("169.254.4.5", 12345)

        with patch("utils.Lauto_detect.psutil.net_if_addrs", return_value=addresses), \
                patch("utils.Lauto_detect.psutil.net_if_stats", return_value=stats), \
                patch("utils.Lauto_detect.socket.socket", return_value=route_socket):
            result = detect_interface()

        self.assertEqual(result, (None, None))


if __name__ == "__main__":
    unittest.main()