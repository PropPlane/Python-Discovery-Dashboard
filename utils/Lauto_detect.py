import psutil
import socket


def get_ip_address(interface):
    try:
        addrs = psutil.net_if_addrs()
        return addrs[interface][0].address
    except (KeyError, IndexError):
        return None


def detect_interface():
    addrs = psutil.net_if_addrs()
    for name, iface_addrs in addrs.items():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return name, addr.address
    return None, None