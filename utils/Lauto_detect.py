import psutil
import socket


def get_ip_address(interface):
    try:
        addrs = psutil.net_if_addrs()
        for addr in addrs[interface]:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return addr.address
    except (KeyError, IndexError):
        pass
    return None


def detect_interface():
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    route_ip = None
    try:
        # UDP connect asks the OS which local interface would reach an external IP.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_probe:
            route_probe.connect(("192.0.2.1", 80))
            route_ip = route_probe.getsockname()[0]
    except OSError:
        pass

    for name, iface_addrs in addrs.items():
        if name not in stats or not stats[name].isup:
            continue
        for addr in iface_addrs:
            if (addr.family == socket.AF_INET
                    and addr.address == route_ip
                    and not addr.address.startswith(("127.", "169.254."))):
                return name, addr.address
    return None, None