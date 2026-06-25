import sqlite3
from scapy.all import ARP, Ether, srp


def scan_network(host):
    target = f"{host}/24"

    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    try:
        result = srp(packet, timeout=2, verbose=0)[0]
    except PermissionError as e:
        raise PermissionError(
            "Raw socket access denied. Run this script with elevated privileges "
            "(sudo) or grant cap_net_raw+eip to the Python interpreter."
        ) from e
    except OSError as e:
        raise RuntimeError(
            "Failed to create a raw socket. Ensure you have permission to use Scapy "
            "and that the network interface is available."
        ) from e

    devices = []
    for sent, received in result:
        devices.append((received.psrc, received.hwsrc))

    return devices


def save_devices(devices):
    con = sqlite3.connect("database/logs.db")
    cur = con.cursor()

    for ip, mac in devices:
        cur.execute("INSERT INTO logs (ip, mac, last_seen) VALUES (?, ?, ?)", (ip, mac))

    con.commit()
    con.close()

if __name__ == "__main__":
    host = input("Enter host (e.g. 192.168.1.1): ")
    devices = scan_network(host)

    save_devices(devices)
    

    for ip, mac, manufacturer in devices:
        print(f"{ip} -> {mac} -> {manufacturer}")

