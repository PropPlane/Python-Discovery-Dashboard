import sqlite3
from scapy.all import ARP, Ether, srp


def scan_network(host):
    target = f"{host}/24"

    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

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

