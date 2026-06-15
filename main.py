from collectors.scanner import scan_network
from ping3 import ping
import time
import threading
from database.db import init_db, save_devices, get_all_devices 
from utils.mac import mac_to_manufacturer
from web.app import app

# Run Flask in a separate thread
flask_thread = threading.Thread(target=lambda: app.run(host="0.0.0.0", port=5000, use_reloader=False), daemon=True)
flask_thread.start()

time.sleep(1)  # Give Flask time to start before prompting for input


def check_internet(host="8.8.8.8"):
    response = ping(host, timeout=2)

    if response is not None:
        print(f"[INTERNET UP] {host} - {response*1000:.2f} ms")
        return True

    print(f"[INTERNET DOWN] {host}")
    return False


def check_device(ip):
    response = ping(ip, timeout=1)

    if response is not None:
        print(f"[ONLINE] {ip} - {response*1000:.2f} ms")
    else:
        print(f"[OFFLINE] {ip}")


if __name__ == "__main__":
    host = input("Enter host (e.g. 192.168.1.1): ")

    init_db()


    while True:
        print("\nScanning network...\n")

        devices = scan_network(host)
        devices = [(ip, mac, mac_to_manufacturer(mac)) for ip, mac in devices]
        if devices:
            save_devices(devices)

        print(f"Found {len(devices)} devices\n")

        internet_ok = check_internet()

        for ip, mac, manufacturer in devices:
            print(f"{ip} -> {mac} ({manufacturer})")
            check_device(ip)

        time.sleep(10)