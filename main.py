from collectors.scanner import scan_network
from ping3 import ping
import time
import threading
import sys
from database.db import init_db, save_devices, get_all_devices 
from utils.Lauto_detect import get_ip_address
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
    host = get_ip_address('wlo1')
    print(f"Local IP address detected: {host}")

    init_db()


    while True:
        print("\nScanning network...\n")

        try:
            devices = scan_network(host)
        except PermissionError as e:
            print("ERROR:", e)
            print("Run with elevated permissions: sudo .venv/bin/python main.py")
            sys.exit(1)
        except RuntimeError as e:
            print("ERROR:", e)
            sys.exit(1)

        devices = [(ip, mac, mac_to_manufacturer(mac)) for ip, mac in devices]
        if devices:
            save_devices(devices)

        print(f"Found {len(devices)} devices\n")

        internet_ok = check_internet()

        for ip, mac, manufacturer in devices:
            print(f"{ip} -> {mac} ({manufacturer})")
            check_device(ip)

        time.sleep(10)