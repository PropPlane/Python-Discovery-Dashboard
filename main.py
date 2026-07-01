import sys
import time
import threading
from utils.startup_text import print_startup_text, module_startup_text
from utils.import_utils import auto_import

# File Loading and startup text
print_startup_text()
module_startup_text(__file__)

scan_network = auto_import("collectors.scanner").scan_network
ping = auto_import("ping3").ping
init_archive_db = auto_import("database.db").init_archive_db
init_db = auto_import("database.db").init_db
save_devices = auto_import("database.db").save_devices
get_all_devices = auto_import("database.db").get_all_devices
detect_interface = auto_import("utils.Lauto_detect").detect_interface
mac_to_manufacturer = auto_import("utils.mac").mac_to_manufacturer
app = auto_import("web.app").app
check_internet = auto_import("utils.status").check_internet
check_device = auto_import("utils.status").check_device
# File loading end


# Run Flask in a separate thread
flask_thread = threading.Thread(target=lambda: app.run(host="0.0.0.0", port=5000, use_reloader=False), daemon=True)
flask_thread.start()

time.sleep(1)  # Give Flask time to start before prompting for input


def run_scan_cycle(host, interval_seconds=10):
    while True:
        print("\nScanning network...\n")

        try:
            devices = scan_network(host)
        except PermissionError as e:
            print("ERROR:", e)
            print("Run with elevated permissions: sudo .venv/bin/python main.py")
            break
        except RuntimeError as e:
            print("ERROR:", e)
            break

        devices = [(check_device(ip), ip, mac, mac_to_manufacturer(mac)) for ip, mac in devices]

        print(f"Devices from scan: {devices}")
        print(f"Device IPs: {[ip for _, ip, _, _ in devices]}")

        if devices:
            save_devices(devices)

        print(f"Found {len(devices)} devices\n")

        internet_ok = check_internet()

        for status, ip, mac, manufacturer in devices:
            print(f"{ip} -> {mac} ({manufacturer})")

        time.sleep(interval_seconds)


if __name__ == "__main__":
    iface, host = detect_interface()
    if host is None:
        host = input("Could not detect local IP address. Please enter your local IP address (e.g., 192.168.1.1): ")

    init_db()
    init_archive_db()

    scan_interval = 10
    if len(sys.argv) > 1:
        try:
            scan_interval = int(sys.argv[1])
        except ValueError:
            print("Invalid scan interval. Using default of 10 seconds.")

    print(f"Scan interval set to {scan_interval} seconds")

    scan_thread = threading.Thread(target=run_scan_cycle, args=(host, scan_interval), daemon=True)
    scan_thread.start()

    while True:
        time.sleep(60)