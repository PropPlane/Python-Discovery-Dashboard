import sys
import time
import threading
from utils.startup_text import print_startup_text, module_startup_text
from utils.import_utils import auto_import

# File Loading and startup text
print_startup_text()
module_startup_text(__file__)


#File import output
scan_network = auto_import("collectors.scanner").scan_network
ping = auto_import("ping3").ping
init_archive_db = auto_import("database.db").init_archive_db
init_db = auto_import("database.db").init_db
init_unique_db = auto_import("database.db").init_unique_db
save_devices = auto_import("database.db").save_devices
get_new_devices = auto_import("database.db").get_new_devices
get_all_devices = auto_import("database.db").get_all_devices
detect_interface = auto_import("utils.Lauto_detect").detect_interface
mac_to_manufacturer = auto_import("utils.mac").mac_to_manufacturer
app = auto_import("web.app").app
push_live_update = auto_import("web.app").push_live_update
record_packet_usage = auto_import("web.app").record_packet_usage
get_global_sniffer = auto_import("utils.packet_sniffer").get_global_sniffer
notify_new_device = auto_import("utils.packet_sniffer").notify_new_device
check_internet = auto_import("utils.status").check_internet
check_device = auto_import("utils.status").check_device
# File loading end


def run_scan_cycle(interval_seconds=10, packet_sniffer=None, network_detector=None, stop_event=None):
    last_packet_sample_time = time.monotonic()
    active_network = None
    network_state_seen = False
    detect_network = network_detector or detect_interface
    while stop_event is None or not stop_event.is_set():
        print("\nScanning network...\n")

        try:
            iface, host = detect_network()
        except Exception as e:
            print("Network detection failed; will retry:", e)
            iface, host = None, None

        if not iface or not host:
            if active_network is not None or not network_state_seen:
                print("Network disconnected; marking devices offline.")
                if packet_sniffer:
                    packet_sniffer.set_interface(None)
                    try:
                        packet_sniffer.get_and_reset()
                    except Exception:
                        pass
                last_packet_sample_time = time.monotonic()
                save_devices([])
                push_live_update(get_all_devices())
                active_network = None
                network_state_seen = True
            if stop_event is not None:
                stop_event.wait(interval_seconds)
            else:
                time.sleep(interval_seconds)
            continue

        current_network = (iface, host)
        network_state_seen = True
        if current_network != active_network:
            print(f"Using network {iface} at {host}")
            active_network = current_network
            if packet_sniffer:
                packet_sniffer.set_interface(iface)

        try:
            discovered_devices = scan_network(host, iface=iface)
            new_devices = get_new_devices(discovered_devices, exclude_ips={host})
            # record actual packet count collected by the background sniffer (if available)
            try:
                packet_count = packet_sniffer.get_and_reset() if packet_sniffer else 0
            except Exception:
                packet_count = 0
            sample_time = time.monotonic()
            sample_interval = max(sample_time - last_packet_sample_time, 0.001)
            last_packet_sample_time = sample_time
            record_packet_usage(packet_count, interval_seconds=sample_interval)
        except PermissionError as e:
            print("ERROR:", e)
            print("Check packet-capture permissions; scanning will retry.")
        except RuntimeError as e:
            print("Scan failed; network state may have changed. Retrying:", e)
        except Exception as e:
            print("Unexpected scan error; retrying:", e)
        else:
            try:
                devices = [(check_device(ip), ip, mac, mac_to_manufacturer(mac)) for ip, mac in discovered_devices]
                print(f"Devices from scan: {devices}") #Outputs devices to the terminal mainly used for debugging
                print(f"Device IPs: {[ip for _, ip, _, _ in devices]}")

                save_devices(devices, elapsed_seconds=interval_seconds)
                for ip, mac in new_devices:
                    notify_new_device(ip, mac)
                # Push even empty scans so clients can see offline transitions.
                push_live_update([
                    {
                        "status": status,
                        "ip": ip,
                        "mac": mac,
                        "manufacturer": manufacturer,
                        "last_seen": "",
                    }
                    for status, ip, mac, manufacturer in devices
                ])
                print(f"Found {len(devices)} devices\n")
                check_internet()

                for status, ip, mac, manufacturer in devices:
                    print(f"{ip} -> {mac} ({manufacturer})")
            except Exception as e:
                print("Post-scan processing failed; scanning will continue:", e)

        if stop_event is not None:
            stop_event.wait(interval_seconds)
        else:
            time.sleep(interval_seconds)


if __name__ == "__main__": #This is where the program actually starts
    # Run Flask in a separate thread when executing the application, not on import.
    flask_thread = threading.Thread(target=lambda: app.run(host="0.0.0.0", port=5000, use_reloader=False, threaded=True), daemon=True)
    flask_thread.start()
    time.sleep(1)

    iface, host = detect_interface()
    if host is None:
        print("No active network detected; the scanner will wait for one.")

    init_db()           #Database initation functions are called here
    init_archive_db()
    init_unique_db()
                        #
                        #

    scan_interval = 10    #The scan interval defaults to 10s
    if len(sys.argv) > 1: #Unless a number is entered beside like so "python main.py {num}"
        try:
            scan_interval = int(sys.argv[1])
        except ValueError:
            print("Invalid scan interval. Using default of 10 seconds.")

    print(f"Scan interval set to {scan_interval} seconds")

    # start or get module-global packet sniffer and wire into scan loop
    try:
        packet_sniffer = get_global_sniffer(iface=iface)
        packet_sniffer.start()
    except Exception:
        # best-effort: continue without sniffing
        packet_sniffer = None

    scan_thread = threading.Thread(target=run_scan_cycle, args=(scan_interval, packet_sniffer), daemon=True)
    scan_thread.start()

    while True:
        time.sleep(60)