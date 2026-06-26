from mac_vendor_lookup import MacLookup
import time
mac_lookup = MacLookup()

def mac_to_manufacturer(mac):
    try:
        return mac_lookup.lookup(mac)
    except Exception as e:
        print(f"Error looking up MAC {mac}: {e}")
        return "Unknown"
    time.sleep(30) # Sleep for preformance