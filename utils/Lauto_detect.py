import psutil

def get_ip_address(interface):
    try:
        addrs = psutil.net_if_addrs()
        return addrs[interface][0].address
    except (KeyError, IndexError):
        return None

# Show available interfaces
addrs = psutil.net_if_addrs()
print("Available interfaces:")
for interface, addr_list in addrs.items():
    print(f"  {interface}: {[a.address for a in addr_list]}")

print(f"\nIP address of wlo1: {get_ip_address('wlo1')}")