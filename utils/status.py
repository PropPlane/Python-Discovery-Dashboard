from ping3 import ping

def check_internet(host="8.8.8.8"):
    response = ping(host, timeout=2)

    if response is not None:
        print(f"[INTERNET UP] {host} - {response*1000:.2f} ms")
        return True

    print(f"[INTERNET DOWN] {host}")
    return False


def check_device(ip):
    response = ping(ip, timeout=2)
    
    if response is not None:
        status = "ONLINE"
        print(f"[{status}] {ip} - {response*1000:.2f} ms")
    else:
        status = "OFFLINE"
        print(f"[{status}] {ip}")

    return status