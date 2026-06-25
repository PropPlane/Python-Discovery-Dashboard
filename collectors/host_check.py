from ping3 import ping, verbose_ping
import time

from utils.Lauto_detect import get_ip_address

def check_inet_status(host):
    response_time = ping(host)

    if response_time is not None:
        print(f"{host} is online. Response time: {response_time:.2f} ms")
    else:
        print(f"{host} is offline.")


if __name__ == "__main__":
    host = get_ip_address('wlo1')
    print(f"Local IP address detected: {host}")
    if host is None:
        print("Could not detect local IP address. Please check your network interface.")

    while True:
        check_inet_status(host)
        time.sleep(.5)
