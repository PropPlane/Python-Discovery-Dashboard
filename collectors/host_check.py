from ping3 import ping, verbose_ping
import time

from utils.Lauto_detect import get_ip_address, detect_interface

#This is just for checking if the host is actually online I plan on doing more with this
def check_inet_status(host):
    response_time = ping(host)

    if response_time is not None:
        print(f"{host} is online. Response time: {response_time:.2f} ms")
    else:
        print(f"{host} is offline.")
        time.sleep(.1)

#Auto loacl network detection needs OS variables
if __name__ == "__main__":
    host = get_ip_address(detect_interface)
    print(f"Local IP address detected: {host}")
    if host is None:
        print("Could not detect local IP address. Please check your network interface.")

    while True:
        check_inet_status(host)
        time.sleep(.1)
