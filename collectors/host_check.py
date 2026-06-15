from ping3 import ping, verbose_ping
import time

def check_inet_status(host):
    response_time = ping(host)

    if response_time is not None:
        print(f"{host} is online. Response time: {response_time:.2f} ms")
    else:
        print(f"{host} is offline.")


if __name__ == "__main__":
    host = input("Enter host (e.g. google.com): ")

    while True:
        check_inet_status(host)
        time.sleep(.5)
