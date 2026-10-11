# Python Network Monitor

This is a SO/HO network monitor built using Python.

### Project Purpose

This project collects device IP addresses, MAC addresses, manufacturer information, last-seen timestamps, and other relevant data on a given local network.

### Key Features

When starting the program your network interface will be automatically detected (currently only available on Linux). If it fails the user will be prompted to enter the router/gateway IP Address manually. The program scans in a chosen intreval, discovering new devices as they connect to the chosen network. An educated guess of the device manufacturer will be done using reverse MAC lookup, if one is not found it will show up as "Unknown". This information will be presented on a web dashboard created upon start-up of the program.


[![](https://mermaid.ink/img/pako:eNqd01GvmjAUB_Cv0tSXLeHeQFugNMsSFc2WbMuMexrchwoHJUJrStmdM373AQqLe7w8cXr-v9OS0AvOdA5Y4NSkqqj0a3aQxqLFj75G3TNPPunGoq2Vtm1e0NPTR7RI3m03X0oLKJZW7mQD71_G-DL5BvZVmyPaZlKpUu2H0B2OqQX60Ndxsq5kc0Tz75-nAfGQXCW9Qsv-MM1_vXUyP53QulWZLbWSVWnPU2I9JDb3uVswv8BMzdWt2ZfjUmPPFaA5KsqqErMCCpqFTmONPoKY5VEYuoGT6UobMYsIc114hMu3wsUIKfCimGBEKQU5Qp97GQ8fYXyHeVZk8G9HL5CUTdBjPiX5I1yNcAeygAkSP6CwmyBQyeUjXL8Vbu4QfAi75AjZzu_oBD2Pk-EbsYP3psyxsKYFB9dgatmX-HIbm2J7gBpSLLpXBa01skqH3_ba0ZNUP7WuR210uz9gUciq6ar2lEsLcSn3RtbTqgGVg1nqVlksGOfeMAWLC_6NhUe9Zx50Jw2ISzjhzMFnLIjrPoeEETfgIfOYS9jVwX-GfbuGy7kfkSiM_DAiPHIw5KXV5uvtgg337PoXBL4Ozw?type=png)](https://mermaid.live/edit#pako:eNqd01GvmjAUB_Cv0tSXLeHeFAq0NMsSFc2WbMuMexrchwoHJUJrStmdM373AQqLe7w8cU7_v9OS0AvOdA5Y4NSkqqj0a3aQxqLFj75G3TNPPunGoq2Vtm1e0NPTR7RI3m03X0oLKJZW7mQD71_G-DL5BvZVmyPaZlKpUu2H0B2OqQX60Ndxsq5kc0Tz75-nAfGQXCW9Qsv-MM1_a-tkfjqhdasyW2olq9Kep8R6SGzuc7dgfoGZFle3xb4cW409V4DmqCirSswKKGjGnMYafQQxyyPGSOhkutJGzCLPJwQe4fKtcDFCCrwoJhhRSkGOMOBuxtkjjO8wz4oM_u3ohpL6E3T9gHr5I1yNcAeygAl6QUhhN0GgkstHuH4r3NwhBMC65Aj9XdDRCbou94ZvxA7emzLHwpoWHFyDqWVf4sttbIrtAWpIseheFbTWyCodfttrR09S_dS6HrXR7f6ARSGrpqvaUy4txKXcG1lPXQMqB7PUrbJY-JyTYQoWF_wbi8h75h4JPc6ikLqEhQ4-Y-FG7jMLmcc4dzkLWHh18J9hW9L1A59ENCA0CjzidQDy0mrz9Xa_hmt2_QsBgw6m)


### Requirements/Dependencies
Python 3 or higher will be needed to run this project, the following are required dependencies: flask, ping3 mac-vendor-lookup, scapy. These dependencies can be installed using: 

```
pip install flask, ping3, mac-vendor-lookup, scapy, psutil
```

It is needed to download the chart.js file locally in order to avoid loading errors when starting the program you can do so in the CLI by using:

For Linux:
```
curl -o static/chart.js https://jsdelivr.net
```

Or for Windows:
```
Invoke-WebRequest -Uri "https://jsdelivr.net" -OutFile "static/chart.js"
```

### Usage

It is recommended to use a venv to run the project and install dependencies.

```
python -m venv .my_venv
```

For Windows:
```
my_env\Scripts\activate
```

For Linux:
```
source my_venv/bin/activate
```

To start the program run the main.py file in the root folder:

```
python main.py
```

Open the dashboard at http://HOST_DEVICE_IP:5000

### Packet sniffer (real packet counts)

This project includes an optional Scapy-based packet sniffer to collect real packet counts for the dashboard. Capturing packets requires elevated privileges on Linux.

- Easiest: run the program with sudo (recommended when testing):

```bash
sudo .venv/bin/python main.py
```

- Alternative: grant the Python binary CAP_NET_RAW and CAP_NET_ADMIN instead of running as root:

```bash
sudo setcap 'cap_net_raw,cap_net_admin+eip' /full/path/to/.venv/bin/python
```

- Quick REPL test for the sniffer:

```python
from utils.packet_sniffer import PacketSniffer
ps = PacketSniffer(iface='eth0')  # or None for default
ps.start()
import time; time.sleep(5)
print('packets seen:', ps.get_and_reset())
ps.stop()
```

Note: Scapy must be installed (see `requirements.txt`). If Scapy is not available the sniffer runs in a no-op mode and the dashboard will show zero packet counts.
