# Python Network Monitor

This is a SO/HO network monitor built using Python.

### Project Purpose

This project collects device IP addresses, MAC addresses, manufacturer information, last-seen timestamps, and other relevant data on a given local network.

### Key Features

The program selects the interface and IPv4 address chosen by the operating-system route table, then scans its local subnet at the configured interval. It rechecks the active network each cycle, retargets capture when the adapter or address changes, waits and retries through disconnects or transient scan errors, and marks devices offline when a network is lost or a successful scan finds no hosts. Device manufacturers are looked up from MAC addresses when available; unknown vendors are shown as "Unknown". Results are presented in the web dashboard.


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

### Intrusion detection

When packet capture is running, the IDS records alerts for:

- Port scans: 20 distinct TCP or UDP destination ports from one source within 10 seconds.
- Packet bursts: 250 IP packets from one source within 10 seconds.
- Conflicting ARP claims: one IP address announced by multiple MAC addresses.

Repeated alerts of the same type and source are suppressed for 60 seconds. Port-scan alerts are tagged T1046 and validated conflicting ARP replies are tagged T1557.002; a generic packet burst is left unmapped unless a user-created rule supplies a technique. Up to 1,000 recent alerts are retained in `database/logs.db` and shown in the dashboard's IDS Alerts table. Detection thresholds are configured in `IntrusionDetector` in `utils/ids.py`.

This is a passive, heuristic IDS: it does not block traffic, inspect encrypted payloads, or see traffic that is not visible on the selected interface. Packet capture may require elevated permissions, and results depend on the network adapter and operating system.

Captured packet totals are stored in `database/logs.db` in `traffic_samples` for up to 30 days. The dashboard's Packet Volume bar chart shows recent intervals; bars above 25 packets per second are highlighted as a watch signal. This aggregate threshold is not a DoS/DDoS verdict and should be interpreted alongside IDS alerts and normal traffic patterns.

### Custom IDS rules

The dashboard's generic rule builder supports an event type, aggregation metric, group key, source/destination filters, threshold, time window, severity, minimum distinct source count, protocol, and optional ATT&CK technique ID. Presets include packet bursts, unique-port scans, ICMP activity and ping sweeps (T1018), ARP sweeps (T1018), SYN-only scans (T1046), target-grouped floods with minimum distinct sources (T1498.001), and first-seen devices. Rules are stored in `ids_rules` in `database/logs.db`; existing rules receive safe defaults during database initialization. Enable, disable, and delete rules from the Custom IDS Rules panel. The sniffer refreshes active traffic rules every five seconds, and matches create entries in the IDS Alerts table with target and ATT&CK metadata. Packet capture must be running for packet-based rules to evaluate traffic; new-device rules use network scan results. These heuristics are triage signals, not confirmation of an ATT&CK technique or attack.

Run its privilege-free unit tests with:

```bash
python -m unittest discover -s tests -v
```
