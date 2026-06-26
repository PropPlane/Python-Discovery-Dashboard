# Python Network Monitor

This is a network device monitor built using Python.

### Project Purpose

This project collects device IP addresses, MAC addresses, manufacturer information, and last-seen timestamps on a given local network.

### Key Features

When starting the program your network interface will be automatically detected. If it fails the user will be prompted to enter the router IP Address manually the program scans constantly in ten second intervals, Discovering new devices as they connect to the targeted network. An educated guess of the device manufacturer will be done using reverse MAC lookup, if one is not found it will show up as "Unknown". This information will be presented on a web dashboard created upon start-up of the program.

### Requirements/Dependencies
Python 3 or higher will be needed to run this project, the following are required dependencies: Flask, ping3 mac-vendor-lookup, scapy. These dependencies can be installed using: 

```python
pip install Flask ping3 mac-vendor-lookup scapy psutil
```

### Usage

To start the program run the main.py file in the root folder:

python main.py

Open the dashboard at http://127.0.0.1:5000/
