import re
import subprocess


def _parse_netsh_interfaces(output, interface=None):
    interfaces = []
    current = {}

    for line in output.splitlines():
        match = re.match(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$", line)
        if not match:
            continue

        key, value = match.group(1).strip().casefold(), match.group(2).strip()
        if key == "name":
            if current:
                interfaces.append(current)
            current = {"name": value}
        elif current:
            current[key] = value

    if current:
        interfaces.append(current)

    for item in interfaces:
        if interface and item.get("name", "").casefold() != interface.casefold():
            continue
        if item.get("state", "").casefold() != "connected":
            continue
        ssid = item.get("ssid", "").strip()
        if ssid and not ssid.startswith("<"):
            return ssid
    return None


def get_network_ssid(interface=None):
    """Return the connected Windows Wi-Fi SSID for the selected adapter."""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode != 0:
        return None
    return _parse_netsh_interfaces(result.stdout, interface)