from collections import defaultdict, deque
from datetime import datetime
import time
import threading


class IntrusionDetector:
    """Small stateful detector for common local-network traffic patterns."""

    def __init__(self, window_seconds=10, port_scan_threshold=20,
                 packet_burst_threshold=250, alert_cooldown=60,
                 clock=None):
        self.window_seconds = window_seconds
        self.port_scan_threshold = port_scan_threshold
        self.packet_burst_threshold = packet_burst_threshold
        self.alert_cooldown = alert_cooldown
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._ports_by_source = defaultdict(deque)
        self._packets_by_source = defaultdict(deque)
        self._arp_claims = defaultdict(set)
        self._last_alert = {}

    def observe(self, source_ip=None, destination_port=None, protocol=None,
                arp_ip=None, arp_mac=None, icmp_type=None, destination_ip=None,
                tcp_syn=False, arp_op=None, arp_target_ip=None):
        """Observe normalized packet fields and return newly generated alerts."""
        now = self._clock()
        alerts = []

        with self._lock:
            if source_ip:
                packet_times = self._packets_by_source[source_ip]
                packet_times.append(now)
                self._discard_expired(packet_times, now)
                if len(packet_times) >= self.packet_burst_threshold:
                    alert = self._make_alert(
                        "Packet burst", "high", source_ip,
                        f"{len(packet_times)} packets observed from {source_ip} "
                        f"within {self.window_seconds} seconds.",
                        now, ("Packet burst", source_ip),
                    )
                    if alert:
                        alerts.append(alert)

                if destination_port is not None and protocol in ("TCP", "UDP"):
                    port_events = self._ports_by_source[source_ip]
                    port_events.append((now, int(destination_port)))
                    self._discard_expired(port_events, now)
                    unique_ports = {port for _, port in port_events}
                    if len(unique_ports) >= self.port_scan_threshold:
                        alert = self._make_alert(
                            "Port scan", "medium", source_ip,
                            f"{source_ip} contacted {len(unique_ports)} distinct "
                            f"{protocol} destination ports within "
                            f"{self.window_seconds} seconds.",
                            now, ("Port scan", source_ip),
                            mitre_id="T1046",
                        )
                        if alert:
                            alerts.append(alert)

            normalized_arp_mac = (arp_mac or "").lower()
            if (arp_op == 2 and arp_ip and arp_ip != "0.0.0.0"
                    and normalized_arp_mac and normalized_arp_mac != "00:00:00:00:00:00"):
                claims = self._arp_claims[arp_ip]
                if claims and normalized_arp_mac not in claims:
                    alert = self._make_alert(
                        "Conflicting ARP claim", "high", arp_ip,
                        f"{arp_ip} was announced by multiple MAC addresses: "
                        f"{', '.join(sorted(claims | {normalized_arp_mac}))}.",
                        now, ("Conflicting ARP claim", arp_ip),
                        mitre_id="T1557.002",
                    )
                    if alert:
                        alerts.append(alert)
                claims.add(normalized_arp_mac)

        return alerts

    def _discard_expired(self, events, now):
        cutoff = now - self.window_seconds
        while events and events[0][0] < cutoff if events and isinstance(events[0], tuple) else events and events[0] < cutoff:
            events.popleft()

    def _make_alert(self, alert_type, severity, source_ip, description,
                    now, cooldown_key, mitre_id=None):
        last_alert = self._last_alert.get(cooldown_key)
        if last_alert is not None and now - last_alert < self.alert_cooldown:
            return None
        self._last_alert[cooldown_key] = now
        return {
            "alert_type": alert_type,
            "severity": severity,
            "source_ip": source_ip,
            "description": description,
            "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "mitre_id": mitre_id,
        }