
import threading
import time

try:
    from scapy.all import sniff
except Exception:
    sniff = None

from utils.ids import IntrusionDetector
from utils.custom_ids import CustomRuleEngine


class PacketSniffer:
    """Background packet counter and IDS using Scapy."""

    def __init__(self, iface=None):
        self.iface = iface
        self._count = 0
        self._lock = threading.Lock()
        self._running = False
        self._thread = None

        self._detector = IntrusionDetector()
        self._custom_detector = CustomRuleEngine()

    def _handle_packet(self, pkt):
        with self._lock:
            self._count += 1

        fields = self._extract_fields(pkt)

        builtin_alerts = self._detector.observe(**fields)

        custom_alerts = self._custom_detector.observe(
            source_ip=fields.get("source_ip"),
            destination_ip=fields.get("destination_ip"),
            destination_port=fields.get("destination_port"),
            protocol=fields.get("protocol"),
            icmp_type=fields.get("icmp_type"),
            tcp_syn=fields.get("tcp_syn", False),
            arp_op=fields.get("arp_op"),
            arp_target_ip=fields.get("arp_target_ip"),
        )

        # Custom-rule exclusions take precedence over matching
        # built-in alerts.
        builtin_rule_types = {
            "Packet burst": "packet_burst",
            "Port scan": "port_scan",
        }

        filtered_builtin_alerts = []

        for alert in builtin_alerts:
            rule_type = builtin_rule_types.get(
                alert.get("alert_type")
            )
            source_ip = alert.get("source_ip")

            if (
                rule_type
                and self._custom_detector.is_source_excluded_for_rule(
                    rule_type, source_ip
                )
            ):
                continue

            filtered_builtin_alerts.append(alert)

        self._persist_alerts(
            filtered_builtin_alerts,
            use_global_exemptions=True,
        )
        self._persist_alerts(custom_alerts)

    def observe_new_device(self, ip_address, mac_address):
        alerts = self._custom_detector.observe_new_device(
            ip_address, mac_address
        )
        self._persist_alerts(alerts)

    @staticmethod
    def _persist_alerts(alerts, use_global_exemptions=False):
        if not alerts:
            return

        from database.db import save_ids_alert

        exemptions = []
        is_exempt = lambda alert: False

        if use_global_exemptions:
            try:
                from database.db import (
                    get_ids_alert_exemptions,
                    is_ids_alert_exempt,
                )

                exemptions = get_ids_alert_exemptions()
                is_exempt = lambda alert: is_ids_alert_exempt(
                    alert, exemptions
                )
            except Exception:
                pass

        for alert in alerts:
            if is_exempt(alert):
                continue

            try:
                save_ids_alert(alert)
            except Exception:
                pass

    @staticmethod
    def _extract_fields(pkt):
        try:
            from scapy.all import ARP, ICMP, IP, TCP, UDP

            source_ip = pkt[IP].src if pkt.haslayer(IP) else None
            destination_ip = pkt[IP].dst if pkt.haslayer(IP) else None

            destination_port = None
            protocol = None
            icmp_type = None
            tcp_syn = False

            if pkt.haslayer(TCP):
                destination_port = pkt[TCP].dport
                protocol = "TCP"
                tcp_flags = int(pkt[TCP].flags)
                tcp_syn = bool(
                    tcp_flags & 0x02 and not tcp_flags & 0x10
                )
            elif pkt.haslayer(UDP):
                destination_port = pkt[UDP].dport
                protocol = "UDP"
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
                icmp_type = int(pkt[ICMP].type)

            arp_ip = pkt[ARP].psrc if pkt.haslayer(ARP) else None
            arp_mac = pkt[ARP].hwsrc if pkt.haslayer(ARP) else None
            arp_op = int(pkt[ARP].op) if pkt.haslayer(ARP) else None
            arp_target_ip = pkt[ARP].pdst if pkt.haslayer(ARP) else None

            if pkt.haslayer(ARP):
                source_ip = source_ip or arp_ip
                destination_ip = destination_ip or arp_target_ip

                if protocol is None:
                    protocol = "ARP"

            return {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "protocol": protocol,
                "icmp_type": icmp_type,
                "tcp_syn": tcp_syn,
                "arp_ip": arp_ip,
                "arp_mac": arp_mac,
                "arp_op": arp_op,
                "arp_target_ip": arp_target_ip,
            }

        except Exception:
            return {}

    def _run_sniff_loop(self):
        if sniff is None:
            while self._running:
                time.sleep(1.0)
            return

        while self._running:
            with self._lock:
                iface = self.iface

            if not iface:
                time.sleep(1)
                continue

            try:
                sniff(
                    iface=iface,
                    prn=self._handle_packet,
                    store=False,
                    timeout=1,
                )
            except Exception:
                time.sleep(1)

    def set_interface(self, iface):
        """Retarget capture; None pauses it until an interface is set."""
        with self._lock:
            self.iface = iface

    def start(self):
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._run_sniff_loop,
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        self._running = False

        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def get_and_reset(self):
        with self._lock:
            val = self._count
            self._count = 0
            return val


# Module-global singleton accessors.
_global_sniffer = None


def get_global_sniffer(iface=None):
    """Return a shared PacketSniffer instance."""
    global _global_sniffer

    if _global_sniffer is None:
        _global_sniffer = PacketSniffer(iface=iface)
    elif iface is not None:
        _global_sniffer.set_interface(iface)

    return _global_sniffer


def notify_new_device(ip_address, mac_address):
    """Send a first-seen scan result to the shared custom rule engine."""
    return get_global_sniffer().observe_new_device(
        ip_address, mac_address
    )


def set_global_sniffer(sniffer):
    global _global_sniffer
    _global_sniffer = sniffer
