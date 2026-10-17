import threading
import time
try:
    from scapy.all import sniff
except Exception:
    sniff = None

from utils.ids import IntrusionDetector
from utils.custom_ids import CustomRuleEngine


class PacketSniffer:
    #Background packet counter using Scapy.

    #Usage:
        #ps = PacketSniffer(iface='eth0')
        #ps.start()
        # later: ps.get_and_reset()
        #ps.stop()
    

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
        alerts = self._detector.observe(**fields)
        alerts.extend(self._custom_detector.observe(
            source_ip=fields.get("source_ip"),
            destination_ip=fields.get("destination_ip"),
            destination_port=fields.get("destination_port"),
            protocol=fields.get("protocol"),
            icmp_type=fields.get("icmp_type"),
            tcp_syn=fields.get("tcp_syn", False),
            arp_op=fields.get("arp_op"),
            arp_target_ip=fields.get("arp_target_ip"),
        ))
        self._persist_alerts(alerts)

    def observe_new_device(self, ip_address, mac_address):
        alerts = self._custom_detector.observe_new_device(ip_address, mac_address)
        self._persist_alerts(alerts)

    @staticmethod
    def _persist_alerts(alerts):
        for alert in alerts:
            try:
                from database.db import save_ids_alert
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
                tcp_syn = bool(tcp_flags & 0x02 and not tcp_flags & 0x10)
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
            # scapy not available; just sleep loop
            while self._running:
                time.sleep(1.0)
            return

        # Run sniff in short timeouts so we can react to stop requests
        while self._running:
            with self._lock:
                iface = self.iface
            if not iface:
                time.sleep(1)
                continue
            try:
                sniff(iface=iface, prn=self._handle_packet, store=False, timeout=1)
            except Exception:
                # swallow errors to avoid crashing the thread; wait briefly
                time.sleep(1)

    def set_interface(self, iface):
        """Retarget capture; None pauses it until an active interface is found."""
        with self._lock:
            self.iface = iface

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_sniff_loop, daemon=True)
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


# module-global singleton accessors so multiple modules talk to the same sniffer
_global_sniffer = None

def get_global_sniffer(iface=None):
    """Return a shared PacketSniffer instance (lazy-create)."""
    global _global_sniffer
    if _global_sniffer is None:
        _global_sniffer = PacketSniffer(iface=iface)
    elif iface is not None:
        _global_sniffer.set_interface(iface)
    return _global_sniffer


def notify_new_device(ip_address, mac_address):
    """Send a first-seen scan result to the shared custom rule engine."""
    return get_global_sniffer().observe_new_device(ip_address, mac_address)

def set_global_sniffer(sniffer):
    global _global_sniffer
    _global_sniffer = sniffer
