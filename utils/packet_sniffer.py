import threading
import time
try:
    from scapy.all import sniff
except Exception:
    sniff = None


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

    def _handle_packet(self, pkt):
        with self._lock:
            self._count += 1

    def _run_sniff_loop(self):
        if sniff is None:
            # scapy not available; just sleep loop
            while self._running:
                time.sleep(1.0)
            return

        # Run sniff in short timeouts so we can react to stop requests
        while self._running:
            try:
                sniff(iface=self.iface, prn=self._handle_packet, store=False, timeout=1)
            except Exception:
                # swallow errors to avoid crashing the thread; wait briefly
                time.sleep(1)

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
    return _global_sniffer

def set_global_sniffer(sniffer):
    global _global_sniffer
    _global_sniffer = sniffer
