"""
packet_capture.py
-----------------
Live packet capture using Scapy.
Extracts features from each packet and places them on a shared queue
for the detection engine to consume.
"""

import time
import queue
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not installed – running in SIMULATION mode.")

logger = logging.getLogger(__name__)

# Protocol number → string
PROTO_MAP = {6: "tcp", 17: "udp", 1: "icmp"}

# Well-known port → service name (subset for feature mapping)
SERVICE_MAP = {
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain_u", 67: "tftp_u", 80: "http", 110: "pop_3",
    111: "sunrpc", 113: "auth", 119: "nntp", 143: "imap4",
    161: "snmp", 194: "IRC", 389: "ldap", 443: "http_443",
    445: "microsoft_ds", 512: "exec", 513: "login", 514: "shell",
    515: "printer", 540: "uucp", 543: "klogin", 544: "kshell",
    993: "imap4", 995: "pop_3", 1080: "http_8001", 3306: "sql_net",
    3389: "X11", 5900: "vnc", 8080: "http_8001",
}

# Flag map (TCP flags bitmask → NSL-KDD flag string)
FLAG_MAP = {
    0x002: "S0", 0x012: "S1", 0x018: "SF", 0x011: "FIN",
    0x004: "REJ", 0x014: "RSTO", 0x010: "OTH",
}


@dataclass
class PacketFeatures:
    """Structured container for a captured packet's extracted features."""
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    protocol: str = "tcp"
    service: str = "other"
    flag: str = "OTH"
    src_bytes: int = 0
    dst_bytes: int = 0
    duration: float = 0.0
    land: int = 0
    wrong_fragment: int = 0
    urgent: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_nsl_vector(self) -> list:
        """
        Return a 41-element feature vector matching NSL-KDD column order.
        Fields we cannot derive from a single packet default to 0.
        """
        proto_num = {"tcp": 0, "udp": 1, "icmp": 2}.get(self.protocol, 0)
        svc_num = _service_to_num(self.service)
        flag_num = _flag_to_num(self.flag)

        return [
            self.duration,      # 0  duration
            proto_num,          # 1  protocol_type
            svc_num,            # 2  service
            flag_num,           # 3  flag
            self.src_bytes,     # 4  src_bytes
            self.dst_bytes,     # 5  dst_bytes
            self.land,          # 6  land
            self.wrong_fragment,# 7  wrong_fragment
            self.urgent,        # 8  urgent
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  # 9–19  host/session features (unknown)
            0, 0,               # 20–21 is_host_login, is_guest_login
            1, 1,               # 22–23 count, srv_count (at least 1 packet seen)
            0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0,   # 24–30 rate features
            1, 1,               # 31–32 dst_host_count, dst_host_srv_count
            1.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # 33–40 dst_host rates
        ]


# ── Helper mappings ───────────────────────────────────────────────────────────

def _service_to_num(svc: str) -> int:
    """Convert service name to a stable integer ID."""
    services = sorted(set(SERVICE_MAP.values()) | {"other"})
    try:
        return services.index(svc)
    except ValueError:
        return 0


def _flag_to_num(flag: str) -> int:
    flags = ["FIN", "INT", "OTH", "REJ", "RSTO", "RSTOS0", "RSTR", "S0",
             "S1", "S2", "S3", "SF", "SH"]
    try:
        return flags.index(flag)
    except ValueError:
        return 2  # OTH


# ── Feature extraction ────────────────────────────────────────────────────────

def extract_features(packet) -> Optional[PacketFeatures]:
    """Extract a PacketFeatures object from a raw Scapy packet."""
    try:
        if not packet.haslayer(IP):
            return None

        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        pkt_len = len(packet)
        land = 1 if src_ip == dst_ip else 0

        # Protocol
        if packet.haslayer(TCP):
            proto = "tcp"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags_int = int(packet[TCP].flags)
            flag = FLAG_MAP.get(flags_int & 0x03F, "OTH")
            urgent = packet[TCP].urgptr if hasattr(packet[TCP], "urgptr") else 0
        elif packet.haslayer(UDP):
            proto = "udp"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            flag = "SF"  # UDP is connectionless – treat as established
            urgent = 0
        elif packet.haslayer(ICMP):
            proto = "icmp"
            sport = dport = 0
            flag = "SF"
            urgent = 0
        else:
            proto = "other"
            sport = dport = 0
            flag = "OTH"
            urgent = 0

        # Service (destination port → service name)
        service = SERVICE_MAP.get(dport, SERVICE_MAP.get(sport, "other"))

        return PacketFeatures(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=proto,
            service=service,
            flag=flag,
            src_bytes=pkt_len,
            dst_bytes=0,      # cannot determine from single sniffed packet
            duration=0.0,
            land=land,
            wrong_fragment=ip.frag if hasattr(ip, "frag") else 0,
            urgent=urgent,
            timestamp=time.time(),
        )
    except Exception as e:
        logger.debug(f"Feature extraction error: {e}")
        return None


# ── Packet sniffer ────────────────────────────────────────────────────────────

class PacketCapture:
    """
    Runs Scapy sniff() in a background thread and feeds PacketFeatures
    objects into a queue for the detection engine.
    """

    def __init__(self, packet_queue: queue.Queue, interface: str = None,
                 bpf_filter: str = "ip", count: int = 0):
        self.packet_queue = packet_queue
        self.interface = interface  # None → Scapy picks default
        self.bpf_filter = bpf_filter
        self.count = count          # 0 = infinite
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── Internal callback ─────────────────────────────────────────────────────

    def _process_packet(self, packet):
        if self._stop_event.is_set():
            return
        features = extract_features(packet)
        if features:
            try:
                self.packet_queue.put_nowait(features)
            except queue.Full:
                logger.warning("Packet queue full – dropping packet.")

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self):
        """Start sniffing in a daemon thread."""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy unavailable – starting simulation mode.")
            self._thread = threading.Thread(target=self._simulate, daemon=True)
            self._thread.start()
            return

        logger.info(f"Starting live capture on interface={self.interface or 'default'} "
                    f"filter='{self.bpf_filter}'")
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Signal the capture thread to stop."""
        self._stop_event.set()
        logger.info("PacketCapture stopped.")

    def _capture_loop(self):
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._process_packet,
                count=self.count,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,
            )
        except Exception as e:
            logger.error(f"Sniff error: {e}")

    # ── Simulation mode (no Scapy / no root) ─────────────────────────────────

    def _simulate(self):
        """Generate synthetic packets for demo / testing purposes."""
        import random
        import itertools

        scenarios = [
            # (src_ip, dst_ip, proto, service, flag, src_bytes, label_hint)
            ("192.168.1.10", "10.0.0.1", "tcp", "http", "SF", 500, "normal"),
            ("10.0.0.5",    "10.0.0.1", "tcp", "ftp",  "S0", 5000, "dos"),
            ("172.16.0.3",  "10.0.0.1", "tcp", "other","S0", 100,  "scan"),
            ("192.168.1.20","10.0.0.1", "tcp", "ssh",  "SF", 200,  "brute"),
            ("192.168.1.15","10.0.0.1", "udp", "domain_u","SF", 60,"normal"),
        ]

        for idx in itertools.cycle(range(len(scenarios))):
            if self._stop_event.is_set():
                break
            s = scenarios[idx]
            pf = PacketFeatures(
                src_ip=s[0], dst_ip=s[1], protocol=s[2],
                service=s[3], flag=s[4], src_bytes=s[5],
                timestamp=time.time(),
            )
            self.packet_queue.put(pf)
            time.sleep(random.uniform(0.3, 1.2))
