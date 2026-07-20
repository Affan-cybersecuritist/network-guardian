"""
live_capture.py
----------------
Real-time packet capture: continuously sniffs a live network interface (not a
finished .pcap file), groups packets into connections in a rolling window, and
scores newly-completed connections as they appear.

WINDOWS NOTE: scapy needs Npcap installed (https://npcap.com/#download, check
"WinPcap API-compatible mode" during install) and this process typically needs
to run as Administrator to open a raw capture handle. If capture fails to
start, this is almost always the cause -- see start_capture()'s error message.

Design:
  - A background sniffer thread (scapy AsyncSniffer) appends packets to an
    in-memory ring buffer, trimmed to the last RETENTION_WINDOW seconds.
  - A separate flush thread wakes up every FLUSH_INTERVAL seconds, re-runs the
    same connection-grouping + feature extraction used for uploaded pcaps
    (pcap_to_features.py) over the current buffer, diffs against previously
    reported connections, scores only the NEW ones, and hands them to a
    callback (main.py wires this to a WebSocket broadcast).
"""
import threading
import time
from collections import deque

from scapy.all import AsyncSniffer, get_if_list, conf

from pcap_to_features import extract_connections_from_packets, compute_features

RETENTION_WINDOW = 65.0   # seconds of packets kept in the buffer (must cover AUTH_WINDOW)
FLUSH_INTERVAL = 3.0      # how often we re-score the window


class LiveCapture:
    def __init__(self, on_results):
        """on_results: callable(list[dict]) invoked with newly-scored connection rows."""
        self.on_results = on_results
        self._sniffer = None
        self._flush_thread = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._packets = deque()
        self._seen_keys = set()  # (5-tuple, start_time) already reported
        self.interface = None
        self.packet_count = 0
        self.error = None
        self.started_at = None

    @property
    def running(self):
        return self._sniffer is not None and self._sniffer.running

    def _on_packet(self, pkt):
        with self._lock:
            self._packets.append(pkt)
            self.packet_count += 1
            cutoff = float(pkt.time) - RETENTION_WINDOW
            while self._packets and float(self._packets[0].time) < cutoff:
                self._packets.popleft()

    def _flush_loop(self):
        while not self._stop_event.wait(FLUSH_INTERVAL):
            try:
                self._flush_once()
            except Exception as e:
                self.error = f"{type(e).__name__}: {e}"

    def _flush_once(self):
        with self._lock:
            snapshot = list(self._packets)
        if not snapshot:
            return

        conns = extract_connections_from_packets(snapshot)
        rows = compute_features(conns)

        new_rows = []
        for r in rows:
            key = r["_conn_key"]
            if key in self._seen_keys:
                continue
            self._seen_keys.add(key)
            new_rows.append(r)

        # keep _seen_keys from growing forever
        if len(self._seen_keys) > 5000:
            self._seen_keys = set(list(self._seen_keys)[-2000:])

        if new_rows:
            self.on_results(new_rows)

    def start(self, interface=None, bpf_filter=None):
        if self.running:
            raise RuntimeError("Capture already running")

        available = get_if_list()
        if interface and interface not in available:
            raise ValueError(f"Unknown interface {interface!r}. Available: {available}")

        self._stop_event.clear()
        self._packets.clear()
        self._seen_keys.clear()
        self.packet_count = 0
        self.error = None
        self.interface = interface

        try:
            self._sniffer = AsyncSniffer(
                iface=interface, filter=bpf_filter, prn=self._on_packet, store=False,
            )
            self._sniffer.start()
        except Exception as e:
            self._sniffer = None
            raise RuntimeError(
                f"Failed to start capture on {interface!r}: {type(e).__name__}: {e}. "
                "On Windows this usually means Npcap isn't installed "
                "(https://npcap.com/#download) or this process isn't running as Administrator."
            ) from e

        self.started_at = time.time()
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()

    def stop(self):
        self._stop_event.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        if self._flush_thread is not None:
            self._flush_thread.join(timeout=FLUSH_INTERVAL + 1)
            self._flush_thread = None

    def status(self):
        return {
            "running": self.running,
            "interface": self.interface,
            "packet_count": self.packet_count,
            "started_at": self.started_at,
            "error": self.error,
        }


def list_interfaces():
    return get_if_list()


def list_interfaces_detailed():
    """Like list_interfaces() but with human-readable name/description attached,
    e.g. {"device": "\\\\Device\\\\NPF_{...}", "name": "Wi-Fi", "description": "Intel(R) Wi-Fi 6E AX211"}
    -- raw NPF device strings alone aren't usable in a UI dropdown."""
    try:
        result = []
        for iface in conf.ifaces.values():
            device = getattr(iface, "network_name", None) or getattr(iface, "name", None)
            result.append({
                "device": device,
                "name": getattr(iface, "name", device),
                "description": getattr(iface, "description", "") or "",
            })
        if result:
            return result
    except Exception:
        pass
    # Fallback: no friendly metadata available, just the raw device list
    return [{"device": d, "name": d, "description": ""} for d in get_if_list()]
