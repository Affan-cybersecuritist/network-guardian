"""
replay_capture.py
------------------
Cloud-safe stand-in for live_capture.LiveCapture. A container on a cloud host
has no real network worth sniffing -- it would only ever see its own internal
traffic, which isn't intrusion detection, it's noise dressed up as it. So
instead of pretending to be live, this replays the same canned attack
scenario used by /demo/simulate-attack (data/test_traffic.pcap) through the
same on_results callback the real WebSocket broadcaster listens to, at a
realistic pace -- a few connections every 1-2.5 seconds, looping -- so the
"Live packet capture" table on the public demo actually fills up and updates
instead of sitting empty, while being clearly labeled as a replay (see
main.py's /interfaces and /live/status responses).

Everything downstream of this -- scoring, SHAP, WAF, alerts, stats -- runs
for real on this data; only the "sniffed live off a real NIC" part is faked,
because a cloud container has no real NIC worth sniffing in the first place.
"""
import random
import threading
import time


class ReplayCapture:
    def __init__(self, on_results, feature_rows):
        """on_results: callable(list[dict]) invoked with a batch of feature rows,
        same shape LiveCapture would produce. feature_rows: precomputed once at
        startup from the demo pcap (see main.py) -- may be empty if it's missing."""
        self.on_results = on_results
        self.feature_rows = feature_rows
        self.running = False
        self._thread = None
        self._stop_event = threading.Event()
        self.packet_count = 0
        self.error = None
        self.started_at = None

    def start(self, interface=None, bpf_filter=None):
        # interface/bpf_filter accepted only to keep the same call signature
        # as LiveCapture.start(); a replay has no real interface to pick.
        if self.running:
            raise RuntimeError("Replay capture is already running.")
        if not self.feature_rows:
            raise RuntimeError(
                "No demo capture data available to replay (data/test_traffic.pcap "
                "missing or empty). Run notebooks/generate_test_pcap.py."
            )
        self._stop_event.clear()
        self.packet_count = 0
        self.error = None
        self.running = True
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        idx = 0
        rows = self.feature_rows
        n = len(rows)
        while not self._stop_event.wait(random.uniform(1.0, 2.5)):
            batch_size = min(n, random.randint(1, 3))
            batch = [rows[(idx + i) % n] for i in range(batch_size)]
            idx = (idx + batch_size) % n
            self.packet_count += batch_size
            try:
                self.on_results(batch)
            except Exception as e:
                self.error = f"{type(e).__name__}: {e}"

    def stop(self):
        self._stop_event.set()
        self.running = False
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    def status(self):
        return {
            "running": self.running,
            "interface": "Replayed demo scenario (cloud deployment — no real NIC to sniff)" if self.running else None,
            "packet_count": self.packet_count,
            "started_at": self.started_at,
            "error": self.error,
            "is_replay": True,
        }
