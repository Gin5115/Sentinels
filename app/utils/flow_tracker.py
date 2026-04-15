"""
Flow Tracker for Sentinels ML Engine.

Aggregates per-packet data from Scapy into bidirectional network flows
and extracts the same 20 features used to train the CICIDS-2017 model.

Flow lifecycle:
  - Created on first packet of a 5-tuple
  - Closed immediately on TCP FIN/RST
  - Expired after FLOW_TIMEOUT seconds of inactivity
  - Hard-expired after FLOW_MAX_DURATION seconds regardless
"""

import time
import threading
import numpy as np


class Flow:
    """A single bidirectional network flow."""

    FLOW_TIMEOUT = 30.0        # seconds of inactivity → expire
    FLOW_MAX_DURATION = 120.0  # hard cap on flow lifetime

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, ts):
        # Forward direction is defined by the first packet (src → dst)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        self.start_time = ts
        self.last_time = ts
        self.is_closed = False

        # Forward stats (initiator → responder)
        self.fwd_packets = 0
        self.fwd_bytes = []
        self._fwd_last_ts = ts

        # Backward stats (responder → initiator)
        self.bwd_packets = 0
        self.bwd_bytes = []
        self._bwd_last_ts = None

        # All-packet inter-arrival times
        self._all_last_ts = ts
        self.all_iat = []

        # TCP flag counts (across both directions)
        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0

    def add_packet(self, packet_data, ts):
        """Update flow with one packet."""
        pkt_len = packet_data.get('len', 0)
        flags = str(packet_data.get('flags', ''))
        is_fwd = (packet_data.get('src_ip') == self.src_ip and
                  packet_data.get('dst_ip') == self.dst_ip)

        # Inter-arrival time (all packets)
        self.all_iat.append(ts - self._all_last_ts)
        self._all_last_ts = ts
        self.last_time = ts

        if is_fwd:
            self.fwd_packets += 1
            self.fwd_bytes.append(pkt_len)
            self._fwd_last_ts = ts
        else:
            self.bwd_packets += 1
            self.bwd_bytes.append(pkt_len)
            self._bwd_last_ts = ts

        # Flag counts
        if 'S' in flags:
            self.syn_count += 1
        if 'F' in flags:
            self.fin_count += 1
        if 'R' in flags:
            self.rst_count += 1
        if 'P' in flags:
            self.psh_count += 1
        if 'A' in flags:
            self.ack_count += 1

        # TCP FIN/RST signals end of connection
        if 'F' in flags or 'R' in flags:
            self.is_closed = True

    def is_expired(self, now):
        return (self.is_closed or
                (now - self.last_time) > self.FLOW_TIMEOUT or
                (now - self.start_time) > self.FLOW_MAX_DURATION)

    def extract_features(self):
        """
        Return a dict of the 20 CICIDS-2017 compatible features.
        Keys match the FEATURES list in train_model.py exactly.
        """
        duration = max(self.last_time - self.start_time, 1e-9)
        total_pkts = self.fwd_packets + self.bwd_packets
        total_bytes = sum(self.fwd_bytes) + sum(self.bwd_bytes)

        fwd_arr = np.array(self.fwd_bytes, dtype=float) if self.fwd_bytes else np.array([0.0])
        bwd_arr = np.array(self.bwd_bytes, dtype=float) if self.bwd_bytes else np.array([0.0])
        iat_arr = np.array(self.all_iat, dtype=float) if self.all_iat else np.array([0.0])

        return {
            'Flow Duration':                   duration * 1e6,          # µs
            'Total Fwd Packets':               float(self.fwd_packets),
            'Total Backward Packets':          float(self.bwd_packets),
            'Total Length of Fwd Packets':     float(sum(self.fwd_bytes)),
            'Total Length of Bwd Packets':     float(sum(self.bwd_bytes)),
            'Fwd Packet Length Mean':          float(np.mean(fwd_arr)),
            'Fwd Packet Length Std':           float(np.std(fwd_arr)),
            'Bwd Packet Length Mean':          float(np.mean(bwd_arr)),
            'Bwd Packet Length Std':           float(np.std(bwd_arr)),
            'Flow Bytes/s':                    total_bytes / duration,
            'Flow Packets/s':                  total_pkts / duration,
            'Flow IAT Mean':                   float(np.mean(iat_arr)) * 1e6,   # µs
            'Flow IAT Std':                    float(np.std(iat_arr)) * 1e6,
            'SYN Flag Count':                  float(self.syn_count),
            'FIN Flag Count':                  float(self.fin_count),
            'RST Flag Count':                  float(self.rst_count),
            'PSH Flag Count':                  float(self.psh_count),
            'ACK Flag Count':                  float(self.ack_count),
            'Average Packet Size':             total_bytes / max(total_pkts, 1),
            'Down/Up Ratio':                   self.bwd_packets / max(self.fwd_packets, 1),
        }


class FlowTracker:
    """
    Thread-safe tracker that groups packets into flows and yields
    completed flows for ML classification.

    Usage:
        completed_flows = tracker.update(packet_data)
        for flow in completed_flows:
            threat = ml_engine.classify_flow(flow)
    """

    MAX_ACTIVE_FLOWS = 10_000   # hard cap — evict oldest when exceeded
    SWEEP_INTERVAL = 5.0        # seconds between expiry sweeps

    def __init__(self):
        self._lock = threading.Lock()
        self._flows = {}           # {flow_key: Flow}
        self._last_sweep = time.time()

    # ── public API ────────────────────────────────────────────────────────────

    def update(self, packet_data):
        """
        Process one packet.
        Returns a list of Flow objects that have just completed (may be empty).
        """
        src_ip = packet_data.get('src_ip', '')
        dst_ip = packet_data.get('dst_ip', '')
        if not src_ip or not dst_ip:
            return []

        ts = time.time()
        key = self._canonical_key(packet_data)
        completed = []

        with self._lock:
            now = ts

            # Periodic sweep for timed-out flows
            if now - self._last_sweep >= self.SWEEP_INTERVAL:
                expired = [k for k, f in self._flows.items() if f.is_expired(now)]
                for k in expired:
                    completed.append(self._flows.pop(k))
                self._last_sweep = now

            # Get or create flow
            flow = self._flows.get(key)
            if flow is None:
                # Enforce memory cap
                if len(self._flows) >= self.MAX_ACTIVE_FLOWS:
                    oldest_key = next(iter(self._flows))
                    completed.append(self._flows.pop(oldest_key))

                src_port = packet_data.get('src_port', 0) or 0
                dst_port = packet_data.get('dst_port', 0) or 0
                proto = packet_data.get('protocol', '')
                flow = Flow(src_ip, dst_ip, src_port, dst_port, proto, ts)
                self._flows[key] = flow

            flow.add_packet(packet_data, ts)

            # Collect immediately if FIN/RST closed the flow
            if flow.is_closed:
                completed.append(self._flows.pop(key))

        return completed

    def clear(self):
        """Reset all state (called on session restart)."""
        with self._lock:
            self._flows.clear()

    # ── internals ─────────────────────────────────────────────────────────────

    def _canonical_key(self, packet_data):
        """
        Canonical bidirectional flow key.
        Same key regardless of which end initiates the current packet.
        """
        a = (packet_data.get('src_ip', ''),
             packet_data.get('src_port', 0) or 0)
        b = (packet_data.get('dst_ip', ''),
             packet_data.get('dst_port', 0) or 0)
        proto = packet_data.get('protocol', '')

        if a <= b:
            return (*a, *b, proto)
        else:
            return (*b, *a, proto)


# ── singleton ─────────────────────────────────────────────────────────────────

_flow_tracker_instance = None


def get_flow_tracker() -> FlowTracker:
    global _flow_tracker_instance
    if _flow_tracker_instance is None:
        _flow_tracker_instance = FlowTracker()
    return _flow_tracker_instance
