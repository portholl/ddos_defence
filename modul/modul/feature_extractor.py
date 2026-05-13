"""
Feature extraction module for RUNOS Guard system.

Provides functions to extract features from packets and statistics,
and a class to convert TrafficStats to feature vectors for ML models.
"""
import numpy as np
from .models import PacketIn, SwitchStats, TrafficStats


def features_from_packet(pkt: PacketIn) -> dict:
    """Extract features from a packet for analysis."""
    return {
        "dpid": pkt.dpid,
        "in_port": pkt.in_port,
        "src_ip": pkt.src_ip or "",
        "dst_ip": pkt.dst_ip or "",
        "ip_proto": pkt.ip_proto or -1,
        "src_port": pkt.src_port or -1,
        "dst_port": pkt.dst_port or -1,
        "payload_len": pkt.payload_len or 0,
    }


def features_from_stats(st: SwitchStats) -> dict:
    """Extract features from switch statistics."""
    return {
        "dpid": st.dpid,
        "ports_count": len(st.ports),
        "flows_count": len(st.flows),
    }


def flow_key(pkt: PacketIn) -> str:
    """Generate a unique key for a flow based on packet information."""
    # Ключ, по которому считаем TVC
    return f"{pkt.src_ip}:{pkt.src_port}->{pkt.dst_ip}:{pkt.dst_port}/p{pkt.ip_proto}"


class FeatureExtractor:
    """Extracts feature vectors from TrafficStats for ML models."""
    
    FEATURE_NAMES = [
        "pps_in", "bps_in", "syn_rate", "fin_rate", "rst_rate",
        "unique_dst_ports", "avg_pkt_size",
    ]

    def to_vector(self, s: TrafficStats) -> np.ndarray:
        """Convert TrafficStats to a numpy feature vector."""
        return np.array([getattr(s, f) for f in self.FEATURE_NAMES], dtype=np.float32)
