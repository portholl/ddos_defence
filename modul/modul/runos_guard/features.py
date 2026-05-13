import numpy as np
from .dtos import TrafficStats

class FeatureExtractor:
    FEATURE_NAMES = [
        "pps_in", "bps_in", "syn_rate", "fin_rate", "rst_rate",
        "unique_dst_ports", "avg_pkt_size",
    ]

    def to_vector(self, s: TrafficStats) -> np.ndarray:
        return np.array([getattr(s, f) for f in self.FEATURE_NAMES], dtype=np.float32)
