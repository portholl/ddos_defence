"""
Utility functions for RUNOS Guard.
"""
import time
import json
from typing import List

from .config import GuardConfig
from .dtos import TrafficStats
from .decision_engine import DecisionEngine

def warmup_train_from_dataset_csv(cfg: GuardConfig, engine: DecisionEngine, csv_path: str) -> None:
    import pandas as pd
    df = pd.read_csv(csv_path)

    samples: List[TrafficStats] = []
    for _, r in df.iterrows():
        s = TrafficStats(
            ts=time.time(),
            flow_id="dataset",
            src_ip="0.0.0.0",
            dst_ip="0.0.0.0",
            pps_in=float(r["pps_in"]),
            bps_in=float(r["bps_in"]),
            syn_rate=float(r["syn_rate"]),
            fin_rate=float(r["fin_rate"]),
            rst_rate=float(r["rst_rate"]),
            unique_dst_ports=float(r["unique_dst_ports"]),
            avg_pkt_size=float(r["avg_pkt_size"]),
            runos_triggers={"syn_flood": 0, "port_scan": 0},
            label=int(r["label"])
        )
        samples.append(s)

    promoted, best_f1 = engine.ml.retrain_and_maybe_promote(samples)
    print(json.dumps({
        "event": "warmup_train",
        "promoted": promoted,
        "best_f1": best_f1,
        "samples": len(samples)
    }, ensure_ascii=False))
