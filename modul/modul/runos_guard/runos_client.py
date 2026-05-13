import json
import os
import time
from typing import List
from .dtos import TrafficStats
from .logger import log

class RunosClientBase:
    def get_stats(self) -> List[TrafficStats]:
        raise NotImplementedError
    def send_block(self, key: str, why: str) -> None:
        raise NotImplementedError

class RunosFileClient(RunosClientBase):
    def __init__(self, stats_file="/tmp/guard_stats.json", block_file="/tmp/guard_block.txt"):
        self.stats_file = stats_file
        self.block_file = block_file

    def get_stats(self) -> List[TrafficStats]:
        if not os.path.exists(self.stats_file):
            return []
            
        try:
            with open(self.stats_file, 'r') as f:
                data = json.load(f)
            items = data.get("items", [])
        except Exception as e:
            return []

        now = time.time()
        out: List[TrafficStats] = []
        for it in items:
            try:
                out.append(TrafficStats(
                    ts=float(it.get("ts", now)),
                    flow_id=str(it["flow_id"]),
                    src_ip=str(it["src_ip"]),
                    dst_ip=str(it["dst_ip"]),
                    pps_in=float(it.get("pps_in", 0.0)),
                    bps_in=float(it.get("bps_in", 0.0)),
                    syn_rate=float(it.get("syn_rate", 0.0)),
                    fin_rate=float(it.get("fin_rate", 0.0)),
                    rst_rate=float(it.get("rst_rate", 0.0)),
                    unique_dst_ports=float(it.get("unique_dst_ports", 0.0)),
                    avg_pkt_size=float(it.get("avg_pkt_size", 0.0)),
                    runos_triggers=dict(it.get("runos_triggers", {})),
                    label=None
                ))
            except Exception:
                pass
        return out

    def send_block(self, key: str, why: str) -> None:
        try:
            with open(self.block_file, 'a') as f:
                f.write(f"{key}\n")
            log({"kind": "action", "action": "BLOCK_SENT", "key": key, "why": why})
        except Exception as e:
            log({"kind": "runos_error", "op": "send_block", "key": key, "err": str(e)})

