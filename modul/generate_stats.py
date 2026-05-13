#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


STATS_FILE = Path("/tmp/guard_stats.json")
GROUND_TRUTH_FILE = Path("/tmp/guard_ground_truth.jsonl")
BLOCK_FILE = Path("/tmp/guard_block.txt")


@dataclass
class FlowState:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str = "tcp"

    baseline_pps: float = 100.0
    baseline_bps: float = 1_000_000.0
    baseline_pkt_size: float = 900.0

    syn_bias: float = 10.0
    fin_bias: float = 4.0
    rst_bias: float = 1.0
    port_bias: float = 2.0

    phase: float = field(default_factory=lambda: random.uniform(0, 2 * math.pi))
    drift: float = field(default_factory=lambda: random.uniform(0.95, 1.05))

    blocked: bool = False
    last_mode: str = "normal"

    def make_item_and_label(self, ts: float, tick: int, mode: str) -> tuple[Dict, Dict]:
        if self.blocked:
            pps = random.uniform(0.0, 2.0)
            bps = random.uniform(0.0, 2000.0)
            syn_rate = random.uniform(0.0, 0.5)
            fin_rate = random.uniform(0.0, 0.2)
            rst_rate = random.uniform(0.0, 0.2)
            unique_dst_ports = 1.0
            avg_pkt_size = random.uniform(300, 1200)
            triggers = {"syn_flood": 0, "port_scan": 0}
            label = 0
            return self._stats_item(ts, pps, bps, syn_rate, fin_rate, rst_rate, unique_dst_ports, avg_pkt_size, triggers), \
                   self._gt_item(ts, label, "blocked_quiet")

        wave = 1.0 + 0.20 * math.sin(tick / 8.0 + self.phase)
        micro = 1.0 + random.uniform(-0.08, 0.08)
        scale = self.drift * wave * micro

        if mode == "normal":
            pps = max(1.0, self.baseline_pps * scale)
            avg_pkt_size = max(64.0, self.baseline_pkt_size * (1.0 + random.uniform(-0.12, 0.12)))
            bps = pps * avg_pkt_size * 8.0

            syn_rate = max(0.0, self.syn_bias * (1.0 + random.uniform(-0.4, 0.4)))
            fin_rate = max(0.0, self.fin_bias * (1.0 + random.uniform(-0.5, 0.5)))
            rst_rate = max(0.0, self.rst_bias * (1.0 + random.uniform(-0.8, 0.8)))
            unique_dst_ports = max(1.0, self.port_bias * (1.0 + random.uniform(-0.4, 0.4)))

            triggers = {"syn_flood": 0, "port_scan": 0}
            label = 0

        elif mode == "attack_syn":
            attack_scale = random.uniform(5.0, 15.0)
            pps = max(200.0, self.baseline_pps * attack_scale)
            avg_pkt_size = random.uniform(100.0, 400.0)
            bps = pps * avg_pkt_size * 8.0

            syn_rate = max(120.0, pps * random.uniform(0.4, 0.85))
            fin_rate = random.uniform(0.0, 3.0)
            rst_rate = random.uniform(0.0, 15.0)
            unique_dst_ports = random.uniform(1.0, 4.0)

            triggers = {
                "syn_flood": 1 if syn_rate > 120 else 0,
                "port_scan": 0,
            }
            label = 1

        elif mode == "attack_scan":
            pps = max(80.0, self.baseline_pps * random.uniform(1.5, 5.0))
            avg_pkt_size = random.uniform(80.0, 300.0)
            bps = pps * avg_pkt_size * 8.0

            syn_rate = random.uniform(30.0, 150.0)
            fin_rate = random.uniform(0.0, 2.0)
            rst_rate = random.uniform(0.0, 8.0)
            unique_dst_ports = random.uniform(20.0, 80.0)

            triggers = {
                "syn_flood": 0,
                "port_scan": 1 if unique_dst_ports > 20 else 0,
            }
            label = 1

        elif mode == "mixed_suspicious":
            pps = max(50.0, self.baseline_pps * random.uniform(2.0, 6.0))
            avg_pkt_size = random.uniform(250.0, 700.0)
            bps = pps * avg_pkt_size * 8.0

            syn_rate = random.uniform(40.0, 180.0)
            fin_rate = random.uniform(0.0, 6.0)
            rst_rate = random.uniform(0.0, 15.0)
            unique_dst_ports = random.uniform(4.0, 25.0)

            triggers = {
                "syn_flood": 1 if syn_rate > 120 and pps > 600 else 0,
                "port_scan": 1 if unique_dst_ports > 20 else 0,
            }
            label = 1

        else:
            raise ValueError(f"Unknown mode: {mode}")

        return self._stats_item(ts, pps, bps, syn_rate, fin_rate, rst_rate, unique_dst_ports, avg_pkt_size, triggers), \
               self._gt_item(ts, label, mode)

    def _stats_item(
        self,
        ts: float,
        pps: float,
        bps: float,
        syn_rate: float,
        fin_rate: float,
        rst_rate: float,
        unique_dst_ports: float,
        avg_pkt_size: float,
        triggers: Dict[str, int],
    ) -> Dict:
        return {
            "ts": ts,
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "pps_in": round(pps, 3),
            "bps_in": round(bps, 3),
            "syn_rate": round(syn_rate, 3),
            "fin_rate": round(fin_rate, 3),
            "rst_rate": round(rst_rate, 3),
            "unique_dst_ports": round(unique_dst_ports, 3),
            "avg_pkt_size": round(avg_pkt_size, 3),
            "runos_triggers": triggers
        }

    def _gt_item(self, ts: float, label: int, mode: str) -> Dict:
        return {
            "ts": ts,
            "flow_id": self.flow_id,
            "label": int(label),
            "mode": mode
        }


class RealisticTrafficGenerator:
    def __init__(
        self,
        mode: str = "mixed",
        n_flows: int = 12,
        tick_sec: float = 1.0,
        seed: Optional[int] = 42,
        reset_ground_truth: bool = True,
    ):
        self.mode = mode
        self.n_flows = n_flows
        self.tick_sec = tick_sec
        self.rng = random.Random(seed)
        self.tick = 0
        self.flows = self._build_flows()

        if reset_ground_truth:
            GROUND_TRUTH_FILE.write_text("", encoding="utf-8")

    def _build_flows(self) -> List[FlowState]:
        flows: List[FlowState] = []
        for i in range(1, self.n_flows + 1):
            src_ip = f"10.0.0.{i}"
            dst_ip = f"10.0.1.{(i % 4) + 1}"
            src_port = self.rng.randint(1024, 65000)
            dst_port = self.rng.choice([22, 53, 80, 123, 443, 8080])

            proto = "tcp"
            dpid = "0000000000000001"
            flow_id = f"{dpid}|{proto}|{src_ip}:{src_port}->{dst_ip}:{dst_port}"

            baseline_pps = self.rng.uniform(40, 250)
            baseline_pkt = self.rng.uniform(500, 1200)
            baseline_bps = baseline_pps * baseline_pkt * 8.0

            flows.append(
                FlowState(
                    flow_id=flow_id,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    proto=proto,
                    baseline_pps=baseline_pps,
                    baseline_bps=baseline_bps,
                    baseline_pkt_size=baseline_pkt,
                    syn_bias=self.rng.uniform(5, 25),
                    fin_bias=self.rng.uniform(1, 8),
                    rst_bias=self.rng.uniform(0.5, 3),
                    port_bias=self.rng.uniform(1, 4),
                )
            )
        return flows

    def _load_blocked(self) -> None:
        if not BLOCK_FILE.exists():
            return
        try:
            blocked_ids = {
                line.strip()
                for line in BLOCK_FILE.read_text(encoding="utf-8").splitlines()
                if line.strip()
            }
            for f in self.flows:
                if f.flow_id in blocked_ids:
                    f.blocked = True
        except Exception:
            pass

    def _choose_mode_for_flow(self, idx: int) -> str:
        if self.mode == "normal":
            return "normal"
        if self.mode == "attack":
            return "attack_syn" if idx < max(2, self.n_flows // 4) else "normal"
        if self.mode == "scan":
            return "attack_scan" if idx < max(2, self.n_flows // 4) else "normal"
        if self.mode == "mixed":
            r = self.rng.random()
            if r < 0.65:
                return "normal"
            elif r < 0.82:
                return "mixed_suspicious"
            elif r < 0.92:
                return "attack_scan"
            else:
                return "attack_syn"
        raise ValueError(f"Unsupported mode: {self.mode}")

    def make_batch(self) -> tuple[Dict, List[Dict]]:
        self._load_blocked()
        self.tick += 1
        ts = time.time()
        items = []
        gt_items = []

        for idx, flow in enumerate(self.flows):
            flow_mode = self._choose_mode_for_flow(idx)
            flow.last_mode = flow_mode
            item, gt = flow.make_item_and_label(ts, self.tick, flow_mode)
            items.append(item)
            gt_items.append(gt)

        return {"items": items}, gt_items

    def run_forever(self) -> None:
        print(f"[generator] mode={self.mode} stats={STATS_FILE} gt={GROUND_TRUTH_FILE}")
        while True:
            batch, gt_items = self.make_batch()

            STATS_FILE.write_text(
                json.dumps(batch, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )

            with GROUND_TRUTH_FILE.open("a", encoding="utf-8") as f:
                for row in gt_items:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")

            print(f"[generator] tick={self.tick} wrote {len(batch['items'])} stats items")
            time.sleep(self.tick_sec)


def main():
    parser = argparse.ArgumentParser(description="Realistic traffic stats generator (ground truth separated)")
    parser.add_argument("--mode", choices=["normal", "attack", "scan", "mixed"], default="mixed")
    parser.add_argument("--flows", type=int, default=12)
    parser.add_argument("--tick", type=float, default=1.0)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    gen = RealisticTrafficGenerator(
        mode=args.mode,
        n_flows=args.flows,
        tick_sec=args.tick,
        seed=args.seed,
        reset_ground_truth=True,
    )
    gen.run_forever()


if __name__ == "__main__":
    main()
