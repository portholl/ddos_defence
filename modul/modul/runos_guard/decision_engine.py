"""
Decision engine module for RUNOS Guard.
"""
from __future__ import annotations

from collections import deque
from typing import Deque, Optional

from .config import GuardConfig
from .dtos import TrafficStats, Decision
from .runos_client import RunosClientBase
from .features import FeatureExtractor
from .ml_classifier import MLClassifier
from .tvc_counter import TVCCounter
from .flow_state import FlowStateMachine, FlowState
from .stats_logger import StatsLogger
from .logger import log


class DecisionEngine:
    def __init__(
        self,
        cfg: GuardConfig,
        client: RunosClientBase,
        stats_logger: Optional[StatsLogger] = None,
    ):
        self.cfg          = cfg
        self.client       = client
        self.extractor    = FeatureExtractor()
        self.ml           = MLClassifier(cfg, self.extractor)
        self.tvc          = TVCCounter(cfg)
        self.fsm          = FlowStateMachine(
            penalized_window_sec  = cfg.penalized_window_sec,
            recovering_window_sec = cfg.recovering_window_sec,
        )
        self.buffer: Deque[TrafficStats] = deque(maxlen=50_000)
        self.stats_logger = stats_logger

    def _key(self, s: TrafficStats) -> str:
        return getattr(s, self.cfg.tvc_key)

    def analyze_one(self, s: TrafficStats) -> Decision:
        key = self._key(s)
        now = s.ts

        triggers_sum = int(sum(int(v) for v in s.runos_triggers.values()))
        ml_prob      = self.ml.predict_proba_attack(s)
        ml_fire      = 1 if ml_prob >= self.cfg.ml_prob_threshold else 0

        tvc_val = self.tvc.add(
            key, now,
            inc=(1 if (ml_fire or triggers_sum > 0) else 0),
        )

        flow_state = self.fsm.transition(
            key, tvc_val, self.cfg.tvc_threshold, now
        )

        reasons = []
        if triggers_sum > 0:
            reasons.append(f"RUNOS_TRIGGERS={s.runos_triggers}")
        if ml_fire:
            reasons.append(f"ML_FIRE prob={ml_prob:.3f}")

        should_block = (
            flow_state == FlowState.PENALIZED
            and self.tvc.should_block(key, now)
        )

        if should_block:
            reasons.append(f"TVC={tvc_val} >= {self.cfg.tvc_threshold}")
            reasons.append(f"FSM={flow_state.value}")

        return Decision(
            should_block  = should_block,
            reasons       = reasons,
            ml_prob       = ml_prob,
            tvc_value     = tvc_val,
            triggers_sum  = triggers_sum,
            flow_state    = flow_state.value,
        )

    def on_decision(self, s: TrafficStats, d: Decision) -> None:
        key = self._key(s)
        self.buffer.append(s)

        if d.should_block:
            status = "BLOCK"
        elif d.flow_state == FlowState.PENALIZED.value:
            status = "PENALIZED"
        elif d.flow_state == FlowState.RECOVERING.value:
            status = "RECOVERING"
        elif d.tvc_value > 0:
            status = "SUSPECT"
        else:
            status = "NORMAL"

        record = {
            "kind":       "decision",
            "status":     status,
            "key":        key,
            "flow_id":    s.flow_id,
            "src_ip":     s.src_ip,
            "dst_ip":     s.dst_ip,
            "ml_prob":    d.ml_prob,
            "tvc":        d.tvc_value,
            "flow_state": d.flow_state,
            "runos_triggers": s.runos_triggers,
            "features": {
                "pps_in":           s.pps_in,
                "bps_in":           s.bps_in,
                "syn_rate":         s.syn_rate,
                "fin_rate":         s.fin_rate,
                "rst_rate":         s.rst_rate,
                "unique_dst_ports": s.unique_dst_ports,
                "avg_pkt_size":     s.avg_pkt_size,
            },
            "label":        s.label,
            "should_block": d.should_block,
            "reasons":      d.reasons,
        }

        log(record)

        if self.stats_logger:
            self.stats_logger.write(record)

        if d.should_block:
            why = "; ".join(d.reasons) if d.reasons else "policy"
            self.client.send_block(key=key, why=why)
            self.tvc.mark_blocked(key, s.ts)

    def poll_once(self) -> None:
        batch = self.client.get_stats()
        for s in batch:
            d = self.analyze_one(s)
            self.on_decision(s, d)
