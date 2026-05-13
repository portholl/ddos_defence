from __future__ import annotations

import csv
import os
import time
import threading
from typing import Any, Dict, Optional

CSV_COLUMNS = [
    "ts",
    "datetime",
    "kind",
    "status",

    "flow_id",
    "src_ip",
    "dst_ip",
    "key",

    "pps_in",
    "bps_in",
    "syn_rate",
    "fin_rate",
    "rst_rate",
    "unique_dst_ports",
    "avg_pkt_size",

    "ml_prob",

    "tvc",
    "flow_state",

    "trigger_syn_flood",
    "trigger_port_scan",

    "label",

    "should_block",
    "reasons",

    "retrain_new_f1",
    "retrain_best_f1",
    "retrain_promoted",
    "retrain_train_size",
    "retrain_test_size",

    "extra",
]


def _fmt_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _safe(v: Any, default: str = "") -> str:
    if v is None:
        return default
    return str(v).replace("\n", " ").replace("\r", "")


class StatsLogger:

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        ts_str = time.strftime("%Y-%m-%d_%H-%M-%S")
        self.filepath = os.path.join(log_dir, f"guard_{ts_str}.csv")

        self._lock = threading.Lock()

        self._fh = open(self.filepath, "w", newline="", encoding="utf-8")
        self._writer = csv.DictWriter(
            self._fh,
            fieldnames=CSV_COLUMNS,
            extrasaction="ignore",
        )
        self._writer.writeheader()
        self._fh.flush()

        self.write({"kind": "session_start"})

        print(f"[StatsLogger] Writing to: {self.filepath}")


    def write(self, record: Dict[str, Any]) -> None:
        row = self._normalize(record)
        with self._lock:
            self._writer.writerow(row)
            self._fh.flush()

    def close(self) -> None:
        self.write({"kind": "session_end"})
        with self._lock:
            self._fh.close()


    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


    def _normalize(self, record: Dict[str, Any]) -> Dict[str, str]
        ts = float(record.get("ts", time.time()))
        kind = record.get("kind", "")

        triggers = record.get("runos_triggers", {}) or {}
        if isinstance(triggers, str):
            import json as _json
            try:
                triggers = _json.loads(triggers)
            except Exception:
                triggers = {}

        features = record.get("features", {}) or {}

        def feat(name: str) -> str:
            v = features.get(name, record.get(name))
            return _safe(v)

        reasons = record.get("reasons", [])
        if isinstance(reasons, list):
            reasons_str = " | ".join(str(r) for r in reasons)
        else:
            reasons_str = _safe(reasons)

        known_keys = {
            "ts", "datetime", "kind", "status",
            "flow_id", "src_ip", "dst_ip", "key",
            "pps_in", "bps_in", "syn_rate", "fin_rate", "rst_rate",
            "unique_dst_ports", "avg_pkt_size",
            "ml_prob", "tvc", "flow_state",
            "trigger_syn_flood", "trigger_port_scan",
            "label", "should_block", "reasons",
            "retrain_new_f1", "retrain_best_f1", "retrain_promoted",
            "retrain_train_size", "retrain_test_size",
            "runos_triggers", "features",
            "event",
        }

        extra_parts = {
            k: v for k, v in record.items()
            if k not in known_keys
        }
        extra_str = "; ".join(f"{k}={v}" for k, v in extra_parts.items())

        row: Dict[str, str] = {
            "ts":         f"{ts:.3f}",
            "datetime":   _fmt_ts(ts),
            "kind":       _safe(kind),
            "status":     _safe(record.get("status")),

            "flow_id":    _safe(record.get("flow_id")),
            "src_ip":     _safe(record.get("src_ip")),
            "dst_ip":     _safe(record.get("dst_ip")),
            "key":        _safe(record.get("key")),

            "pps_in":           feat("pps_in"),
            "bps_in":           feat("bps_in"),
            "syn_rate":         feat("syn_rate"),
            "fin_rate":         feat("fin_rate"),
            "rst_rate":         feat("rst_rate"),
            "unique_dst_ports": feat("unique_dst_ports"),
            "avg_pkt_size":     feat("avg_pkt_size"),

            "ml_prob":    _safe(record.get("ml_prob")),
            "tvc":        _safe(record.get("tvc")),
            "flow_state": _safe(record.get("flow_state")),

            "trigger_syn_flood": _safe(triggers.get("syn_flood")),
            "trigger_port_scan": _safe(triggers.get("port_scan")),

            "label":        _safe(record.get("label")),
            "should_block": _safe(record.get("should_block")),
            "reasons":      reasons_str,

            "retrain_new_f1":    _safe(record.get("new_f1")),
            "retrain_best_f1":   _safe(record.get("best_f1")),
            "retrain_promoted":  _safe(record.get("promoted")),
            "retrain_train_size":_safe(record.get("train_size")),
            "retrain_test_size": _safe(record.get("test_size")),

            "extra": extra_str,
        }

        return row
