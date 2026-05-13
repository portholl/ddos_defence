"""
Background tasks module for RUNOS Guard.
"""
import time
import json
import threading

from .config import GuardConfig
from .decision_engine import DecisionEngine
from .logger import log

class BackgroundRetrainer:
    def __init__(self, cfg: GuardConfig, engine: DecisionEngine):
        self.cfg = cfg
        self.engine = engine
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._t.start()

    def stop(self) -> None:
        self._stop.set()
        self._t.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.is_set():
            time.sleep(self.cfg.retrain_every_sec)

            data = list(self.engine.buffer)
            if len(data) < self.cfg.min_buffer_to_retrain:
                continue

            promoted, best_f1 = self.engine.ml.retrain_and_maybe_promote(data)
            log({
                "kind": "retrain",
                "promoted": promoted,
                "best_f1": best_f1,
                "buffer_size": len(data),
            })
