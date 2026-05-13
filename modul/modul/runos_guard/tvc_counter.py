"""
Threshold Violation Counter (TVC) module for RUNOS Guard.
"""
from typing import Dict, Deque, Tuple
from collections import defaultdict, deque

from .config import GuardConfig

class TVCCounter:
    def __init__(self, cfg: GuardConfig):
        self.cfg = cfg
        self.events: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self.blocked: Dict[str, float] = {}

    def _cleanup(self, key: str, now: float) -> None:
        q = self.events[key]
        while q and (now - q[0][0]) > self.cfg.tvc_window_sec:
            q.popleft()

    def add(self, key: str, ts: float, inc: int) -> int:
        self.events[key].append((ts, int(inc)))
        self._cleanup(key, ts)
        return self.value(key, ts)

    def value(self, key: str, now: float) -> int:
        self._cleanup(key, now)
        return int(sum(inc for _, inc in self.events[key]))

    def should_block(self, key: str, now: float) -> bool:
        if key in self.blocked:
            return False
        return self.value(key, now) >= self.cfg.tvc_threshold

    def mark_blocked(self, key: str, now: float) -> None:
        self.blocked[key] = now
