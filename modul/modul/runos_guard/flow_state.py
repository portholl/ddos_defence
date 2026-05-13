"""
Flow State Machine: NORMAL → SUSPECT → PENALIZED → RECOVERING → NORMAL
"""
from __future__ import annotations

import time
from enum import Enum
from typing import Dict
from dataclasses import dataclass, field

from .logger import log


class FlowState(Enum):
    NORMAL     = "NORMAL"
    SUSPECT    = "SUSPECT"
    PENALIZED  = "PENALIZED"
    RECOVERING = "RECOVERING"


@dataclass
class FlowStateEntry:
    state: FlowState = FlowState.NORMAL
    state_since: float = field(default_factory=time.time)
    penalized_at: float = 0.0
    tvc_at_penalize: int = 0


class FlowStateMachine:
    """
    NORMAL → SUSPECT → PENALIZED → RECOVERING → NORMAL
    """

    def __init__(
        self,
        penalized_window_sec: int = 300,
        recovering_window_sec: int = 60,
    ):
        self.penalized_window_sec  = penalized_window_sec
        self.recovering_window_sec = recovering_window_sec
        self._states: Dict[str, FlowStateEntry] = {}

    def get_state(self, key: str) -> FlowState:
        return self._states.get(key, FlowStateEntry()).state

    def _entry(self, key: str) -> FlowStateEntry:
        if key not in self._states:
            self._states[key] = FlowStateEntry()
        return self._states[key]

    def transition(
        self,
        key: str,
        tvc_value: int,
        tvc_threshold: int,
        now: float,
    ) -> FlowState:
        e    = self._entry(key)
        prev = e.state

        if e.state == FlowState.NORMAL:
            if tvc_value > 0:
                e.state       = FlowState.SUSPECT
                e.state_since = now

        elif e.state == FlowState.SUSPECT:
            if tvc_value >= tvc_threshold:
                e.state          = FlowState.PENALIZED
                e.state_since    = now
                e.penalized_at   = now
                e.tvc_at_penalize = tvc_value
            elif tvc_value == 0:
                e.state       = FlowState.NORMAL
                e.state_since = now

        elif e.state == FlowState.PENALIZED:
            if (now - e.penalized_at) >= self.penalized_window_sec:
                e.state       = FlowState.RECOVERING
                e.state_since = now

        elif e.state == FlowState.RECOVERING:
            elapsed = now - e.state_since
            if elapsed >= self.recovering_window_sec:
                e.state       = FlowState.NORMAL
                e.state_since = now
                log({
                    "kind":      "flow_recovered",
                    "key":       key,
                    "after_sec": elapsed,
                })

        if prev != e.state:
            log({
                "kind": "state_transition",
                "key":  key,
                "from": prev.value,
                "to":   e.state.value,
                "tvc":  tvc_value,
            })

        return e.state

    def reset(self, key: str) -> None:
        if key in self._states:
            self._states[key] = FlowStateEntry()
            log({"kind": "flow_reset", "key": key})

    def is_blocked(self, key: str) -> bool:
        return self.get_state(key) == FlowState.PENALIZED
