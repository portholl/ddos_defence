"""
Data models for RUNOS Guard system.

Contains Pydantic models for network packets, switch statistics,
and dataclasses for traffic analysis and decision making.
"""
from pydantic import BaseModel
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class PacketIn(BaseModel):
    ts: float
    dpid: str
    in_port: int
    eth_type: int | None = None
    src_mac: str | None = None
    dst_mac: str | None = None

    src_ip: str | None = None
    dst_ip: str | None = None
    ip_proto: int | None = None
    src_port: int | None = None
    dst_port: int | None = None

    payload_len: int | None = None
    raw: dict[str, Any] = {}


class SwitchStats(BaseModel):
    ts: float
    dpid: str
    ports: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []


class MLScore(BaseModel):
    score: float
    label: str | None = None
    extra: dict[str, Any] = {}


@dataclass
class TrafficStats:
    """Traffic statistics for a flow or host."""
    ts: float
    flow_id: str
    src_ip: str
    dst_ip: str

    pps_in: float
    bps_in: float
    syn_rate: float
    fin_rate: float
    rst_rate: float
    unique_dst_ports: float
    avg_pkt_size: float

    runos_triggers: Dict[str, int]

    label: Optional[int] = None


@dataclass
class Decision:
    """Decision result from traffic analysis."""
    should_block: bool
    reasons: List[str] = field(default_factory=list)
    ml_prob: Optional[float] = None
    tvc_value: int = 0
    triggers_sum: int = 0
