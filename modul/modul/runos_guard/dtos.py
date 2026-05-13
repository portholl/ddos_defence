from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass
class TrafficStats:
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
    should_block: bool
    reasons: List[str] = field(default_factory=list)
    ml_prob: Optional[float] = None
    tvc_value: int = 0
    triggers_sum: int = 0
    flow_state:str = "NORMAL"

