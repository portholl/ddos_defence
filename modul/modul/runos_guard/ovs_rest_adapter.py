from __future__ import annotations

import time
import re
import subprocess
from typing import Any, Dict, List, Tuple

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


BRIDGE = "s1"

FLOW_LINE_RE = re.compile(r".*?priority=\d+,(?P<match>.*?) actions=(?P<actions>.*)$")

def sh(cmd: List[str]) -> str:
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8", errors="ignore")

def get_dpid() -> str:
    out = sh(["ovs-ofctl", "-O", "OpenFlow13", "show", BRIDGE])
    for ln in out.splitlines():
        ln = ln.strip()
        if "dpid:" in ln:
            return ln.split("dpid:")[1].strip()
    return "0000000000000001"

def parse_field(s: str, key: str) -> str | None:
    m = re.search(rf"{key}=([^, ]+)", s)
    return m.group(1) if m else None

def parse_int(s: str, key: str) -> int | None:
    m = re.search(rf"{key}=(\d+)", s)
    return int(m.group(1)) if m else None

def proto_name(nw_proto: int) -> str:
    if nw_proto == 6:
        return "tcp"
    if nw_proto == 17:
        return "udp"
    return "ip"

def build_flow_id(dpid: str, proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
    return f"{dpid}|{proto}|{src_ip}:{src_port}->{dst_ip}:{dst_port}"


app = FastAPI()

# flow_id -> (ts, packets, bytes)
last: Dict[str, Tuple[float, int, int]] = {}


class BlockReq(BaseModel):
    flow_id: str
    why: str | None = None


@app.get("/guard/v1/stats")
def stats() -> Dict[str, Any]:
    dpid = get_dpid()
    dump = sh(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", BRIDGE])

    now = time.time()
    items: List[Dict[str, Any]] = []

    for line in dump.splitlines():
        line = line.strip()
        if "n_packets=" not in line or "n_bytes=" not in line:
            continue

        m = FLOW_LINE_RE.match(line)
        if not m:
            continue

        packets = parse_int(line, "n_packets") or 0
        bytes_ = parse_int(line, "n_bytes") or 0

        match = m.group("match")
        src_ip = parse_field(match, "nw_src")
        dst_ip = parse_field(match, "nw_dst")
        nw_proto = parse_int(match, "nw_proto") 

        if not (src_ip and dst_ip and nw_proto is not None):
            continue

        proto = proto_name(nw_proto)

        src_port = (
            parse_int(match, "tp_src")
            or parse_int(match, "tcp_src")
            or parse_int(match, "udp_src")
            or 0
        )
        dst_port = (
            parse_int(match, "tp_dst")
            or parse_int(match, "tcp_dst")
            or parse_int(match, "udp_dst")
            or 0
        )

        flow_id = build_flow_id(dpid, proto, src_ip, src_port, dst_ip, dst_port)

        prev = last.get(flow_id)
        last[flow_id] = (now, packets, bytes_)

        pps = 0.0
        bps = 0.0
        avg_pkt = 0.0
        if prev:
            prev_ts, prev_p, prev_b = prev
            dt = max(now - prev_ts, 1e-6)
            dp = max(packets - prev_p, 0)
            db = max(bytes_ - prev_b, 0)
            pps = dp / dt
            bps = (db * 8) / dt
            avg_pkt = (db / dp) if dp > 0 else 0.0

        runos_triggers = {
            "syn_flood": 1 if pps > 2000 else 0,
            "port_scan": 0,
        }

        items.append({
            "ts": now,
            "flow_id": flow_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,

            "pps_in": pps,
            "bps_in": bps,

            "syn_rate": 0.0,
            "fin_rate": 0.0,
            "rst_rate": 0.0,
            "unique_dst_ports": 1.0,

            "avg_pkt_size": avg_pkt,
            "runos_triggers": runos_triggers,
        })

    return {"items": items}


@app.post("/guard/v1/block")
def block(req: BlockReq) -> Dict[str, Any]:
    try:
        _, proto, rest = req.flow_id.split("|", 2)
        left, right = rest.split("->", 1)
        src_ip, src_port = left.split(":")
        dst_ip, dst_port = right.split(":")
        src_port = int(src_port)
        dst_port = int(dst_port)
    except Exception:
        raise HTTPException(400, "bad flow_id format")

    if proto == "tcp":
        match = f"priority=50000,ip,tcp,nw_src={src_ip},nw_dst={dst_ip},tp_src={src_port},tp_dst={dst_port}"
    elif proto == "udp":
        match = f"priority=50000,ip,udp,nw_src={src_ip},nw_dst={dst_ip},tp_src={src_port},tp_dst={dst_port}"
    else:
        match = f"priority=50000,ip,nw_src={src_ip},nw_dst={dst_ip}"

    sh(["ovs-ofctl", "-O", "OpenFlow13", "add-flow", BRIDGE, f"{match} actions=drop"])

    return {"ok": True, "flow_id": req.flow_id, "why": req.why}
