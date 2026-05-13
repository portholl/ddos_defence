# runos_guard/logger.py
import json
import time
from typing import Any, Dict

def log(event: Dict[str, Any]) -> None:
    event.setdefault("event", "RUNOS_GUARD")
    event.setdefault("ts", time.time())
    print(json.dumps(event, ensure_ascii=False))
