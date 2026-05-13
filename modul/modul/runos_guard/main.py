import os
import signal
import time

from .config import GuardConfig
from .runos_client import RunosFileClient
from .decision_engine import DecisionEngine
from .background_tasks import BackgroundRetrainer
from .stats_logger import StatsLogger
from .logger import log

def main() -> None:
    cfg = GuardConfig()
    
    client = RunosFileClient(stats_file=cfg.stats_file, block_file=cfg.block_file)
    
    stats_logger = None
    if cfg.stats_log_enabled:
        stats_logger = StatsLogger(log_dir=cfg.stats_log_dir)

    engine = DecisionEngine(cfg, client, stats_logger=stats_logger)
    retrainer = BackgroundRetrainer(cfg, engine)
    retrainer.start()

    def _shutdown(sig, frame):
        log({"kind": "shutdown", "signal": sig})
        retrainer.stop()
        if stats_logger:
            stats_logger.close()
        raise SystemExit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    log({
        "kind": "guard_start",
        "mode": "FILE_IPC",
        "log_dir": cfg.stats_log_dir,
    })

    try:
        while True:
            engine.poll_once()
            time.sleep(cfg.poll_interval_sec)
    except SystemExit:
        pass
    finally:
        retrainer.stop()
        if stats_logger:
            stats_logger.close()

if __name__ == "__main__":
    main()

