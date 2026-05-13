from dataclasses import dataclass
import os

@dataclass
class GuardConfig:
    poll_interval_sec: float = 1.0
    stats_file: str = "/tmp/guard_stats.json"
    block_file: str = "/tmp/guard_block.txt"

    tvc_threshold: int = 2
    tvc_window_sec: int = 30
    tvc_key: str = "flow_id"

    model_path: str = "best_model.joblib"
    retrain_every_sec: int = 180
    min_buffer_to_retrain: int = 200
    test_size: float = 0.25
    random_state: int = 42
    ml_prob_threshold: float = 0.70

    stats_log_dir: str = os.environ.get("GUARD_LOG_DIR", "/home/admsys/modul/modul/logs")
    stats_log_enabled: bool = True

    penalized_window_sec: int = 300
    recovering_window_sec: int = 60

