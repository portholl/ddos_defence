import time
from runos_guard.config import GuardConfig
from runos_guard.runos_client import RunosRestClient
from runos_guard.decision_engine import DecisionEngine
from runos_guard.background_tasks import BackgroundRetrainer

def main():
    cfg = GuardConfig(
        poll_interval_sec   = 1.0,
        tvc_threshold       = 2,
        tvc_window_sec      = 30,
        tvc_key             = "flow_id",
        ml_prob_threshold   = 0.70,
        retrain_every_sec   = 180,
        min_buffer_to_retrain = 200,
        model_path          = "best_model.joblib",
        runos_base_url      = "http://172.20.6.2:6480",
    )

    client  = RunosRestClient(base_url=cfg.runos_base_url)
    engine  = DecisionEngine(cfg, client)
    trainer = BackgroundRetrainer(cfg, engine)
    trainer.start()

    try:
        while True:
            engine.poll_once()
            time.sleep(cfg.poll_interval_sec)
    except KeyboardInterrupt:
        trainer.stop()

if __name__ == "__main__":
    main()
