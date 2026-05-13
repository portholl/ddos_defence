#!/usr/bin/env bash
set -e

BASE_DIR="/home/admsys/modul/modul"
cd "${BASE_DIR}"

chmod +x run_experiment.sh

echo "=================================================="
echo "Running full suite:"
echo "  normal"
echo "  attack"
echo "  scan"
echo "  mixed"
echo "=================================================="

# normal: 15 мин
./run_experiment.sh normal 900 12 1.0 11

# attack: 15 мин
./run_experiment.sh attack 900 12 1.0 17

# scan: 15 мин
./run_experiment.sh scan 900 12 1.0 23

# mixed: 20 мин
./run_experiment.sh mixed 1200 12 1.0 42

echo "=================================================="
echo "[DONE] All experiments finished"
echo "Produced files:"
ls -la "${BASE_DIR}/logs"/exp_*.csv "${BASE_DIR}/logs"/gt_*.jsonl 2>/dev/null || true
echo "=================================================="
