#!/usr/bin/env bash
set -e

MODE="${1:-mixed}"          # normal | attack | scan | mixed
DURATION="${2:-900}"        # секунды
FLOWS="${3:-12}"
TICK="${4:-1.0}"
SEED="${5:-42}"

BASE_DIR="/home/admsys/modul/modul"
LOG_DIR="${BASE_DIR}/logs"

TMP_STATS="/tmp/guard_stats.json"
TMP_BLOCK="/tmp/guard_block.txt"
TMP_GT="/tmp/guard_ground_truth.jsonl"

cd "${BASE_DIR}"
mkdir -p "${LOG_DIR}"

echo "=================================================="
echo "[run_experiment] mode      = ${MODE}"
echo "[run_experiment] duration  = ${DURATION} sec"
echo "[run_experiment] flows     = ${FLOWS}"
echo "[run_experiment] tick      = ${TICK}"
echo "[run_experiment] seed      = ${SEED}"
echo "=================================================="

echo "[1/8] Stopping old processes..."
pkill -f "python3 -m runos_guard.main" || true
pkill -f "python3 generate_stats.py" || true
sleep 2

echo "[2/8] Cleaning tmp files..."
rm -f "${TMP_STATS}" "${TMP_BLOCK}" "${TMP_GT}" || true
sleep 1

echo "[3/8] Checking tmp cleanup..."
[ -e "${TMP_STATS}" ] && echo "WARNING: ${TMP_STATS} still exists" || echo "OK: ${TMP_STATS} removed"
[ -e "${TMP_BLOCK}" ] && echo "WARNING: ${TMP_BLOCK} still exists" || echo "OK: ${TMP_BLOCK} removed"
[ -e "${TMP_GT}" ] && echo "WARNING: ${TMP_GT} still exists" || echo "OK: ${TMP_GT} removed"

echo "[4/8] Starting Python guard..."
python3 -m runos_guard.main > "${LOG_DIR}/guard_runtime_${MODE}.log" 2>&1 &
GUARD_PID=$!
echo "    Guard PID = ${GUARD_PID}"
sleep 4

echo "[5/8] Starting realistic generator..."
python3 generate_stats.py --mode "${MODE}" --flows "${FLOWS}" --tick "${TICK}" --seed "${SEED}" > "${LOG_DIR}/generator_${MODE}.log" 2>&1 &
GEN_PID=$!
echo "    Generator PID = ${GEN_PID}"
sleep 2

echo "[6/8] Running experiment for ${DURATION} seconds..."
sleep "${DURATION}"

echo "[7/8] Stopping processes..."
kill "${GEN_PID}" 2>/dev/null || true
kill "${GUARD_PID}" 2>/dev/null || true
sleep 3

echo "[8/8] Saving outputs..."

LATEST_CSV=$(ls -t "${LOG_DIR}"/guard_*.csv 2>/dev/null | head -n 1 || true)
TARGET_CSV="${LOG_DIR}/exp_${MODE}.csv"
TARGET_GT="${LOG_DIR}/gt_${MODE}.jsonl"

if [ -n "${LATEST_CSV}" ]; then
    mv "${LATEST_CSV}" "${TARGET_CSV}"
    echo "Saved CSV: ${TARGET_CSV}"
else
    echo "WARNING: No guard CSV found."
fi

if [ -f "${TMP_GT}" ]; then
    cp "${TMP_GT}" "${TARGET_GT}"
    echo "Saved ground truth: ${TARGET_GT}"
else
    echo "WARNING: Ground truth file not found: ${TMP_GT}"
fi

echo "Cleaning tmp files after experiment..."
rm -f "${TMP_STATS}" "${TMP_BLOCK}" "${TMP_GT}" || true

echo "=================================================="
echo "[DONE] Experiment '${MODE}' completed"
echo "Runtime logs:"
echo "  ${LOG_DIR}/guard_runtime_${MODE}.log"
echo "  ${LOG_DIR}/generator_${MODE}.log"
echo "Artifacts:"
echo "  ${TARGET_CSV}"
echo "  ${TARGET_GT}"
echo "=================================================="
