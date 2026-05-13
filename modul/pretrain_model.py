#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import joblib
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split


FEATURES = [
    "pps_in",
    "bps_in",
    "syn_rate",
    "fin_rate",
    "rst_rate",
    "unique_dst_ports",
    "avg_pkt_size",
]


def load_stats_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("items", [])


def load_gt_jsonl(path: Path):
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def merge_stats_and_gt(stats_items, gt_items):
    gt_by_flow = {}
    for row in gt_items:
        gt_by_flow[row["flow_id"]] = int(row["label"])

    dataset = []
    for it in stats_items:
        fid = it["flow_id"]
        if fid not in gt_by_flow:
            continue
        x = [float(it.get(k, 0.0)) for k in FEATURES]
        y = gt_by_flow[fid]
        dataset.append((x, y))
    return dataset


def replicate_dataset(dataset, target_size: int, seed: int):
    rng = random.Random(seed)
    if not dataset:
        return []
    out = []
    while len(out) < target_size:
        out.append(rng.choice(dataset))
    return out[:target_size]


def main():
    parser = argparse.ArgumentParser(description="Pretrain initial ML model")
    parser.add_argument("--stats", required=True, help="Path to guard_stats.json snapshot")
    parser.add_argument("--gt", required=True, help="Path to guard_ground_truth.jsonl")
    parser.add_argument("--size", choices=["small", "large"], required=True)
    parser.add_argument("--out", required=True, help="Output .joblib path")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    stats_path = Path(args.stats)
    gt_path = Path(args.gt)
    out_path = Path(args.out)

    stats_items = load_stats_json(stats_path)
    gt_items = load_gt_jsonl(gt_path)
    dataset = merge_stats_and_gt(stats_items, gt_items)

    if not dataset:
        raise SystemExit("Dataset is empty after merge of stats and ground truth.")

    # Размеры для small / large
    target_size = 200 if args.size == "small" else 2000

    dataset = replicate_dataset(dataset, target_size=target_size, seed=args.seed)

    X = np.array([row[0] for row in dataset], dtype=np.float32)
    y = np.array([row[1] for row in dataset], dtype=np.int32)

    if len(np.unique(y)) < 2:
        raise SystemExit("Dataset has only one class after preparation.")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.25,
        random_state=args.seed,
        stratify=y
    )

    model = DecisionTreeClassifier(
        max_depth=8,
        min_samples_split=10,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=args.seed,
    )
    model.fit(X_train, y_train)

    y_hat = model.predict(X_test)
    f1 = f1_score(y_test, y_hat, zero_division=0)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model": model,
        "best_f1": float(f1),
        "feature_names": FEATURES,
        "meta": {
            "size": args.size,
            "target_size": target_size,
            "seed": args.seed,
            "train_size": len(X_train),
            "test_size": len(X_test)
        }
    }, out_path)

    print(f"Saved model: {out_path}")
    print(f"Model size: {args.size}")
    print(f"Samples   : {target_size}")
    print(f"F1        : {f1:.4f}")


if __name__ == "__main__":
    main()
