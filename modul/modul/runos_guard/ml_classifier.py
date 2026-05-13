"""
ML classifier — Decision Tree.
"""
from __future__ import annotations

import time
from typing import List, Optional, Tuple

import numpy as np
import joblib

from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.metrics import f1_score, classification_report
from sklearn.model_selection import train_test_split

from .config import GuardConfig
from .features import FeatureExtractor
from .dtos import TrafficStats
from .logger import log


class MLClassifier:
    def __init__(self, cfg: GuardConfig, extractor: FeatureExtractor):
        self.cfg       = cfg
        self.extractor = extractor
        self.model: Optional[DecisionTreeClassifier] = None
        self.best_f1: float = -1.0
        self._load_if_exists()

    def _new_model(self) -> DecisionTreeClassifier:
        return DecisionTreeClassifier(
            max_depth        = 8,
            min_samples_split= 10,
            min_samples_leaf = 5,
            class_weight     = "balanced",
            random_state     = self.cfg.random_state,
            criterion        = "gini",
        )

    def _load_if_exists(self) -> None:
        try:
            obj        = joblib.load(self.cfg.model_path)
            self.model = obj["model"]
            self.best_f1 = float(obj.get("best_f1", -1.0))
            log({
                "kind":    "model_loaded",
                "path":    self.cfg.model_path,
                "best_f1": self.best_f1,
            })
        except Exception:
            self.model = self._new_model()
            log({"kind": "model_new", "msg": "no saved model, will train on first batch"})

    def predict_proba_attack(self, s: TrafficStats) -> float:
        if self.model is None:
            self.model = self._new_model()

        if not hasattr(self.model, "classes_"):
            return 0.0

        x      = self.extractor.to_vector(s).reshape(1, -1)
        proba  = self.model.predict_proba(x)[0]
        classes = list(self.model.classes_)

        if 1 not in classes:
            return 0.0

        return float(proba[classes.index(1)])

    def retrain_and_maybe_promote(
        self, dataset: List[TrafficStats]
    ) -> Tuple[bool, float]:
        rows = [s for s in dataset if s.label in (0, 1)]

        if len(rows) < 50:
            log({
                "kind":   "retrain_skip",
                "reason": "not enough labeled data",
                "count":  len(rows),
            })
            return (False, self.best_f1)

        X = np.stack([self.extractor.to_vector(s) for s in rows], axis=0)
        y = np.array([s.label for s in rows], dtype=np.int32)

        if len(np.unique(y)) < 2:
            log({
                "kind":    "retrain_skip",
                "reason":  "only one class present",
                "classes": np.unique(y).tolist(),
            })
            return (False, self.best_f1)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size    = self.cfg.test_size,
            random_state = self.cfg.random_state,
            stratify     = y,
        )

        m = self._new_model()
        m.fit(X_train, y_train)

        y_hat  = m.predict(X_test)
        f1     = f1_score(y_test, y_hat, zero_division=0)
        report = classification_report(
            y_test, y_hat, zero_division=0, output_dict=True
        )

        tree_text = export_text(
            m,
            feature_names = FeatureExtractor.FEATURE_NAMES,
            max_depth     = 4,
        )

        log({
            "kind":         "retrain_result",
            "new_f1":       f1,
            "best_f1":      self.best_f1,
            "promoted":     f1 > self.best_f1,
            "train_size":   len(X_train),
            "test_size":    len(X_test),
            "report":       report,
            "tree_preview": tree_text[:500],
        })

        if f1 > self.best_f1:
            self.model   = m
            self.best_f1 = float(f1)
            joblib.dump(
                {
                    "model":         self.model,
                    "best_f1":       self.best_f1,
                    "trained_at":    time.time(),
                    "feature_names": FeatureExtractor.FEATURE_NAMES,
                },
                self.cfg.model_path,
            )
            log({
                "kind":    "model_promoted",
                "best_f1": self.best_f1,
                "path":    self.cfg.model_path,
            })
            return (True, self.best_f1)

        return (False, self.best_f1)

    def get_tree_rules(self, max_depth: int = 4) -> str:
        if not hasattr(self.model, "classes_"):
            return "Model not trained yet"
        return export_text(
            self.model,
            feature_names = FeatureExtractor.FEATURE_NAMES,
            max_depth     = max_depth,
        )

