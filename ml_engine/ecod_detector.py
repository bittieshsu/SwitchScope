"""
SwitchScope - Dual-Engine ECOD Outlier Detection
1. High-Performance Mode: Uses PyOD's C-accelerated ECOD algorithm when installed.
2. Zero-Dependency Safe Mode: Uses native Python math/empirical distribution calculations.
   100% resilient and immune to Python pip supply chain attacks (requires 0 pip packages).
"""
import math
from typing import List, Dict, Any

try:
    import numpy as np
    import pandas as pd
    from pyod.models.ecod import ECOD
    HAS_PYOD = True
except ImportError:
    HAS_PYOD = False
    np = None
    pd = None
    ECOD = None

class ECODPortDetector:
    def __init__(self, contamination: float = 0.08):
        self.contamination = contamination
        self.feature_names = [
            "crc_errors",
            "in_errors",
            "out_errors",
            "collisions",
            "in_drops",
            "out_drops"
        ]
        self.has_pyod = HAS_PYOD

    def detect(self, ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Runs ECOD outlier detection on port counter data.
        Falls back seamlessly to pure-Python ECOD if PyOD or NumPy are not installed.
        """
        if not ports:
            return {
                "anomalies": [],
                "total_ports": 0,
                "outlier_count": 0,
                "max_score": 0.0,
                "engine": "PyOD-ECOD (C-Accelerated)" if HAS_PYOD else "Zero-Dependency Native Python ECOD"
            }

        if HAS_PYOD:
            try:
                return self._detect_pyod(ports)
            except Exception:
                return self._detect_pure_python(ports)
        else:
            return self._detect_pure_python(ports)

    def _detect_pyod(self, ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        C-accelerated PyOD ECOD detection.
        """
        df = pd.DataFrame(ports)
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

        X = df[self.feature_names].values

        if np.all(X == 0):
            results = []
            for p in ports:
                results.append({
                    "port": p["port"],
                    "status": p.get("status", "unknown"),
                    "is_outlier": False,
                    "anomaly_score": 0.0,
                    "severity": "NORMAL",
                    "dominant_anomalous_feature": None,
                    "explanation": "All hardware counters normal (0 errors).",
                    "raw_counters": {k: 0 for k in self.feature_names}
                })
            return {
                "anomalies": results,
                "total_ports": len(ports),
                "outlier_count": 0,
                "max_score": 0.0,
                "engine": "PyOD-ECOD (C-Accelerated)"
            }

        if len(ports) < 3:
            return self._detect_pure_python(ports)

        effective_contamination = min(0.25, max(0.01, self.contamination))
        clf = ECOD(contamination=effective_contamination)
        clf.fit(X)

        raw_scores = clf.decision_scores_
        labels = clf.labels_

        min_s, max_s = raw_scores.min(), raw_scores.max()
        if max_s > min_s:
            norm_scores = (raw_scores - min_s) / (max_s - min_s)
        else:
            norm_scores = np.zeros_like(raw_scores)

        results = []
        outlier_count = 0

        feat_labels_map = {
            "crc_errors": "CRC 錯誤 (實體線路/光模組衰退)",
            "in_errors": "輸入錯誤 (Input Errors)",
            "out_errors": "輸出錯誤 (Output Errors)",
            "collisions": "衝突次數 (Collisions/雙工衝突)",
            "in_drops": "輸入佇列丟包 (Queue Drops)",
            "out_drops": "輸出佇列擁塞丟包"
        }

        for i, p in enumerate(ports):
            is_outlier = bool(labels[i] == 1)
            score = float(norm_scores[i])
            row = X[i]

            dominant_feat = None
            explanation = "All port counters in line with normal baseline."

            if is_outlier or score > 0.6 or any(row > 0):
                max_idx = int(np.argmax(row))
                val = row[max_idx]
                if val > 0:
                    dominant_feat = self.feature_names[max_idx]
                    is_outlier = True
                    score = max(score, 0.75)
                    label_desc = feat_labels_map.get(dominant_feat, dominant_feat)
                    explanation = f"{label_desc} 達 {int(val)} 次"

            if is_outlier:
                outlier_count += 1

            severity = "NORMAL"
            if score >= 0.8:
                severity = "CRITICAL"
            elif score >= 0.5:
                severity = "WARNING"

            results.append({
                "port": p["port"],
                "status": p.get("status", "unknown"),
                "is_outlier": is_outlier,
                "anomaly_score": round(score, 3),
                "severity": severity,
                "dominant_anomalous_feature": dominant_feat,
                "explanation": explanation,
                "raw_counters": {k: int(v) for k, v in zip(self.feature_names, row)}
            })

        results.sort(key=lambda x: x["anomaly_score"], reverse=True)
        return {
            "anomalies": results,
            "total_ports": len(ports),
            "outlier_count": outlier_count,
            "max_score": round(float(norm_scores.max()), 3) if len(norm_scores) > 0 else 0.0,
            "engine": "PyOD-ECOD (C-Accelerated)"
        }

    def _detect_pure_python(self, ports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Pure-Python zero-dependency implementation of ECOD.
        Requires ZERO third-party packages (no NumPy, Pandas, or PyOD).
        Immune to external supply chain attacks.
        """
        N = len(ports)
        if N == 0:
            return {"anomalies": [], "total_ports": 0, "outlier_count": 0, "max_score": 0.0}

        matrix = []
        for p in ports:
            row = []
            for feat in self.feature_names:
                v = p.get(feat, 0)
                try:
                    row.append(float(v if v is not None else 0))
                except (ValueError, TypeError):
                    row.append(0.0)
            matrix.append(row)

        if all(all(val == 0.0 for val in row) for row in matrix):
            results = [{
                "port": p["port"],
                "status": p.get("status", "unknown"),
                "is_outlier": False,
                "anomaly_score": 0.0,
                "severity": "NORMAL",
                "dominant_anomalous_feature": None,
                "explanation": "All hardware counters normal (0 errors).",
                "raw_counters": {k: 0 for k in self.feature_names}
            } for p in ports]
            return {
                "anomalies": results,
                "total_ports": N,
                "outlier_count": 0,
                "max_score": 0.0,
                "engine": "Zero-Dependency Native Python ECOD"
            }

        num_feats = len(self.feature_names)
        raw_scores = [0.0] * N

        for j in range(num_feats):
            vals = [matrix[i][j] for i in range(N)]
            if all(v == 0.0 for v in vals):
                continue
            for i in range(N):
                x = matrix[i][j]
                left_p = sum(1 for v in vals if v <= x) / N
                right_p = sum(1 for v in vals if v >= x) / N
                s_left = -math.log(max(left_p, 1e-6))
                s_right = -math.log(max(right_p, 1e-6))
                raw_scores[i] += max(s_left, s_right)

        min_s = min(raw_scores)
        max_s = max(raw_scores)
        if max_s > min_s:
            norm_scores = [(s - min_s) / (max_s - min_s) for s in raw_scores]
        else:
            norm_scores = [0.0] * N

        results = []
        outlier_count = 0

        feat_labels_map = {
            "crc_errors": "CRC 錯誤 (實體線路/光模組衰退)",
            "in_errors": "輸入錯誤 (Input Errors)",
            "out_errors": "輸出錯誤 (Output Errors)",
            "collisions": "衝突次數 (Collisions/雙工衝突)",
            "in_drops": "輸入佇列丟包 (Queue Drops)",
            "out_drops": "輸出佇列擁塞丟包"
        }

        for i, p in enumerate(ports):
            score = norm_scores[i]
            row = matrix[i]
            is_outlier = score >= 0.7 or any(v > 0 for v in row)

            dominant_feat = None
            explanation = "All port counters in line with normal baseline."

            if any(v > 0 for v in row):
                max_val = max(row)
                max_idx = row.index(max_val)
                dominant_feat = self.feature_names[max_idx]
                label_desc = feat_labels_map.get(dominant_feat, dominant_feat)
                explanation = f"{label_desc} 達 {int(max_val)} 次"
                score = max(score, 0.75)
                is_outlier = True

            if is_outlier:
                outlier_count += 1

            severity = "NORMAL"
            if score >= 0.8:
                severity = "CRITICAL"
            elif score >= 0.5:
                severity = "WARNING"

            results.append({
                "port": p["port"],
                "status": p.get("status", "unknown"),
                "is_outlier": is_outlier,
                "anomaly_score": round(score, 3),
                "severity": severity,
                "dominant_anomalous_feature": dominant_feat,
                "explanation": explanation,
                "raw_counters": {k: int(v) for k, v in zip(self.feature_names, row)}
            })

        results.sort(key=lambda x: x["anomaly_score"], reverse=True)
        return {
            "anomalies": results,
            "total_ports": N,
            "outlier_count": outlier_count,
            "max_score": round(max(norm_scores), 3) if norm_scores else 0.0,
            "engine": "Zero-Dependency Native Python ECOD"
        }
