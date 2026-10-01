"""
Anomaly Detection Engines for Encrypted Traffic Metadata.
Supports Isolation Forest, One-Class SVM, Rule-Based Statistical Heuristics, and Hybrid Scoring.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from core.feature_extractor import extract_features_single, extract_features_dataset, FEATURE_NAMES
from core.ja3_database import lookup_ja3

class MetadataAnomalyEngine:
    def __init__(self, model_type="isolation_forest", contamination=0.15):
        self.model_type = model_type
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.is_trained = False
        
        if model_type == "isolation_forest":
            self.model = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
        elif model_type == "one_class_svm":
            self.model = OneClassSVM(nu=contamination, kernel="rbf", gamma="scale")
        else:
            self.model = IsolationForest(contamination=contamination, random_state=42)

    def train(self, train_flows):
        """Train the unsupervised ML anomaly model on baseline flow features."""
        if not train_flows:
            return False
            
        X = extract_features_dataset(train_flows)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True
        return True

    def predict_single(self, flow):
        """
        Evaluate a single flow record and return anomaly score (0.0 to 1.0),
        threat level, detection flags, and detailed explanation.
        """
        features = extract_features_single(flow)
        
        # 1. Machine Learning Anomaly Score computation
        if self.is_trained:
            X_scaled = self.scaler.transform([features])
            if self.model_type == "isolation_forest":
                # decision_function returns negative for anomalies, positive for normal
                raw_score = self.model.decision_function(X_scaled)[0]
                # Map decision function to 0..1 scale (lower decision -> higher anomaly score)
                ml_score = max(0.0, min(1.0, 0.5 - raw_score * 2.5))
            else:
                raw_score = self.model.score_samples(X_scaled)[0] if hasattr(self.model, "score_samples") else 0.0
                ml_score = max(0.0, min(1.0, 0.5 - raw_score * 0.1))
        else:
            ml_score = 0.5

        # 2. Rule-Based Heuristic Flags & Analysis
        heuristic_score, flags, explanations = self._analyze_heuristics(flow)

        # 3. Combine ML + Heuristics into Hybrid Anomaly Score
        combined_score = round(max(ml_score * 0.5 + heuristic_score * 0.5, heuristic_score if heuristic_score > 0.8 else ml_score), 4)

        if combined_score >= 0.8:
            risk = "CRITICAL"
        elif combined_score >= 0.6:
            risk = "HIGH"
        elif combined_score >= 0.4:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        return {
            "flow_id": str(flow.get("flow_id", "unknown")),
            "anomaly_score": float(combined_score),
            "ml_score": float(ml_score),
            "heuristic_score": float(heuristic_score),
            "risk_level": str(risk),
            "is_anomaly": bool(combined_score >= 0.5),
            "flags": [str(f) for f in flags],
            "explanations": [str(e) for e in explanations],
            "ja3_info": lookup_ja3(flow.get("ja3_hash", ""))
        }

    def _analyze_heuristics(self, flow):
        """Apply domain heuristics to identify specific anomaly signatures."""
        score = 0.0
        flags = []
        explanations = []

        ja3 = flow.get("ja3_hash", "")
        ja3_info = lookup_ja3(ja3)

        # A. Signature Check (JA3 Database Match)
        if ja3_info.get("risk") == "CRITICAL":
            score = max(score, 0.95)
            flags.append("KNOWN_MALWARE_JA3")
            explanations.append(f"Matched known malicious fingerprint: {ja3_info.get('name')}")
        elif ja3_info.get("risk") == "HIGH":
            score = max(score, 0.75)
            flags.append("SUSPICIOUS_JA3")
            explanations.append(f"Matched suspicious tool fingerprint: {ja3_info.get('name')}")

        # B. Malware Beaconing Check (Low IAT Coefficient of Variation)
        iat_cv = flow.get("iat_cv", 1.0)
        duration = flow.get("duration", 0)
        total_pkts = flow.get("total_packets", 0)

        if iat_cv < 0.12 and total_pkts >= 10 and duration > 5.0:
            score = max(score, 0.85)
            flags.append("BEACONING_PATTERN")
            explanations.append(f"Ultra-regular packet inter-arrival interval (CV = {iat_cv:.4f}), typical of C2 heartbeat pulse.")

        # C. Data Exfiltration Check (High Outbound Byte Ratio)
        bytes_sent = flow.get("bytes_sent", 0)
        bytes_recv = flow.get("bytes_recv", 0)
        ratio = flow.get("bytes_ratio", 0.0)

        if ratio > 6.0 and bytes_sent > 15000:
            score = max(score, 0.80)
            flags.append("ASYMMETRIC_EXFILTRATION")
            explanations.append(f"Abnormally high outbound traffic ratio ({ratio:.1f}:1, {bytes_sent} bytes sent vs {bytes_recv} received).")

        # D. High Entropy Covert Tunnel / Proxy Check
        pkt_entropy = flow.get("pkt_entropy", 0.0)
        if pkt_entropy > 4.2 and total_pkts > 50:
            score = max(score, 0.65)
            flags.append("HIGH_ENTROPY_PAYLOAD_DYNAMICS")
            explanations.append(f"Uniform high-entropy packet length distribution ({pkt_entropy:.2f}), indicative of encrypted tunnel / proxy.")

        # E. Short High-Frequency Burst (DDoS / Scan)
        if duration < 0.05 and total_pkts >= 3 and bytes_sent > 1000:
            score = max(score, 0.70)
            flags.append("TRAFFIC_SURGE_BURST")
            explanations.append(f"Rapid high-frequency burst in microsecond interval ({duration*1000:.1f}ms).")

        if not flags:
            flags.append("NORMAL_TRAFFIC")
            explanations.append("Traffic metadata exhibits standard benign baseline parameters.")

        return score, flags, explanations

    def predict_dataset(self, flows):
        """Run inference across an entire dataset of flows."""
        results = []
        for f in flows:
            results.append(self.predict_single(f))
        return results
