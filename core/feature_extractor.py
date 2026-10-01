"""
Feature Extraction Engine for Encrypted Traffic Metadata.
Converts raw flow JSON records into normalized feature arrays for ML models.
"""

import math
from core.ja3_database import lookup_ja3

FEATURE_NAMES = [
    "duration",
    "total_packets",
    "bytes_sent",
    "bytes_recv",
    "bytes_ratio",
    "bytes_per_sec",
    "pkts_per_sec",
    "iat_mean",
    "iat_std",
    "iat_cv",
    "pkt_size_mean",
    "pkt_size_std",
    "pkt_entropy",
    "ja3_threat_score"
]

def extract_features_single(flow):
    """
    Extract a 1D numerical feature vector from a flow dictionary.
    """
    duration = float(flow.get("duration", 0.001))
    if duration <= 0:
        duration = 0.0001
        
    total_pkts = float(flow.get("total_packets", 1))
    bytes_sent = float(flow.get("bytes_sent", 0))
    bytes_recv = float(flow.get("bytes_recv", 0))
    bytes_ratio = float(flow.get("bytes_ratio", 0.0))

    bytes_per_sec = (bytes_sent + bytes_recv) / duration
    pkts_per_sec = total_pkts / duration

    iat_mean = float(flow.get("iat_mean", 0.01))
    iat_std = float(flow.get("iat_std", 0.01))
    iat_cv = float(flow.get("iat_cv", 0.0))

    pkt_size_mean = float(flow.get("pkt_size_mean", 500.0))
    pkt_size_std = float(flow.get("pkt_size_std", 100.0))
    pkt_entropy = float(flow.get("pkt_entropy", 3.0))

    # Lookup JA3 signature risk
    ja3_info = lookup_ja3(flow.get("ja3_hash", ""))
    risk = ja3_info.get("risk", "LOW")
    if risk == "CRITICAL":
        ja3_score = 1.0
    elif risk == "HIGH":
        ja3_score = 0.8
    elif risk == "MEDIUM":
        ja3_score = 0.5
    elif risk == "INFO":
        ja3_score = 0.2
    else:
        ja3_score = 0.0

    vector = [
        duration,
        total_pkts,
        bytes_sent,
        bytes_recv,
        bytes_ratio,
        bytes_per_sec,
        pkts_per_sec,
        iat_mean,
        iat_std,
        iat_cv,
        pkt_size_mean,
        pkt_size_std,
        pkt_entropy,
        ja3_score
    ]

    return vector

def extract_features_dataset(flows):
    """
    Extract 2D feature matrix [N, D] from a list of flow dictionaries.
    """
    matrix = []
    for f in flows:
        matrix.append(extract_features_single(f))
    return matrix
