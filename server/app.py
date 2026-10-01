"""
REST API Backend Server for Encrypted-Traffic Metadata Anomaly Lab.
Provides endpoints for dataset generation, real-time metadata analysis,
ML anomaly detection model training, and visual dashboard statistics.
"""

import json
import os
import sys
from flask import Flask, jsonify, request, send_from_directory

# Ensure parent directory is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.generator import generate_dataset, generate_flow
from core.ja3_database import lookup_ja3, JA3_SIGNATURES
from core.anomaly_detector import MetadataAnomalyEngine
from core.pcap_parser import parse_pcap_scapy

app = Flask(__name__, static_folder="../static", static_url_path="")

# In-memory storage for current lab session
CURRENT_FLOWS = generate_dataset(num_flows=60, anomaly_ratio=0.25)
ENGINE = MetadataAnomalyEngine(model_type="isolation_forest", contamination=0.15)
ENGINE.train(CURRENT_FLOWS)

@app.route("/")
def index():
    return send_from_directory("../static", "index.html")

@app.route("/api/flows", methods=["GET"])
def get_flows():
    limit = request.args.get("limit", default=100, type=int)
    anomaly_filter = request.args.get("anomaly_only", default="false").lower() == "true"
    
    flows = CURRENT_FLOWS
    if anomaly_filter:
        flows = [f for f in flows if f.get("is_anomaly")]

    results = ENGINE.predict_dataset(flows[:limit])
    return jsonify({
        "status": "success",
        "count": len(results),
        "total_in_session": len(CURRENT_FLOWS),
        "flows": results
    })

@app.route("/api/generate", methods=["POST"])
def api_generate():
    global CURRENT_FLOWS
    data = request.get_json() or {}
    num_flows = data.get("num_flows", 80)
    anomaly_ratio = data.get("anomaly_ratio", 0.25)

    num_flows = max(10, min(500, num_flows))
    anomaly_ratio = max(0.0, min(0.9, anomaly_ratio))

    CURRENT_FLOWS = generate_dataset(num_flows=num_flows, anomaly_ratio=anomaly_ratio)
    ENGINE.train(CURRENT_FLOWS)

    results = ENGINE.predict_dataset(CURRENT_FLOWS)
    return jsonify({
        "status": "success",
        "message": f"Generated {num_flows} new encrypted traffic flows.",
        "count": len(results),
        "flows": results
    })

@app.route("/api/detect", methods=["POST"])
def api_detect():
    data = request.get_json() or {}
    model_type = data.get("model_type", "isolation_forest")
    contamination = data.get("contamination", 0.15)

    engine = MetadataAnomalyEngine(model_type=model_type, contamination=contamination)
    engine.train(CURRENT_FLOWS)

    results = engine.predict_dataset(CURRENT_FLOWS)
    return jsonify({
        "status": "success",
        "model_type": model_type,
        "results": results
    })

@app.route("/api/stats", methods=["GET"])
def api_stats():
    results = ENGINE.predict_dataset(CURRENT_FLOWS)
    
    total_flows = len(results)
    anomalies = [r for r in results if r["is_anomaly"]]
    critical_threats = [r for r in results if r["risk_level"] == "CRITICAL"]
    high_threats = [r for r in results if r["risk_level"] == "HIGH"]

    total_bytes = sum(f.get("total_bytes", 0) for f in CURRENT_FLOWS)

    # Attack Breakdown
    attack_counts = {}
    for r in anomalies:
        for flag in r.get("flags", []):
            attack_counts[flag] = attack_counts.get(flag, 0) + 1

    # JA3 Distribution
    ja3_counts = {}
    for f in CURRENT_FLOWS:
        ja3 = f.get("ja3_hash", "unknown")
        info = lookup_ja3(ja3)
        name = info.get("name", "Unknown")
        ja3_counts[name] = ja3_counts.get(name, 0) + 1

    return jsonify({
        "total_flows": total_flows,
        "anomaly_count": len(anomalies),
        "anomaly_rate": round(len(anomalies) / (total_flows or 1) * 100, 1),
        "critical_threats": len(critical_threats),
        "high_threats": len(high_threats),
        "total_bytes_mb": round(total_bytes / (1024 * 1024), 2),
        "attack_breakdown": attack_counts,
        "ja3_distribution": ja3_counts
    })

@app.route("/api/ja3/lookup/<ja3_hash>", methods=["GET"])
def api_ja3_lookup(ja3_hash):
    info = lookup_ja3(ja3_hash)
    return jsonify({
        "ja3_hash": ja3_hash,
        "info": info
    })

@app.route("/api/simulate_stream", methods=["POST"])
def api_simulate_stream():
    """Generates 1 live incoming traffic flow for streaming simulation."""
    data = request.get_json() or {}
    t_type = data.get("traffic_type", "c2_beaconing")
    flow = generate_flow(traffic_type=t_type)
    result = ENGINE.predict_single(flow)
    CURRENT_FLOWS.insert(0, flow)
    return jsonify({
        "status": "success",
        "flow": result
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting Encrypted-Traffic Metadata Anomaly Lab Web Server on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
