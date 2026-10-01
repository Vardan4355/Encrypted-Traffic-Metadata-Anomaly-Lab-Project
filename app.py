#!/usr/bin/env python3
"""
Root entry point for Encrypted-Traffic Metadata Anomaly Lab Web Server.
"""

import sys
import os

# Ensure server and core are in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server.app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    try:
        print(f"[*] Starting Encrypted-Traffic Metadata Anomaly Lab on http://0.0.0.0:{port}")
        app.run(host="0.0.0.0", port=port, debug=True)
    except OSError:
        port = 5050
        print(f"[*] Port 5000 busy. Starting Lab on http://0.0.0.0:{port}")
        app.run(host="0.0.0.0", port=port, debug=True)

