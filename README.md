# 🔒 Encrypted-Traffic Metadata Anomaly Lab (Linux)

> **Machine Learning & Statistical Anomaly Detection Platform for Encrypted (TLS 1.2/1.3, QUIC, DoH, SSH) Network Traffic Metadata**

---

## 📌 Overview

When network traffic is encrypted, Deep Packet Inspection (DPI) cannot read payload contents. However, **network metadata**—such as packet lengths, inter-arrival times (IAT), TLS handshakes, JA3/JA4 fingerprints, flow direction sequences, and payload entropy—contains key signatures of malicious behavior.

This lab provides a complete cybersecurity toolkit and web dashboard for detecting:
- 🤖 **Cobalt Strike & Malware C2 Beaconing** (low inter-arrival time variance, regular heartbeat pulses).
- 📤 **DNS-over-HTTPS & TLS Data Exfiltration** (asymmetric high outbound byte ratios).
- 🕵️ **Covert Tunnels & Encrypted Proxies** (uniform high-entropy packet dynamics).
- 💥 **High-Frequency Traffic Surges / DDoS Floods**.
- 🛡️ **JA3 / JA4 Threat Intelligence Fingerprinting** (matching Cobalt Strike, Empire, Metasploit, AsyncRAT, Tor).

---

## 🚀 Quick Start (Linux Terminal)

### Option 1: Interactive Menu Runner
Run the unified launcher script:
```bash
./run_lab.sh
```

### Option 2: Start the Web Dashboard
```bash
source venv/bin/activate
python3 server/app.py
```
Then open your browser at **`http://localhost:5000`**.

---

## 💻 Terminal CLI Usage

You can execute all anomaly detection, PCAP parsing, and threat lookup commands directly in your Linux terminal:

### 1. Generate Synthetic Traffic Dataset
```bash
python3 lab_cli.py generate --num-flows 100 --ratio 0.25 --out data/flows.json
```

### 2. Run Anomaly Detection Inference
```bash
python3 lab_cli.py detect --file data/flows.json --model isolation_forest
```

### 3. Inspect Flow Metadata Table in Terminal
```bash
python3 lab_cli.py inspect --file data/flows.json --limit 20
```

### 4. JA3 Signature Lookup
```bash
python3 lab_cli.py ja3-lookup --hash 3b2a1060b2984534f3780f2d93e1cf70
```

### 5. Parse PCAP Capture File
```bash
python3 lab_cli.py pcap --file sample.pcap --out data/pcap_flows.json
```

---

## 🛠 Project Architecture

```
Encrypted-Traffic Metadata Anomaly Lab/
├── lab_cli.py              # Terminal CLI application
├── run_lab.sh              # Interactive Linux launcher script
├── requirements.txt        # Python dependencies (scikit-learn, numpy, pandas, flask, scapy)
├── core/
│   ├── generator.py        # Synthetic encrypted flow generator (Benign & Malicious)
│   ├── feature_extractor.py# Feature extraction engine (IAT, SPL, Entropy, JA3)
│   ├── anomaly_detector.py # Isolation Forest, One-Class SVM & Rule-Based Ensembling
│   ├── ja3_database.py     # Threat intelligence signature database
│   └── pcap_parser.py      # Scapy PCAP packet metadata parser
├── server/
│   └── app.py              # Flask REST API server
├── static/
│   ├── index.html          # Web UI Dashboard template
│   ├── css/style.css       # Cybersecurity dark mode design system
│   └── js/app.js           # Chart.js visualization & interactive stream logic
└── data/                   # JSON dataset storage
```

---

## 📊 Extracted Features & Detection Methodology

1. **Inter-Arrival Time (IAT) Statistics**: Mean $\mu$, Std Dev $\sigma$, and Coefficient of Variation ($CV = \sigma / \mu$). Beaconing malware exhibits $CV < 0.12$.
2. **Sequence of Packet Lengths (SPL)**: Directional packet sequence ($+512, -1420, -1420, +64, \dots$).
3. **Shannon Payload Entropy**: Packet size distribution entropy ($H(X) = -\sum p_i \log_2 p_i$).
4. **JA3 Fingerprinting**: MD5 hash of TLS Client Hello parameters (`TLSVersion,Ciphers,Extensions,EllipticCurves`).
5. **Isolation Forest Ensemble**: Unsupervised tree model isolating abnormal traffic in high-dimensional feature space.

---

## 📜 License
MIT License - Developed for Network Security & Anomaly Detection Research.
