"""
Synthetic & Real-World Vulnerability Traffic Metadata Generator.
Generates rich network flow datasets matching actual CVE attack vectors, C2 frameworks,
and benign baseline enterprise traffic.
"""

import math
import random
import time
import uuid
from core.ja3_database import JA3_SIGNATURES

# Real-World Threat & Benign Domains
BENIGN_SNIS = [
    "www.google.com", "github.com", "api.github.com", "cloudflare.com",
    "aws.amazon.com", "cdn.jsdelivr.net", "stackoverflow.com",
    "login.microsoftonline.com", "video.net-stream.io", "i.ytimg.com"
]

REAL_WORLD_CVE_PROFILES = {
    "cve_log4shell_c2": {
        "cve": "CVE-2021-44228 (Log4Shell RCE)",
        "sni": "c2-cobaltstrike-listener.evil.site",
        "ja3": "3b2a1060b2984534f3780f2d93e1cf70", # Cobalt Strike Beacon
        "traffic_type": "c2_beaconing",
        "description": "Post-exploitation Cobalt Strike C2 established after remote LDAP/JNDI injection."
    },
    "cve_solarwinds_exfil": {
        "cve": "SUNBURST / SolarWinds Supply Chain",
        "sni": "doh.stealth-data-exfil.net",
        "ja3": "9a2f7c00e12d45a9871bc3298fa11122", # DoH Exfil
        "traffic_type": "data_exfiltration",
        "description": "Encrypted DNS-over-HTTPS staging and credential exfiltration tunnel."
    },
    "cve_proxyshell_empire": {
        "cve": "CVE-2021-34473 (ProxyShell RCE)",
        "sni": "exchange-update-check.biz",
        "ja3": "fa84f73809623e10037a34eb60bf3d2b", # Empire Agent
        "traffic_type": "c2_beaconing",
        "description": "PowerShell Empire reverse HTTPS agent after Microsoft Exchange Web Service exploit."
    },
    "cve_asyncrat_dropper": {
        "cve": "CVE-2023-23397 (Outlook NTLM / RCE)",
        "sni": "async-rat-node-892.xyz",
        "ja3": "6734f37d976077357e4e107d92b85292", # AsyncRAT
        "traffic_type": "covert_tunnel",
        "description": "Encrypted RAT session establishing persistence prior to enterprise ransomware execution."
    }
}

BENIGN_JA3_LIST = [
    "cdb5840456437bd7738ee96fc6a4182a",  # Chrome
    "b32309a26951912be7dba376398207b3",  # Firefox
    "73b88b29b4e3498877ee3d538e137839",  # Safari
    "3505c21f92e03aa37227bf0225d3512e"   # Python requests
]

def calculate_entropy(packet_sizes):
    """Calculate Shannon entropy of packet size distribution."""
    if not packet_sizes:
        return 0.0
    abs_sizes = [abs(s) for s in packet_sizes]
    total_count = len(abs_sizes)
    frequency = {}
    for size in abs_sizes:
        frequency[size] = frequency.get(size, 0) + 1
    
    entropy = 0.0
    for count in frequency.values():
        p = count / total_count
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def generate_flow(traffic_type="benign_web", flow_id=None):
    """
    Generate a single flow metadata record matching the requested benign or CVE threat profile.
    """
    if flow_id is None:
        flow_id = str(uuid.uuid4())[:8]

    timestamp = time.time() - random.uniform(0, 3600)
    src_ip = f"192.168.1.{random.randint(10, 250)}"
    src_port = random.randint(49152, 65535)

    cve_info = "None"

    if traffic_type in REAL_WORLD_CVE_PROFILES:
        prof = REAL_WORLD_CVE_PROFILES[traffic_type]
        dst_ip = f"{random.randint(185, 198)}.{random.randint(10, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        dst_port = 443
        sni = prof["sni"]
        ja3 = prof["ja3"]
        cve_info = prof["cve"]
        is_anomaly = True
        traffic_pattern = prof["traffic_type"]
    elif traffic_type.startswith("benign"):
        dst_ip = f"{random.randint(1, 200)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}"
        dst_port = 443
        sni = random.choice(BENIGN_SNIS)
        ja3 = random.choice(BENIGN_JA3_LIST)
        is_anomaly = False
        traffic_pattern = traffic_type
    else:
        # Standard anomaly fallbacks
        dst_ip = f"{random.randint(185, 198)}.{random.randint(10, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        dst_port = 443
        sni = "c2-node-malicious.online"
        ja3 = "3b2a1060b2984534f3780f2d93e1cf70"
        is_anomaly = True
        traffic_pattern = traffic_type

    packets = []
    iats = []

    if traffic_pattern in ["benign_web", "benign_api"]:
        num_packets = random.randint(15, 60)
        duration = random.uniform(1.2, 8.5)
        packets = [512, -1420, -1420, 64, 380]
        for _ in range(num_packets - 5):
            direction = 1 if random.random() < 0.35 else -1
            packets.append(direction * random.randint(64, 1500))
        for _ in range(num_packets - 1):
            iats.append(round(random.expovariate(1.0 / 0.12), 4))

    elif traffic_pattern == "benign_video":
        num_packets = random.randint(120, 350)
        duration = random.uniform(15.0, 45.0)
        packets = [512, -1420, 64]
        for _ in range(num_packets - 3):
            if random.random() < 0.85:
                packets.append(-random.randint(1200, 1500))
            else:
                packets.append(random.randint(64, 128))
        for _ in range(num_packets - 1):
            iats.append(round(random.normalvariate(0.1, 0.02), 4))

    elif traffic_pattern == "c2_beaconing":
        # Ultra-regular heartbeat pulse (Cobalt Strike / Empire Beaconing)
        num_packets = random.randint(25, 90)
        base_interval = random.choice([5.0, 10.0, 15.0])
        duration = num_packets * base_interval
        packets = [512, -1420, 64]
        for _ in range((num_packets - 3) // 2):
            packets.append(210 + random.randint(-2, 2))
            packets.append(-(128 + random.randint(-2, 2)))
        for _ in range(len(packets) - 1):
            iats.append(round(base_interval + random.uniform(-0.02, 0.02), 4))

    elif traffic_pattern == "data_exfiltration":
        # Asymmetric heavy outbound flow (DoH / SolarWinds Exfil)
        num_packets = random.randint(90, 280)
        duration = random.uniform(3.0, 12.0)
        packets = [512, -1420, 64]
        for _ in range(num_packets - 3):
            if random.random() < 0.90:
                packets.append(random.randint(1200, 1480))
            else:
                packets.append(-64)
        for _ in range(num_packets - 1):
            iats.append(round(random.expovariate(25.0), 4))

    else:
        # Covert Tunnel / General Anomaly
        num_packets = random.randint(100, 300)
        duration = random.uniform(10.0, 60.0)
        packets = [512, -1420, 64]
        for _ in range(num_packets - 3):
            direction = 1 if random.random() < 0.5 else -1
            packets.append(direction * random.randint(500, 1450))
        for _ in range(num_packets - 1):
            iats.append(round(random.uniform(0.005, 0.2), 4))

    bytes_sent = sum(p for p in packets if p > 0)
    bytes_recv = abs(sum(p for p in packets if p < 0))
    total_bytes = bytes_sent + bytes_recv
    total_pkts = len(packets)
    ratio_sent_recv = round(bytes_sent / (bytes_recv + 1), 4)

    clean_iats = [max(0.00001, t) for t in iats]
    if not clean_iats:
        clean_iats = [0.01]

    iat_mean = sum(clean_iats) / len(clean_iats)
    iat_variance = sum((x - iat_mean) ** 2 for x in clean_iats) / len(clean_iats)
    iat_std = math.sqrt(iat_variance)
    iat_cv = iat_std / (iat_mean + 1e-6)

    pkt_sizes_abs = [abs(p) for p in packets]
    pkt_size_mean = sum(pkt_sizes_abs) / len(pkt_sizes_abs)
    pkt_size_variance = sum((x - pkt_size_mean) ** 2 for x in pkt_sizes_abs) / len(pkt_sizes_abs)
    pkt_size_std = math.sqrt(pkt_size_variance)
    pkt_entropy = calculate_entropy(packets)

    return {
        "flow_id": flow_id,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": "TLS/HTTPS",
        "sni": sni,
        "ja3_hash": ja3,
        "cve_correlation": cve_info,
        "traffic_type": traffic_type,
        "is_anomaly": is_anomaly,
        "duration": round(duration, 4),
        "total_packets": total_pkts,
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "total_bytes": total_bytes,
        "bytes_ratio": ratio_sent_recv,
        "iat_mean": round(iat_mean, 6),
        "iat_std": round(iat_std, 6),
        "iat_cv": round(iat_cv, 4),
        "pkt_size_mean": round(pkt_size_mean, 2),
        "pkt_size_std": round(pkt_size_std, 2),
        "pkt_entropy": pkt_entropy,
        "spl_sequence": packets[:15]
    }

def generate_dataset(num_flows=100, anomaly_ratio=0.25):
    """
    Generate a dataset containing benign enterprise traffic and real-world CVE threat scenarios.
    """
    flows = []
    num_anomalies = int(num_flows * anomaly_ratio)
    num_benign = num_flows - num_anomalies

    benign_types = ["benign_web", "benign_video", "benign_api"]
    cve_keys = list(REAL_WORLD_CVE_PROFILES.keys())

    for _ in range(num_benign):
        b_type = random.choice(benign_types)
        flows.append(generate_flow(traffic_type=b_type))

    for _ in range(num_anomalies):
        cve_type = random.choice(cve_keys)
        flows.append(generate_flow(traffic_type=cve_type))

    random.shuffle(flows)
    return flows

if __name__ == "__main__":
    dataset = generate_dataset(5)
    print(f"Sample Real-World CVE Flow:")
    print(dataset[0])
