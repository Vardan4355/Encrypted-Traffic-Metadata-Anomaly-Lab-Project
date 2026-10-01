#!/usr/bin/env python3
"""
Encrypted-Traffic Metadata Anomaly Lab - Terminal CLI Interface.
Command-line tool for network security analysts to generate, inspect, train, and run anomaly detection.
"""

import argparse
import json
import os
import sys
from core.generator import generate_dataset
from core.ja3_database import lookup_ja3, JA3_SIGNATURES
from core.anomaly_detector import MetadataAnomalyEngine
from core.pcap_parser import parse_pcap_scapy

# ANSI Terminal Colors
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_CYAN = "\033[96m"
COLOR_BLUE = "\033[94m"

BANNER = f"""{COLOR_CYAN}{COLOR_BOLD}
  =====================================================================
    ENCRYPTED-TRAFFIC METADATA ANOMALY LAB - TERMINAL CLI (LINUX)
    Detection of C2 Beaconing, Exfiltration & Tunnels in TLS Traffic
  ====================================================================={COLOR_RESET}
"""

def print_banner():
    print(BANNER)

def cmd_generate(args):
    print(f"{COLOR_BLUE}[+] Generating {args.num_flows} synthetic traffic flow records (Anomaly ratio: {args.ratio})...{COLOR_RESET}")
    dataset = generate_dataset(num_flows=args.num_flows, anomaly_ratio=args.ratio)
    
    os.makedirs(os.path.dirname(args.out) if os.path.dirname(args.out) else ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(dataset, f, indent=2)
        
    num_anomalies = sum(1 for flow in dataset if flow.get("is_anomaly"))
    print(f"{COLOR_GREEN}[✔] Successfully saved dataset to '{args.out}'! ({num_anomalies} anomalies / {len(dataset)} total flows){COLOR_RESET}")

def cmd_inspect(args):
    if not os.path.exists(args.file):
        print(f"{COLOR_RED}[!] Error: File '{args.file}' not found.{COLOR_RESET}")
        return

    with open(args.file, "r") as f:
        flows = json.load(f)

    print(f"{COLOR_CYAN}[+] Inspecting {len(flows)} flow records from '{args.file}':{COLOR_RESET}\n")
    print(f"{'FLOW ID':<10} {'PROTOCOL':<10} {'DESTINATION IP:PORT':<22} {'SNI':<28} {'BYTES S/R':<15} {'IAT CV':<8} {'JA3 MATCH':<25}")
    print("-" * 120)

    for flow in flows[:args.limit]:
        fid = flow.get("flow_id", "N/A")[:8]
        proto = flow.get("protocol", "TLS")
        dst = f"{flow.get('dst_ip', '0.0.0.0')}:{flow.get('dst_port', 443)}"
        sni = flow.get("sni", "N/A")[:26]
        bytes_info = f"{flow.get('bytes_sent', 0)}/{flow.get('bytes_recv', 0)}"
        iat_cv = f"{flow.get('iat_cv', 0.0):.3f}"
        ja3_info = lookup_ja3(flow.get("ja3_hash", ""))
        ja3_name = ja3_info.get("name", "Unknown")[:24]

        color = COLOR_GREEN
        if flow.get("is_anomaly"):
            color = COLOR_RED

        print(f"{color}{fid:<10} {proto:<10} {dst:<22} {sni:<28} {bytes_info:<15} {iat_cv:<8} {ja3_name:<25}{COLOR_RESET}")

    if len(flows) > args.limit:
        print(f"\n{COLOR_YELLOW}... and {len(flows) - args.limit} more flows.{COLOR_RESET}")

def cmd_detect(args):
    if not os.path.exists(args.file):
        print(f"{COLOR_RED}[!] Error: File '{args.file}' not found.{COLOR_RESET}")
        return

    with open(args.file, "r") as f:
        flows = json.load(f)

    print(f"{COLOR_BLUE}[+] Initializing Anomaly Detection Engine ({args.model})...{COLOR_RESET}")
    engine = MetadataAnomalyEngine(model_type=args.model, contamination=args.contamination)
    engine.train(flows)

    print(f"{COLOR_CYAN}[+] Executing Anomaly Detection Inference across {len(flows)} flows...{COLOR_RESET}\n")
    results = engine.predict_dataset(flows)

    anomalies = [r for r in results if r["is_anomaly"]]

    print(f"{COLOR_BOLD}{'FLOW ID':<10} {'RISK':<10} {'SCORE':<8} {'ML SCORE':<10} {'FLAGS':<30} {'DETAILED REASON'}{COLOR_RESET}")
    print("=" * 110)

    for res in results[:args.limit]:
        score = res["anomaly_score"]
        risk = res["risk_level"]
        flags_str = ",".join(res["flags"])[:28]
        reason = res["explanations"][0] if res["explanations"] else "Normal baseline"

        if risk == "CRITICAL":
            c = COLOR_RED + COLOR_BOLD
        elif risk == "HIGH":
            c = COLOR_RED
        elif risk == "MEDIUM":
            c = COLOR_YELLOW
        else:
            c = COLOR_GREEN

        print(f"{c}{res['flow_id']:<10} {risk:<10} {score:<8.4f} {res['ml_score']:<10.4f} {flags_str:<30} {reason[:45]}{COLOR_RESET}")

    print("\n" + "=" * 110)
    print(f"{COLOR_BOLD}SUMMARY:{COLOR_RESET} Analyzed {len(flows)} flows | {COLOR_RED}{len(anomalies)} Anomalies Flagged{COLOR_RESET} | Anomaly Rate: {len(anomalies)/len(flows)*100:.1f}%")

def cmd_ja3_lookup(args):
    ja3_info = lookup_ja3(args.hash)
    print(f"\n{COLOR_CYAN}[+] JA3 Fingerprint Analysis: {args.hash}{COLOR_RESET}")
    print(f"    Name:        {COLOR_BOLD}{ja3_info.get('name')}{COLOR_RESET}")
    print(f"    Category:    {ja3_info.get('category')}")
    print(f"    Threat Risk: {ja3_info.get('risk')}")
    print(f"    Description: {ja3_info.get('description')}\n")

def cmd_pcap(args):
    print(f"{COLOR_BLUE}[+] Parsing PCAP file '{args.file}'...{COLOR_RESET}")
    flows = parse_pcap_scapy(args.file)
    if isinstance(flows, dict) and "error" in flows:
        print(f"{COLOR_RED}[!] Error: {flows['error']}{COLOR_RESET}")
        return

    print(f"{COLOR_GREEN}[✔] Extracted {len(flows)} encrypted flow records from PCAP.{COLOR_RESET}")
    if args.out:
        with open(args.out, "w") as f:
            json.dump(flows, f, indent=2)
        print(f"{COLOR_CYAN}[+] Saved extracted PCAP flows to '{args.out}'{COLOR_RESET}")

def main():
    parser = argparse.ArgumentParser(description="Encrypted-Traffic Metadata Anomaly Lab CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Generate subcommand
    gen_parser = subparsers.add_parser("generate", help="Generate synthetic traffic metadata dataset")
    gen_parser.add_argument("--num-flows", type=int, default=100, help="Number of flows to generate")
    gen_parser.add_argument("--ratio", type=float, default=0.2, help="Ratio of anomalous flows (0.0 to 1.0)")
    gen_parser.add_argument("--out", type=str, default="data/flows.json", help="Output JSON path")

    # Inspect subcommand
    insp_parser = subparsers.add_parser("inspect", help="Inspect traffic metadata flows in terminal")
    insp_parser.add_argument("--file", type=str, default="data/flows.json", help="Flow JSON dataset path")
    insp_parser.add_argument("--limit", type=int, default=25, help="Limit number of displayed rows")

    # Detect subcommand
    det_parser = subparsers.add_parser("detect", help="Run ML and rule-based anomaly detection")
    det_parser.add_argument("--file", type=str, default="data/flows.json", help="Flow dataset path")
    det_parser.add_argument("--model", type=str, default="isolation_forest", choices=["isolation_forest", "one_class_svm"], help="ML model type")
    det_parser.add_argument("--contamination", type=float, default=0.15, help="Model contamination parameter")
    det_parser.add_argument("--limit", type=int, default=30, help="Limit output rows")

    # JA3 lookup subcommand
    ja3_parser = subparsers.add_parser("ja3-lookup", help="Look up JA3 hash in threat intel database")
    ja3_parser.add_argument("--hash", type=str, required=True, help="32-character MD5 JA3 hash")

    # PCAP parser subcommand
    pcap_parser = subparsers.add_parser("pcap", help="Parse PCAP packet capture file into metadata flows")
    pcap_parser.add_argument("--file", type=str, required=True, help="Path to input PCAP file")
    pcap_parser.add_argument("--out", type=str, default="data/pcap_flows.json", help="Output JSON path")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(1)

    if args.command == "generate":
        cmd_generate(args)
    elif args.command == "inspect":
        cmd_inspect(args)
    elif args.command == "detect":
        cmd_detect(args)
    elif args.command == "ja3-lookup":
        cmd_ja3_lookup(args)
    elif args.command == "pcap":
        cmd_pcap(args)

if __name__ == "__main__":
    main()
