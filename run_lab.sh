#!/usr/bin/env bash
# Encrypted-Traffic Metadata Anomaly Lab - Linux Launcher & Runner Script

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Color Codes
CYAN='\033[96m'
GREEN='\033[92m'
YELLOW='\033[93m'
RED='\033[91m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "========================================================================="
echo "  ENCRYPTED-TRAFFIC METADATA ANOMALY LAB - LINUX TERMINAL LAUNCHER"
echo "========================================================================="
echo -e "${RESET}"

# Check virtual environment
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}[!] Creating Python virtual environment...${RESET}"
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

# Print menu options
echo -e "${BOLD}Select execution mode:${RESET}"
echo -e "  ${GREEN}1)${RESET} Start Web UI & REST Server Dashboard (http://localhost:5000)"
echo -e "  ${GREEN}2)${RESET} Run Terminal CLI Anomaly Detector (CLI Mode)"
echo -e "  ${GREEN}3)${RESET} Generate New Synthetic Dataset (data/flows.json)"
echo -e "  ${GREEN}4)${RESET} Perform JA3 Hash Signature Lookup"
echo -e "  ${GREEN}5)${RESET} Parse Sample PCAP Packet Capture File"
echo -e "  ${GREEN}6)${RESET} Run Automated Suite Test"
echo ""

if [ "$1" != "" ]; then
    CHOICE="$1"
else
    read -p "Enter choice [1-6] (default: 1): " CHOICE
    CHOICE=${CHOICE:-1}
fi

case $CHOICE in
    1)
        echo -e "${GREEN}[+] Starting Web Dashboard REST Server on http://0.0.0.0:5000${RESET}"
        python3 server/app.py
        ;;
    2)
        echo -e "${CYAN}[+] Running Terminal CLI Inspector & Detector...${RESET}"
        python3 lab_cli.py detect --file data/flows.json
        ;;
    3)
        echo -e "${CYAN}[+] Generating 100 Encrypted Traffic Flows...${RESET}"
        python3 lab_cli.py generate --num-flows 100 --out data/flows.json
        ;;
    4)
        read -p "Enter 32-character JA3 Hash: " HASH
        HASH=${HASH:-"3b2a1060b2984534f3780f2d93e1cf70"}
        python3 lab_cli.py ja3-lookup --hash "$HASH"
        ;;
    5)
        read -p "Enter PCAP file path: " PCAP_PATH
        python3 lab_cli.py pcap --file "${PCAP_PATH:-sample.pcap}"
        ;;
    6)
        echo -e "${GREEN}[+] Running complete test suite...${RESET}"
        python3 lab_cli.py generate --num-flows 60 --out data/flows.json
        python3 lab_cli.py detect --file data/flows.json
        echo -e "${GREEN}[✔] All tests passed!${RESET}"
        ;;
    *)
        echo -e "${RED}[!] Invalid option selected.${RESET}"
        exit 1
        ;;
esac
