#!/usr/bin/env bash

GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
RESET="\033[0m"

set -euo pipefail

cleanup() {
    echo "${RED}=====> Signal received. Cleaning up...${RESET}"
    rm -rf ./captures/$profile/json/*
    rm -rf ./analyze/csv_files/$profile/*.csv
    rm -rf ./analyze/csv_files/$profile/timeseries/*.csv

    exit 130
}

trap cleanup SIGINT SIGTERM SIGTSTP

source .venv/bin/activate

run_file(){
    local file="$1"
    local profile="$2"

    if python "$file" --profile "$profile" > /dev/null; then
        echo "Finished: $file"
    else
        echo "${RED}Failed to run: $file"
        return 1
    fi
}

profile="$1"

echo "${YELLOW}=====> Starting to create JSON file${RESET}"
run_file captures/generate_json.py "$profile"
echo "${GREEN}=====> Generate JSON successfully${RESET}"
echo

echo "${YELLOW}=====> Starting to analyze .pcap file${RESET}"
run_file analyze/sctp_single.py "$profile"
run_file analyze/sctp_mul.py "$profile"
echo "${GREEN}=====> Finished analyzing SCTP${RESET}"

run_file analyze/tcp_single.py "$profile"
run_file analyze/tcp_mul.py "$profile"
echo "${GREEN}=====> Finished analyzing TCP${RESET}"
echo
