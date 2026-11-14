import argparse
import json
import subprocess
from pathlib import Path

cli_parser = argparse.ArgumentParser()
cli_parser.add_argument("--profile", type=str, help="baseline, real")

args = cli_parser.parse_args()

CAPTURE_DIR = Path("/home/tuan/Code/sctp-client/captures")
PCAP_DIR = CAPTURE_DIR / f"{args.profile}/pcap"
JSON_DIR = CAPTURE_DIR / f"{args.profile}/json"

sctp_pcap_files = PCAP_DIR.glob("sctp_*")
tcp_pcap_files = PCAP_DIR.glob("tcp_*")

PCAP_DIR.mkdir(exist_ok=True, parents=True)
JSON_DIR.mkdir(exist_ok=True, parents=True)

for pcap_path in sctp_pcap_files:
    result = subprocess.run(
        [
            "tshark",
            "-r", str(pcap_path),
            "-Y", "sctp.retransmission",
            "-T", "json",
        ],
        capture_output=True,
        text=True,
        check=True
    )

    with open(str(JSON_DIR / f"{pcap_path.stem}.json"), "w") as f:
        f.write(result.stdout)

for pcap_path in tcp_pcap_files:
    result = subprocess.run(
        [
            "tshark",
            "-r", str(pcap_path),
            "-Y", "tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.spurious_retransmission",
            "-T", "json",
        ],
        capture_output=True,
        text=True,
        check=True
    )

    with open(str(JSON_DIR / f"{pcap_path.stem}.json"), "w") as f:
        f.write(result.stdout)
