import os
import math
import pandas as pd
from pathlib import Path
from scapy.utils import rdpcap
from scapy.layers.inet import IP
from scapy.layers.sctp import SCTP, SCTPChunkData

PROJECT_DIR = Path("/home/tuan/Code/sctp-client")
PCAP_DIR = PROJECT_DIR / "captures/pcap"
CSV_DIR = PROJECT_DIR / "analyze/csv_files"
TIME_SERIES_DIR = CSV_DIR / "timeseries"

os.makedirs(TIME_SERIES_DIR, exist_ok=True)

INTERVAL = 0.10

for pcap_path in PCAP_DIR.glob("sctp_mul_*"):
    packets = rdpcap(str(pcap_path))

    start_time = float(packets[0].time)
    total_throughput = {}

    results = []

    for pkt in packets:
        if IP not in pkt or SCTP not in pkt:
            continue
    
        ip = pkt[IP]
        sctp = pkt[SCTP]
        chunk = sctp.payload

        if not isinstance(chunk, SCTPChunkData):
            continue

        sctp_bytes = int(ip.len) - int(ip.ihl * 4)
    
        elapsed = float(pkt.time) - start_time
        bin_index = max(0, math.ceil(elapsed / INTERVAL) - 1)
        total_throughput[bin_index] = (total_throughput.get(bin_index, 0) + sctp_bytes)

    for index, byte_count in sorted(total_throughput.items()): 
        results.append({
            "elapsed_time": round((index + 1) * INTERVAL, 3),
            "bytes": byte_count,
            "throughput_mbps": byte_count * 8 / INTERVAL / 1_000_000
        })

    df = pd.DataFrame(results)
    output_file = TIME_SERIES_DIR / f"{pcap_path.stem}_summary.csv"
    df.to_csv(output_file, index=False)
    print(f"Saved: {output_file}")
