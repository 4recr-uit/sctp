import argparse
import json
import math
from pathlib import Path

import pandas as pd
from scapy.utils import rdpcap
from scapy.layers.inet import IP, UDP
from scapy.layers.sctp import SCTP, SCTPChunkData

cli_parser = argparse.ArgumentParser()
cli_parser.add_argument("--profile", type=str, help="baseline, real")

args = cli_parser.parse_args()

PROJECT_DIR = Path("/home/tuan/Code/sctp-client")
PCAP_DIR = PROJECT_DIR / f"captures/{args.profile}/pcap"
JSON_DIR = PROJECT_DIR / f"captures/{args.profile}/json"
CSV_DIR = PROJECT_DIR / f"analyze/csv_files/{args.profile}"
TIME_SERIES_DIR = CSV_DIR / "timeseries"
GLOB = "sctp_single_*.pcap"

INTERVAL = 0.05

CSV_DIR.mkdir(parents=True, exist_ok=True)

def json_extract_chunks(pkt):
    if isinstance(pkt, list):
        if pkt and all(isinstance(item, tuple) and len(item) == 2 for item in pkt):
            d = dict(pkt)

            if d.get("sctp.chunk_type") == "0":
                yield d

            for _, value in pkt:
                yield from json_extract_chunks(value)

        else:
            for value in pkt:
                yield from json_extract_chunks(value)

def sctp_retransmision(pcap_path: Path):
    with open(str(pcap_path), "r") as file:
        packets = json.load(file, object_pairs_hook=list)

    retrans_bytes = 0
    for pkt in packets:
        for chunk in json_extract_chunks(pkt):
            chunk = dict(chunk)

            if "sctp.data_tsn_tree" in chunk and "sctp.retransmission" in dict(chunk["sctp.data_tsn_tree"]):
                retrans_bytes += int(chunk["sctp.chunk_length"])

    return retrans_bytes

def time_series(packets):
    start_time = float(packets[0].time)
    throughput = {}
    
    results = []
    
    for pkt in packets:
        if IP not in pkt or SCTP not in pkt:
            continue
    
        ip = pkt[IP]
        sctp = pkt[SCTP]
        chunk = sctp.payload
            
        sctp_bytes = int(ip.len) - int(ip.ihl * 4)
    
        elapsed = float(pkt.time) - start_time
        bin_index = max(0, math.ceil(elapsed / INTERVAL) - 1)
        throughput[bin_index] = (throughput.get(bin_index, 0) + sctp_bytes)
    
    for index, byte_count in sorted(throughput.items()): 
        results.append({
            "elapsed_time": round((index + 1) * INTERVAL, 3),
            "bytes": byte_count,
            "throughput_mbps": byte_count * 8 / INTERVAL / 1_000_000
        })
    
    df = pd.DataFrame(results)
    return df    

def analyze_pcap(pcap_path: Path):
    packets = rdpcap(str(pcap_path))

    goodput_bytes = 0
    sctp_bytes = 0
    seen_tsn = set()
    start_transfer_time = None
    end_transfer_time = None

    total_header_bytes = 0
    total_transport_bytes = 0

    for pkt in packets:
        if SCTP not in pkt or IP not in pkt:
            continue
    
        ip = pkt[IP]
        sctp = pkt[SCTP]
        chunk = sctp.payload
    
        sctp_bytes += int(ip.len) - int(ip.ihl * 4)

        total_header_bytes += 12
        if UDP in pkt:
            total_header_bytes += 8

        total_transport_bytes += int(ip.len) - int(ip.ihl) * 4
    
        while chunk:
            chunk_length = int(chunk.len) if hasattr(chunk, "len") else len(bytes(chunk))
            padded_length = (chunk_length + 3) & ~3
            total_header_bytes += padded_length - chunk_length

            if not isinstance(chunk, SCTPChunkData):
                total_header_bytes += chunk_length
                chunk = chunk.payload
                continue
    
            tsn = int(chunk.tsn)
            chunk_length = int(chunk.len)
            payload_size = max(0, chunk_length - 16)

            total_header_bytes += chunk_length - payload_size
    
            if tsn not in seen_tsn:
                seen_tsn.add(tsn)
                goodput_bytes += payload_size
    
            if start_transfer_time is None:
                start_transfer_time = float(pkt.time)
    
            end_transfer_time = float(pkt.time)
    
            chunk = chunk.payload

    transfer_duration = 0
    if start_transfer_time is not None and end_transfer_time is not None:
        transfer_duration = end_transfer_time - start_transfer_time

    if total_header_bytes > total_transport_bytes:
        raise ValueError("Calculated overhead exceeds transport bytes")

    goodput_mbps = goodput_bytes * 8 / (transfer_duration * 1e6)
    sctp_throughput = sctp_bytes * 8 / (transfer_duration * 1e6)

    retrans_bytes = sctp_retransmision(Path(f"{JSON_DIR}/{pcap_path.stem}.json"))
    retrans_rate = retrans_bytes * 100 / sctp_bytes 

    protocol_overhead = total_header_bytes * 100 / total_transport_bytes

    summary = {
        "experiment": pcap_path.stem,
        "duration": transfer_duration,
        "goodput_bytes": goodput_bytes,
        "sctp_bytes": sctp_bytes,
        "goodput_mbps": goodput_mbps,
        "sctp_throughput_mbps": sctp_throughput,
        "retrans_bytes": retrans_bytes,
        "retrans_rate": retrans_rate,
        "protocol_overhead": protocol_overhead
    }
    return summary, time_series(packets)

pcap_files = sorted(list(PCAP_DIR.glob(GLOB)))
summaries = []
for path in pcap_files:
    print(f"Analyzing: {path.name}")
    summary, ts = analyze_pcap(path)
    ts.to_csv(TIME_SERIES_DIR / f"{path.stem}.csv", index=False)
    summaries.append(summary)

    print(f"Duration: {summary['duration']:.4f} s")
    print(f"Goodput: {summary['goodput_mbps']:.4f} Mbps")
    print(f"SCTP Throughput: {summary['sctp_throughput_mbps']:.4f} Mbps")
    print(f"Retransmission Bytes: {summary['retrans_bytes']} bytes")
    print(f"Retransmission Rates: {summary['retrans_rate']}%")
    print(f"Protocol overhead: {summary['protocol_overhead']:.4f}%")
    print()

if summaries:
    pd.DataFrame(summaries).to_csv(CSV_DIR / "sctp_single_summary.csv", index=False)
print(f"Analyzed {len(summaries)}/{len(pcap_files)} files. Results in {CSV_DIR}")
