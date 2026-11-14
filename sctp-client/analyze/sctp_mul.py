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
GLOB = "sctp_mul_*.pcap"

INTERVAL = 0.10
SCTP_STREAM = 5

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
    return df

def analyze_pcap(pcap_path: Path):
    packets = rdpcap(str(pcap_path))
    
    seen_tsn = set()

    goodput_bytes = 0
    total_sctp_bytes = 0

    stream_goodput_bytes: list[ int ] = [ 0 for i in range(SCTP_STREAM) ]
    stream_sctp_bytes: list[ int ] = [ 0 for i in range(SCTP_STREAM) ]

    start_stream_time: list[ float | None ] = [ None for i in range(SCTP_STREAM) ]
    end_stream_time: list[ float | None ] = [ None for i in range(SCTP_STREAM) ]

    total_start_time = None
    total_end_time = None

    total_header_bytes = 0
    total_transport_bytes = 0

    for pkt in packets:
        if SCTP not in pkt or IP not in pkt:
            continue

        ip = pkt[IP]
        sctp = pkt[SCTP]
        chunk = sctp.payload

        total_header_bytes += 12
        if UDP in pkt:
            total_header_bytes += 8

        total_transport_bytes += int(ip.len) - int(ip.ihl) * 4

        total_sctp_bytes += int(ip.len) - int(ip.ihl) * 4

        while chunk:
            chunk_length = int(chunk.len) if hasattr(chunk, "len") else len(bytes(chunk))
            padded_length = (chunk_length + 3) & ~3
            total_header_bytes += padded_length - chunk_length

            if not isinstance(chunk, SCTPChunkData):
                total_header_bytes += chunk_length
                chunk = chunk.payload
                continue
            
            data_chunk = chunk

            tsn = int(data_chunk.tsn)
            stream_id = int(data_chunk.stream_id)
            
            payload_size = max(0, chunk_length - 16)
            total_header_bytes += chunk_length - payload_size

            stream_sctp_bytes[stream_id] += chunk_length

            if tsn not in seen_tsn:
                seen_tsn.add(tsn)
                goodput_bytes += payload_size
                stream_goodput_bytes[stream_id] += payload_size

            if start_stream_time[stream_id] is None:
                start_stream_time[stream_id] = float(pkt.time)

            end_stream_time[stream_id] = float(pkt.time)

            if total_start_time is None:
                total_start_time = float(pkt.time)

            total_end_time = float(pkt.time)

            chunk = chunk.payload

    if total_start_time is None or total_end_time is None:
        raise ValueError(f"No SCTP DATA chunks found in {pcap_path.name}")

    transfer_duration = total_end_time - total_start_time
    if transfer_duration <= 0:
        raise ValueError(f"Invalid transfer duration: {pcap_path.name}")

    if total_header_bytes > total_transport_bytes:
        raise ValueError("Calculated overhead exceeds transport bytes")
    
    stream_results = []
    stream_throughput = [ 0.0 ] * SCTP_STREAM
    for i in range(SCTP_STREAM):
        stream_start = start_stream_time[i]
        stream_end = end_stream_time[i]

        stream_duration = 0.0
        if stream_start is not None and stream_end is not None:
            stream_duration = stream_end - stream_start

        stream_throughput[i] += stream_goodput_bytes[i] * 8 / (stream_duration * 1e6)

        stream_results.append({
            "experiment": pcap_path.stem,
            "stream_id": i,
            "duration": stream_duration,
            "goodput_bytes": stream_goodput_bytes[i],
            "sctp_bytes": stream_sctp_bytes[i],
            "goodput_mbps": stream_goodput_bytes[i] * 8 / (stream_duration * 1e6),
            "sctp_throughput_mbps": stream_sctp_bytes[i] * 8 / (stream_duration * 1e6),
            "contribution_mbps": stream_goodput_bytes[i] * 8 / (transfer_duration * 1e6)
            })

    total_goodput = goodput_bytes * 8 / (transfer_duration * 1e6)
    sctp_throughput = total_sctp_bytes * 8 / (transfer_duration * 1e6)
    data_throughput = sum(stream_sctp_bytes) * 8 / (transfer_duration * 1e6)
    protocol_overhead = total_header_bytes * 100 / total_transport_bytes

    retrans_bytes = sctp_retransmision(Path(f"{JSON_DIR}/{pcap_path.stem}.json"))
    retrans_rate = retrans_bytes * 100 / sum(stream_sctp_bytes)
    jain_index = sum(stream_throughput) ** 2 / (SCTP_STREAM * sum(n ** 2 for n in stream_throughput))

    summary = {
        "experiment": pcap_path.stem,
        "duration": transfer_duration,
        "goodput_bytes": goodput_bytes,
        "sctp_bytes": total_sctp_bytes,
        "data_bytes": sum(stream_sctp_bytes),
        "goodput_mbps": total_goodput,
        "sctp_throughput_mbps": sctp_throughput,
        "data_throughput_mbps": data_throughput,
        "retrans_bytes": retrans_bytes,
        "retrans_rate": retrans_rate,
        "protocol_overhead": protocol_overhead,
        "jain_index": jain_index
    }

    return summary, stream_results, time_series(packets)


files = sorted(list(PCAP_DIR.glob(GLOB)))
summaries, all_streams = [], []
for path in files:
    print(f"Analyzing: {path.name}")
    summary, streams, ts = analyze_pcap(path)
    ts.to_csv(TIME_SERIES_DIR / f"{path.stem}_summary.csv", index=False)
    summaries.append(summary)
    all_streams.extend(streams)

    print(f"Duration: {summary['duration']:.4f} s")
    print(f"Goodput: {summary['goodput_mbps']:.4f} Mbps")
    print(f"SCTP Throughput: {summary['sctp_throughput_mbps']:.4f} Mbps")
    print(f"Retransmission Bytes: {summary['retrans_bytes']} bytes")
    print(f"Retransmission Rates: {summary['retrans_rate']:.4f}%")
    print(f"Protocol overhead: {summary['protocol_overhead']:.4f}%")
    print(f"Jain's Fairness Index: {summary['jain_index']:.4f}")
    print()

if summaries:
    pd.DataFrame(summaries).to_csv(CSV_DIR / "sctp_mul_summary.csv", index=False)
    pd.DataFrame(all_streams).to_csv(CSV_DIR / "sctp_mul_streams.csv", index=False)
print(f"Analyzed {len(summaries)}/{len(files)} files. Results in {CSV_DIR}")
