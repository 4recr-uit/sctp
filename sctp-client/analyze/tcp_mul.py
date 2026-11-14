import argparse
import json
import math
from pathlib import Path

import pandas as pd
from scapy.utils import rdpcap
from scapy.layers.inet import IP, TCP

cli_parser = argparse.ArgumentParser()
cli_parser.add_argument("--profile", type=str, help="baseline, real")

args = cli_parser.parse_args()

PROJECT_DIR = Path("/home/tuan/Code/sctp-client")
PCAP_DIR = PROJECT_DIR / f"captures/{args.profile}/pcap"
JSON_DIR = PROJECT_DIR / f"captures/{args.profile}/json"
CSV_DIR = PROJECT_DIR / f"analyze/csv_files/{args.profile}"
TIME_SERIES_DIR = CSV_DIR / "timeseries"
GLOB = "tcp_mul_*.pcap"

INTERVAL = 0.10
TCP_STREAM = 5

CSV_DIR.mkdir(parents=True, exist_ok=True)

def handle_duplicates(pairs):
    result = {}

    for key, value in pairs:
        if key in result:
            if not isinstance(result[key], list):
                result[key] = [result[key]]

            result[key].append(value)
        else:
            result[key] = value

    return result

def tcp_retransmision(pcap_path: Path):
    with open(str(pcap_path), "r") as file:
        packets = json.load(file, object_pairs_hook=handle_duplicates)

    retrans_bytes = 0
    for pkt in packets:
        layer = pkt["_source"]["layers"]

        ip = layer["ip"]
        tcp = layer["tcp"]
        tcp_analysis = tcp["tcp.analysis"]["tcp.analysis.flags"]
        for analysis in tcp_analysis.get("_ws.expert", []):
            if "tcp.analysis.fast_retransmission" in analysis or \
                "tcp.analysis.retransmission" in analysis:
                    retrans_bytes += int(ip["ip.len"]) - int(ip["ip.hdr_len"])
                    break
                    print(int(ip["ip.len"]) - int(ip["ip.hdr_len"]) - int(tcp["tcp.hdr_len"]) )

    return retrans_bytes

def tcp_goodput(tcp_data, tcp_timestamps):
    if not tcp_data:
        return 0, [], [], []

    first_seq = min(tcp_data)
    last_seq = max(tcp_data)
    stream_bytes: list[ int ] = [ 0 ] * TCP_STREAM
    stream_start: list[ float | None ] = [ None ] * TCP_STREAM
    stream_end: list[ float | None ] = [ None ] * TCP_STREAM

    missing = [ seq for seq in range(first_seq, last_seq + 1) if seq not in tcp_data ]
    if missing:
        raise ValueError(f"TCP stream has {len(missing)} missing bytes")

    stream = bytes(tcp_data[seq] for seq in range(first_seq, last_seq + 1))
    offset = 0
    total_file_bytes = 0

    while offset < len(stream):
        if offset + 5 > len(stream):
            raise ValueError("Incomplete application header")

        stream_id = stream[offset]
        length = int.from_bytes(stream[offset + 1:offset + 5], "big")
        offset += 5

        if stream_id >= TCP_STREAM:
            raise ValueError(f"Invalid stream ID: {stream_id}")

        if offset + length > len(stream):
            raise ValueError("Incomplete application payload")

        if length > 0:
            first_data_time = tcp_timestamps[first_seq + offset]
            last_data_time = tcp_timestamps[first_seq + offset + length - 1]

            if stream_start[stream_id] is None:
                stream_start[stream_id] = first_data_time

            stream_end[stream_id] = last_data_time

        total_file_bytes += length
        stream_bytes[stream_id] += length
        offset += length

    return (total_file_bytes, stream_bytes, stream_start, stream_end)

def time_series(packets):
    start_time = float(packets[0].time)
    throughput = {}

    results = []

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
    
        ip = pkt[IP]
        tcp = pkt[TCP]
            
        tcp_bytes = int(ip.len) - int(ip.ihl * 4)
    
        elapsed = float(pkt.time) - start_time
        bin_index = max(0, math.ceil(elapsed / INTERVAL) - 1)
        throughput[bin_index] = (throughput.get(bin_index, 0) + tcp_bytes)

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

    CLIENT_PORT = packets[0][TCP].sport
    SERVER_PORT = packets[0][TCP].dport

    total_tcp_bytes = 0
    start_data_time = None
    end_data_time = None

    tcp_data = {}
    tcp_timestamps = {}

    total_header_bytes = 0
    total_transport_bytes = 0

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue

        ip = pkt[IP]
        tcp = pkt[TCP]

        total_tcp_bytes += int(ip.len) - int(ip.ihl) * 4

        total_header_bytes += int(tcp.dataofs) * 4
        total_transport_bytes += int(ip.len) - int(ip.ihl) * 4

        if tcp.sport != SERVER_PORT or tcp.dport != CLIENT_PORT:
            continue

        payload = bytes(tcp.payload)
        if not payload:
            continue

        if start_data_time == None:
            start_data_time = float(pkt.time)

        end_data_time = float(pkt.time)

        seq = int(tcp.seq)
        
        for i, byte in enumerate(payload):
            tcp_data[seq + i] = byte

        for i in range(len(payload)):
            tcp_timestamps.setdefault(seq + i, float(pkt.time))

    goodput_bytes, stream_goodput_bytes, stream_start_time, stream_end_time = tcp_goodput(tcp_data, tcp_timestamps)
    
    transfer_duration = 0
    if end_data_time != None and start_data_time != None:
        transfer_duration = end_data_time - start_data_time

    if total_header_bytes > total_transport_bytes:
        raise ValueError("Calculated overhead exceeds transport bytes")

    stream_results = []
    stream_throughput = [ 0.0 ] * TCP_STREAM
    for i in range(TCP_STREAM):
        stream_start = stream_start_time[i]
        stream_end = stream_end_time[i]
    
        stream_duration = 0.0
    
        if stream_start is not None and stream_end is not None:
            stream_duration = stream_end - stream_start

        stream_throughput[i] += stream_goodput_bytes[i] * 8 / (stream_duration * 1e6)
    
        stream_results.append({
            "experiment": pcap_path.stem,
            "stream_id": i,
            "duration": stream_duration,
            "goodput_bytes": stream_goodput_bytes[i],
            "goodput_mbps": stream_goodput_bytes[i] * 8 / (stream_duration * 1e6),
            "contribution_mbps": stream_goodput_bytes[i] * 8 / (transfer_duration * 1e6)
        })
    
    goodput_mbps = goodput_bytes * 8 / (transfer_duration * 1e6)
    tcp_throughput = total_tcp_bytes * 8 / (transfer_duration * 1e6)
    protocol_overhead = total_header_bytes * 100 / total_transport_bytes

    retrans_bytes = tcp_retransmision(Path(f"{JSON_DIR}/{pcap_path.stem}.json"))
    retrans_rate = retrans_bytes * 100 / sum(stream_goodput_bytes)
    jain_index = sum(stream_throughput) ** 2 / (TCP_STREAM * sum(n ** 2 for n in stream_throughput))

    summary = {
        "experiment": pcap_path.stem,
        "duration": transfer_duration,
        "goodput_bytes": goodput_bytes,
        "tcp_bytes": total_tcp_bytes,
        "data_bytes": sum(stream_goodput_bytes),
        "goodput_mbps": goodput_mbps,
        "tcp_throughput_mbps": tcp_throughput,
        "retrans_bytes": retrans_bytes,
        "retrans_rate": retrans_rate,
        "protocol_overhead": protocol_overhead,
        "jain_index": jain_index
    }

    return summary, stream_results, time_series(packets)

files = sorted(PCAP_DIR.glob(GLOB))
summaries, all_streams = [], []
for path in files:
    print(f"Analyzing: {path.name}")
    
    summary, streams, ts = analyze_pcap(path)
    ts.to_csv(TIME_SERIES_DIR / f"{path.stem}_summary.csv", index=False)
    summaries.append(summary)
    all_streams.extend(streams)
    
    print(f"Duration: {summary['duration']:.4f} s")
    print(f"Goodput: {summary['goodput_mbps']:.4f} Mbps")
    print(f"TCP Throughput: {summary['tcp_throughput_mbps']:.4f} Mbps")
    print(f"Retransmission Bytes: {summary['retrans_bytes']} bytes")
    print(f"Retransmission Rates: {summary['retrans_rate']}%")
    print(f"Protocol overhead: {summary['protocol_overhead']:.4f}%")
    print(f"Jain's Fairness Index: {summary['jain_index']:.4f}")
    print()

if summaries:
    pd.DataFrame(summaries).to_csv(CSV_DIR / "tcp_mul_summary.csv", index=False)
    pd.DataFrame(all_streams).to_csv(CSV_DIR / "tcp_mul_streams.csv", index=False)
print(f"Analyzed {len(summaries)}/{len(files)} files. Results in {CSV_DIR}")
