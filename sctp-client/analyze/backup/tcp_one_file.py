import json
import pandas as pd
from pathlib import Path
from scapy.utils import rdpcap
from scapy.layers.inet import IP, TCP

PROJECT_DIR = Path("/home/tuan/Code/sctp-client")
PCAP_DIR = PROJECT_DIR / "captures/pcap"
JSON_DIR = PROJECT_DIR / "captures/json"
CSV_DIR = PROJECT_DIR / "analyze/csv_files"

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

    return retrans_bytes

def add_ack_block(seq, data_len, ack_blocks):
    if data_len <= 0:
        return 0

    start = seq
    end = seq + data_len
    new_bytes = data_len

    merged = []
    for old_start, old_end in ack_blocks:
        if old_end <= start:
            merged.append((old_start, old_end))

        elif old_start >= end:
            merged.append((start, end))
            start, end = old_start, old_end

        else:
            overlap = min(end, old_end) - max(start, old_start)
            new_bytes -= max(0, overlap)

            start = min(start, old_start)
            end = max(end, old_end)

    merged.append((start, end))
    merged.sort()

    ack_blocks[:] = merged

    return new_bytes

def analyze_pcap(pcap_path: Path):
    packets = rdpcap(str(pcap_path))
    CLIENT_PORT = packets[0][TCP].sport
    SERVER_PORT = packets[0][TCP].dport

    unique_tcp_size = 0
    total_tcp_bytes = 0
    start_data_time = None
    end_data_time = None
    ack_blocks = []

    total_header_bytes = 0
    total_transport_bytes = 0
    
    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
    
        ip = pkt[IP]
        tcp = pkt[TCP]
    
        tcp_packet_size = ip.len - ip.ihl * 4 - tcp.dataofs * 4
        total_tcp_bytes += int(ip.len) - int(ip.ihl) * 4

        total_header_bytes += int(tcp.dataofs) * 4
        total_transport_bytes += int(ip.len) - int(ip.ihl) * 4
    
        if int(tcp.sport) != SERVER_PORT or int(tcp.dport) != CLIENT_PORT:
            continue
    
        if tcp_packet_size == 0:
            continue
    
        if start_data_time is None:
            start_data_time = float(pkt.time)
    
        end_data_time = float(pkt.time)
    
        unique_tcp_size += add_ack_block(int(tcp.seq), tcp_packet_size, ack_blocks)

    transfer_duration = 0
    if start_data_time != None and end_data_time != None:
        transfer_duration = end_data_time - start_data_time

    if total_header_bytes > total_transport_bytes:
        raise ValueError("Calculated overhead exceeds transport bytes")

    goodput = unique_tcp_size * 8 / (transfer_duration * 1e6)
    tcp_throughput = total_tcp_bytes * 8 / (transfer_duration * 1e6)
    protocol_overhead = total_header_bytes * 100 / total_transport_bytes

    retrans_bytes = tcp_retransmision(Path(f"{JSON_DIR}/{pcap_path.stem}.json"))
    retrans_rate = retrans_bytes * 100 / total_tcp_bytes

    summary = {
        "experiment": pcap_path.stem,
        "duration": transfer_duration,
        "goodput_bytes": unique_tcp_size,
        "tcp_bytes": total_tcp_bytes,
        "goodput_mbps": goodput,
        "tcp_throughput_mbps": tcp_throughput,
        "retrans_bytes": retrans_bytes,
        "retrans_rate": retrans_rate,
        "protocol_overhead": protocol_overhead
    }

    return summary

summary_results = []

pcap_files = sorted(PCAP_DIR.glob("tcp_single_*.pcap"))

for pcap_path in pcap_files:
    print(f"Analyzing: {pcap_path.name}")

    summary = analyze_pcap(pcap_path)
    summary_results.append(summary)

    print(f"Duration: {summary['duration']:.4f} s")
    print(f"Goodput: {summary['goodput_mbps']:.4f} Mbps")
    print(f"TCP Throughput: {summary['tcp_throughput_mbps']:.4f} Mbps")
    print(f"Retransmission Bytes: {summary['retrans_bytes']} bytes")
    print(f"Retransmission Rates: {summary['retrans_rate']}%")
    print(f"Protocol overhead: {summary['protocol_overhead']:.4f}%")
    print()

summary_df = pd.DataFrame(summary_results)

summary_df.to_csv(CSV_DIR / "tcp_single_summary.csv", index=False)

print(f"Analyzed {len(pcap_files)} PCAP files.")
print(f"Results saved to {CSV_DIR}")
