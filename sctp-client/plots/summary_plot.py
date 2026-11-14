import argparse
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path

cli_parser = argparse.ArgumentParser()
cli_parser.add_argument("--profile", type=str, help="baseline, real")

args = cli_parser.parse_args()

PROJECT_DIR = Path("/home/tuan/Code/sctp-client")
CSV_DIR = PROJECT_DIR / f"analyze/csv_files/{args.profile}"
PLOTS_DIR = PROJECT_DIR / f"plots/{args.profile}/png"

TCP_SINGLE = CSV_DIR / "tcp_single_summary.csv"
SCTP_SINGLE = CSV_DIR / "sctp_single_summary.csv"

TCP_MUL = CSV_DIR / "tcp_mul_summary.csv"
SCTP_MUL = CSV_DIR / "sctp_mul_summary.csv"

os.makedirs(PLOTS_DIR, exist_ok=True)

def plot_throughput_bar(tcp_path: Path, sctp_path: Path, isSingle=True):
    df_tcp_summary = pd.read_csv(str(tcp_path))
    df_sctp_summary = pd.read_csv(str(sctp_path))

    fig, ax = plt.subplots(figsize=(11, 5))

    x = np.arange(len(df_tcp_summary))
    width = 0.35

    ax.bar(
            x - width/2,
            df_tcp_summary["tcp_throughput_mbps"],
            width=width,
            label="TCP Throughput",
            color="steelblue",
            edgecolor="black",
            linewidth=0.5,
            zorder=3
            )

    ax.bar(
            x + width/2,
            df_sctp_summary["sctp_throughput_mbps"],
            width=width,
            label="SCTP Throughput",
            color="orange",
            edgecolor="black",
            linewidth=0.5,
            zorder=3
            )

    ax.set_xlabel("Experiment")
    ax.set_ylabel("Throughput (Mbps)")
    ax.set_title("TCP vs SCTP Throughput Comparison")

    ax.set_xticks(x)
    ax.set_xticklabels([f"Experiment {i}" for i in range(1, 6)])

    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.5, zorder=0)

    plt.tight_layout()
    if isSingle:
        plt.savefig(PLOTS_DIR / f"summary_single_throughput_comparison.png", dpi=300, bbox_inches="tight")
    else:
        plt.savefig(PLOTS_DIR / f"summary_mul_throughput_comparison.png", dpi=300, bbox_inches="tight")

def plot_overhead_bar(tcp_path: Path, sctp_path: Path, isSingle=True):
    df_tcp_summary = pd.read_csv(str(tcp_path))
    df_sctp_summary = pd.read_csv(str(sctp_path))

    fig, ax = plt.subplots(figsize=(11, 5))
    x = np.arange(len(df_tcp_summary))
    width = 0.35

    ax.bar(
            x - width/2,
            df_tcp_summary["protocol_overhead"],
            width=width,
            label="TCP overhead",
            color="steelblue",
            edgecolor="black",
            linewidth=0.5,
            zorder=3
            )

    ax.bar(
            x + width/2,
            df_sctp_summary["protocol_overhead"],
            width=width,
            label="SCTP overhead",
            color="orange",
            edgecolor="black",
            linewidth=0.5,
            zorder=3
            )

    ax.set_xlabel("Experiment")
    ax.set_ylabel("Overhead (%)")
    ax.set_title("TCP vs SCTP Overhead Comparison")

    ax.set_xticks(x)
    ax.set_xticklabels([f"Experiment {i}" for i in range(1, 6)])

    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.5, zorder=0)

    plt.tight_layout()
    if isSingle:
        plt.savefig(PLOTS_DIR / f"summary_single_overhead_comparison.png", dpi=300, bbox_inches="tight")
    else:
        plt.savefig(PLOTS_DIR / f"summary_mul_overhead_comparison.png", dpi=300, bbox_inches="tight")

plot_throughput_bar(TCP_SINGLE, SCTP_SINGLE)
plot_throughput_bar(TCP_MUL, SCTP_MUL, False)

plot_overhead_bar(TCP_SINGLE, SCTP_SINGLE)
plot_overhead_bar(TCP_MUL, SCTP_MUL, False)
