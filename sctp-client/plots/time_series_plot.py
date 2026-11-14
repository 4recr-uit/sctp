import os
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.cm as cm
from pathlib import Path

cli_parser = argparse.ArgumentParser()
cli_parser.add_argument("--profile", type=str, help="baseline, real")

args = cli_parser.parse_args()

PROJECT_DIR = Path("/home/tuan/Code/sctp-client")
CSV_DIR = PROJECT_DIR / f"analyze/csv_files/{args.profile}/timeseries"
PLOTS_DIR = PROJECT_DIR / f"plots/{args.profile}/png"

os.makedirs(PLOTS_DIR, exist_ok=True)

def time_series_plot(protocol, glob_str, is_single=True):
    plt.rcParams.update({
        "axes.titlesize": 11,
        "axes.labelsize": 12,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "figure.titlesize": 16,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "lines.antialiased": True,
        "savefig.dpi": 300,
    })

    if is_single:
        fig, axes = plt.subplots(
                        nrows=5,
                        ncols=1,
                        figsize=(12, 12),
                        sharex=True,
                        sharey=True
                    )
    else:
        fig, axes = plt.subplots(
                        nrows=5,
                        ncols=1,
                        figsize=(12, 12),
                        sharex=True
                    )

    colors = [
        "#0072B2",
        "#E69F00",
        "#009E73",
        "#CC79A7",
        "#D55E00",
    ]
    
    csv_files = sorted(CSV_DIR.glob(glob_str))
    for index, (ax, csv_path) in enumerate(zip(axes, csv_files)):
        if "summary" in str(csv_path) and "mul" not in str(csv_path):
            continue

        df = pd.read_csv(csv_path)
        end_time = int(df["elapsed_time"].max())
        df = df[df["elapsed_time"] <= end_time]
    
        ax.plot(
            df["elapsed_time"],
            df["throughput_mbps"],
            color=colors[index % len(colors)],
            linewidth=1.2
        )
    
        ax.set_title(csv_path.stem.replace("_", " "), fontsize=10, fontweight="bold")
        ax.grid(True, linestyle="--", alpha=0.4)
    

    for ax in axes:
        ax.tick_params(axis="x", labelbottom=True)
    
    fig.supxlabel("Time (seconds)", fontsize=12)
    fig.supylabel("Throughput (Mbps)", fontsize=12)
    fig.suptitle(f"{protocol.upper()} Throughput Comparison", fontweight="bold", fontsize=14)
    
    fig.tight_layout(rect=(0.04, 0.02, 1, 0.97))

    if is_single:
        plt.savefig(PLOTS_DIR / f"{protocol.lower()}_single_throughput_comparison.png", dpi=300, bbox_inches="tight")
    else:
        plt.savefig(PLOTS_DIR / f"{protocol.lower()}_mul_throughput_comparison.png", dpi=300, bbox_inches="tight")

time_series_plot("SCTP", "sctp_single_*.csv")
time_series_plot("TCP", "tcp_single_*.csv")

time_series_plot("SCTP", "sctp_mul_*_summary.csv", False)
time_series_plot("TCP", "tcp_mul_*_summary.csv", False)
