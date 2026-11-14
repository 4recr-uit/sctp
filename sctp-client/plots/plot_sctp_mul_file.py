import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

PROJECT_DIR = Path("/home/tuan/Code/sctp-client")
CSV_DIR = PROJECT_DIR / "analyze/csv_files"
PLOT_DIR = PROJECT_DIR / "analyze/graphs"

PLOT_DIR.mkdir(parents=True, exist_ok=True)

summary_df = pd.read_csv(CSV_DIR / "sctp_summary.csv")
streams_df = pd.read_csv(CSV_DIR / "sctp_streams.csv")

# Sort experiments numerically
summary_df = summary_df.sort_values(
    "experiment",
    key=lambda col: col.str.extract(r"(\d+)$")[0].astype(int)
)

experiments = summary_df["experiment"].tolist()

streams_df["experiment"] = pd.Categorical(
    streams_df["experiment"],
    categories=experiments,
    ordered=True
)

streams_df = streams_df.sort_values(["experiment", "stream_id"])

# Matplotlib styling
plt.rcParams.update({
    "figure.figsize": (10, 5),
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "font.family": "serif",
    "font.size": 11,
    "axes.titlesize": 15,
    "axes.titleweight": "bold",
    "axes.labelsize": 12,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "grid.linestyle": "--",
    "legend.frameon": False,
})

COLORS = [
    "#4477AA",
    "#EE6677",
    "#228833",
    "#CCBB44",
    "#66CCEE",
]

x = range(len(experiments))

fig, ax = plt.subplots()

bars = ax.bar(
    x,
    summary_df["goodput_mbps"],
    width=0.6,
    color=COLORS[0],
    edgecolor="black",
    linewidth=0.7,
    zorder=3
)

ax.bar_label(bars, fmt="%.2f", padding=4)

ax.set_title("SCTP Goodput Comparison")
ax.set_xlabel("Experiment")
ax.set_ylabel("Goodput (Mbps)")

ax.set_xticks(list(x))
ax.set_xticklabels(experiments, rotation=20, ha="right")

ax.set_ylim(bottom=0)
ax.set_axisbelow(True)

fig.tight_layout()
fig.savefig(PLOT_DIR / "goodput_comparison.png", bbox_inches="tight")
plt.close()

fig, ax = plt.subplots(figsize=(11, 5))

width = 0.25

metrics = [
    ("Goodput", "goodput_mbps"),
    ("DATA Throughput", "data_throughput_mbps"),
    ("SCTP Throughput", "sctp_throughput_mbps"),
]

for i, (label, column) in enumerate(metrics):
    positions = [
        pos + (i - 1) * width
        for pos in x
    ]

    bars = ax.bar(
        positions,
        summary_df[column],
        width=width,
        label=label,
        color=COLORS[i],
        edgecolor="black",
        linewidth=0.5,
        zorder=3
    )

ax.set_title("SCTP Goodput and Throughput Comparison")
ax.set_xlabel("Experiment")
ax.set_ylabel("Throughput (Mbps)")

ax.set_xticks(list(x))
ax.set_xticklabels(experiments, rotation=20, ha="right")

ax.legend()
ax.set_ylim(bottom=0)
ax.set_axisbelow(True)

fig.tight_layout()
fig.savefig(PLOT_DIR / "throughput_comparison.png", bbox_inches="tight")
plt.close()

fig, ax = plt.subplots()

bars = ax.bar(
    x,
    summary_df["retrans_rate"],
    width=0.6,
    color=COLORS[1],
    edgecolor="black",
    linewidth=0.7,
    zorder=3
)

ax.bar_label(bars, fmt="%.2f%%", padding=4)

ax.set_title("SCTP Retransmission Rate")
ax.set_xlabel("Experiment")
ax.set_ylabel("Retransmission Rate (%)")

ax.set_xticks(list(x))
ax.set_xticklabels(experiments, rotation=20, ha="right")

ax.set_ylim(bottom=0)
ax.set_axisbelow(True)

fig.tight_layout()
fig.savefig(PLOT_DIR / "retransmission_rate.png", bbox_inches="tight")
plt.close()

stream_pivot = streams_df.pivot(
    index="experiment",
    columns="stream_id",
    values="contribution_mbps"
).fillna(0)

stream_pivot = stream_pivot.reindex(experiments)

fig, ax = plt.subplots(figsize=(11, 6))

bottom = [0.0] * len(experiments)

for i, stream_id in enumerate(stream_pivot.columns):
    values = stream_pivot[stream_id].tolist()

    ax.bar(
        x,
        values,
        bottom=bottom,
        width=0.65,
        label=f"Stream {stream_id}",
        color=COLORS[i % len(COLORS)],
        edgecolor="black",
        linewidth=0.5,
        zorder=3
    )

    bottom = [
        b + v
        for b, v in zip(bottom, values)
    ]

ax.set_title("SCTP Stream Goodput Contribution")
ax.set_xlabel("Experiment")
ax.set_ylabel("Goodput Contribution (Mbps)")

ax.set_xticks(list(x))
ax.set_xticklabels(experiments, rotation=20, ha="right")

ax.legend(title="Stream ID", bbox_to_anchor=(1.02, 1), loc="upper left")

ax.set_ylim(bottom=0)
ax.set_axisbelow(True)

fig.tight_layout()
fig.savefig(PLOT_DIR / "stream_contribution.png", bbox_inches="tight")
plt.close()

fig, ax = plt.subplots(figsize=(11, 5))

stream_ids = sorted(streams_df["stream_id"].unique())

width = 0.8 / len(stream_ids)

for i, stream_id in enumerate(stream_ids):
    stream_data = (
        streams_df[streams_df["stream_id"] == stream_id]
        .set_index("experiment")
        .reindex(experiments)
    )

    positions = [
        pos - 0.4 + width / 2 + i * width
        for pos in x
    ]

    ax.bar(
        positions,
        stream_data["goodput_mbps"],
        width=width,
        label=f"Stream {stream_id}",
        color=COLORS[i % len(COLORS)],
        edgecolor="black",
        linewidth=0.4,
        zorder=3
    )

ax.set_title("Individual SCTP Stream Goodput")
ax.set_xlabel("Experiment")
ax.set_ylabel("Goodput (Mbps)")

ax.set_xticks(list(x))
ax.set_xticklabels(experiments, rotation=20, ha="right")

ax.legend(title="Stream ID", bbox_to_anchor=(1.02, 1), loc="upper left")

ax.set_ylim(bottom=0)
ax.set_axisbelow(True)

fig.tight_layout()
fig.savefig(PLOT_DIR / "individual_stream_goodput.png", bbox_inches="tight")
plt.close()
