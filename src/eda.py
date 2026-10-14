from __future__ import annotations

import pandas as pd
import plotly.express as px


def describe_dataset(df: pd.DataFrame) -> dict[str, int | float]:
    summary = {
        "rows": len(df),
        "columns": len(df.columns),
        "missing_values": int(df.isnull().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "benign_count": int((df["label"] == "Benign").sum()),
        "suspicious_count": int((df["label"] == "Suspicious").sum()),
        "malicious_count": int((df["label"] == "Malicious").sum()),
    }
    return summary


def build_protocol_chart(df: pd.DataFrame):
    protocol_counts = df.groupby(["protocol", "label"]).size().reset_index(name="count")
    return px.bar(
        protocol_counts,
        x="protocol",
        y="count",
        color="label",
        barmode="group",
        title="Traffic by Protocol and Label",
        color_discrete_map={
            "Benign": "#22c55e",
            "Suspicious": "#f59e0b",
            "Malicious": "#ef4444",
        },
    )


def build_attack_distribution(df: pd.DataFrame):
    counts = df.groupby("attack_type").size().reset_index(name="count")
    return px.pie(
        counts,
        names="attack_type",
        values="count",
        title="Attack Type Distribution",
        hole=0.45,
    )


def build_port_activity(df: pd.DataFrame):
    top_ports = df["dst_port"].value_counts().head(10).reset_index()
    top_ports.columns = ["port", "count"]
    return px.bar(
        top_ports,
        x="port",
        y="count",
        title="Top Destination Ports",
        color_discrete_sequence=["#7c3aed"],
    )


def build_flow_scatter(df: pd.DataFrame):
    subset = df.head(3000).copy()
    subset["bytes_total"] = subset["bytes_in"] + subset["bytes_out"]
    return px.scatter(
        subset,
        x="duration_ms",
        y="bytes_total",
        color="label",
        title="Traffic Intensity vs Duration",
        color_discrete_map={
            "Benign": "#22c55e",
            "Suspicious": "#f59e0b",
            "Malicious": "#ef4444",
        },
    )
