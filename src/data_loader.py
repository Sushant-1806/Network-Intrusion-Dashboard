from __future__ import annotations

import numpy as np
import pandas as pd
from pathlib import Path


DATASET_FILENAME = "network_traffic.csv"


def ensure_dataset(data_dir: str | Path | None = None) -> Path:
    """Load an existing dataset or generate a realistic synthetic one."""
    root = Path(data_dir) if data_dir is not None else Path(__file__).resolve().parent.parent
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    dataset_path = data_dir / DATASET_FILENAME

    if not dataset_path.exists():
        generate_synthetic_data(dataset_path)

    return dataset_path


def generate_synthetic_data(path: str | Path) -> pd.DataFrame:
    """Create a realistic flow-based network traffic dataset."""
    rng = np.random.default_rng(42)
    rows = 24000

    protocols = ["TCP", "UDP", "ICMP", "HTTP", "DNS", "SSH"]
    src_ips = [f"10.0.0.{i}" for i in range(1, 81)]
    dst_ips = [f"192.168.1.{i}" for i in range(1, 121)]
    countries = ["US", "UK", "DE", "IN", "CN", "JP", "BR", "CA"]
    states = ["ESTABLISHED", "SYN_SENT", "TIME_WAIT", "FIN_WAIT", "CLOSE_WAIT", "LISTEN"]
    attack_types = [
        "Normal",
        "Port Scan",
        "DDoS",
        "Botnet",
        "Credential Stuffing",
        "Malware Beaconing",
        "Data Exfiltration",
    ]

    records = []

    for idx in range(rows):
        rnd = rng.random()
        if rnd < 0.72:
            label = "Benign"
            attack_type = "Normal"
            severity = 0
            failed_logins = int(rng.integers(0, 2))
            duration_ms = int(rng.integers(5, 1300))
            packets = int(rng.integers(8, 450))
            bytes_in = int(rng.integers(500, 50000))
            bytes_out = int(rng.integers(400, 35000))
            packet_size = float(rng.uniform(40, 150))
            flow_rate = float(rng.uniform(1, 150))
            tcp_flags = int(rng.integers(0, 15))
            protocol = str(rng.choice(protocols))
            dst_port = int(rng.integers(20, 65535))
            src_port = int(rng.integers(1000, 65535))
            country = str(rng.choice(countries))
            src_ip = str(rng.choice(src_ips))
            dst_ip = str(rng.choice(dst_ips))
        elif rnd < 0.9:
            label = "Suspicious"
            attack_type = str(rng.choice(["Port Scan", "Botnet", "Credential Stuffing"]))
            severity = 1
            failed_logins = int(rng.integers(3, 12))
            duration_ms = int(rng.integers(1500, 60000))
            packets = int(rng.integers(150, 1500))
            bytes_in = int(rng.integers(20000, 600000))
            bytes_out = int(rng.integers(8000, 450000))
            packet_size = float(rng.uniform(80, 260))
            flow_rate = float(rng.uniform(100, 600))
            tcp_flags = int(rng.integers(1, 24))
            protocol = str(rng.choice(["TCP", "UDP", "DNS", "HTTP"]))
            dst_port = int(rng.choice([22, 23, 80, 443, 53, 3389, 8080]))
            src_port = int(rng.integers(1024, 65535))
            country = str(rng.choice(countries))
            src_ip = str(rng.choice(src_ips))
            dst_ip = str(rng.choice(dst_ips))
        else:
            label = "Malicious"
            attack_type = str(rng.choice(["DDoS", "Malware Beaconing", "Data Exfiltration"]))
            severity = 2
            failed_logins = int(rng.integers(8, 50))
            duration_ms = int(rng.integers(20000, 250000))
            packets = int(rng.integers(1200, 22000))
            bytes_in = int(rng.integers(700000, 15000000))
            bytes_out = int(rng.integers(150000, 12000000))
            packet_size = float(rng.uniform(140, 500))
            flow_rate = float(rng.uniform(500, 4000))
            tcp_flags = int(rng.integers(10, 30))
            protocol = str(rng.choice(["TCP", "UDP", "ICMP"]))
            dst_port = int(rng.choice([80, 443, 53, 22, 25, 3389]))
            src_port = int(rng.integers(1024, 65535))
            country = str(rng.choice(countries))
            src_ip = str(rng.choice(src_ips))
            dst_ip = str(rng.choice(dst_ips))

        records.append(
            {
                "timestamp": pd.Timestamp("2024-01-01") + pd.to_timedelta(idx % 7000, unit="min"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "duration_ms": duration_ms,
                "packets": packets,
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "packet_size_mean": packet_size,
                "flow_rate": flow_rate,
                "tcp_flags": tcp_flags,
                "connection_state": str(rng.choice(states)),
                "failed_logins": failed_logins,
                "is_dns_tunnel": int(rng.integers(0, 2)) if label != "Benign" else 0,
                "risk_score": int(rng.integers(10, 95)) + severity * 12,
                "src_country": country,
                "dst_country": str(rng.choice(countries)),
                "attack_type": attack_type,
                "label": label,
                "severity": severity,
            }
        )

    df = pd.DataFrame.from_records(records)
    df = df.sort_values("timestamp").reset_index(drop=True)

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    return df


def load_dataset(data_path: str | Path | None = None) -> pd.DataFrame:
    """Return the network dataset, generating it if needed."""
    dataset_path = ensure_dataset(data_path)
    df = pd.read_csv(dataset_path)
    if "label" not in df.columns:
        raise ValueError("The dataset must include a 'label' column for classification.")
    return df
