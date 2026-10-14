from __future__ import annotations

from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_DIR / "data"
MODEL_DIR = PROJECT_DIR / "models"


def safe_format(value: int | float) -> str:
    if abs(value) >= 1_000_000:
        return f"{value / 1_000_000:.2f}M"
    if abs(value) >= 1_000:
        return f"{value / 1_000:.2f}K"
    return str(int(value))


def status_badge(label: str) -> str:
    mapping = {
        "Benign": "background: #1d4d36; color: #a7f3d0; border-radius: 999px; padding: 0.25rem 0.75rem;",
        "Suspicious": "background: #854d0e; color: #fef3c7; border-radius: 999px; padding: 0.25rem 0.75rem;",
        "Malicious": "background: #7f1d1d; color: #fecaca; border-radius: 999px; padding: 0.25rem 0.75rem;",
    }
    return mapping.get(label, "background: #1f2937; color: white; border-radius: 999px; padding: 0.25rem 0.75rem;")
