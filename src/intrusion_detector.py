from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.data_loader import ensure_dataset
from src.preprocessing import get_feature_columns


def predict_dataframe(model, preprocessor, df: pd.DataFrame) -> pd.DataFrame:
    feature_cols = [col for col in get_feature_columns(df)]
    X = df[feature_cols]
    transformed = preprocessor.transform(X)
    predictions = model.predict(transformed)
    scores = model.predict_proba(transformed)
    confidence = scores.max(axis=1)

    result = df.copy()
    result["predicted_label"] = predictions
    result["confidence"] = confidence
    return result


def predict_dataset(model, preprocessor, dataset_path: str | Path | None = None) -> pd.DataFrame:
    dataset_path = ensure_dataset(dataset_path)
    df = pd.read_csv(dataset_path)
    return predict_dataframe(model, preprocessor, df)


def label_to_severity(label: str) -> str:
    if label == "Malicious":
        return "Critical"
    if label == "Suspicious":
        return "High"
    return "Low"
