from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score

from src.data_loader import ensure_dataset
from src.preprocessing import build_preprocessor, get_feature_columns


MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "intrusion_model.pkl"
PREPROCESSOR_PATH = Path(__file__).resolve().parent.parent / "models" / "preprocessing_pipeline.pkl"


def train_model(data_path: str | Path | None = None) -> tuple[RandomForestClassifier, object, pd.DataFrame]:
    """Train and save the intrusion detection model."""
    dataset_path = ensure_dataset(data_path)
    df = pd.read_csv(dataset_path)

    feature_cols = get_feature_columns(df)
    X = df[feature_cols]
    y = df["label"]

    preprocessor = build_preprocessor(df)
    X_processed = preprocessor.fit_transform(X)

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced_subsample",
    )
    model.fit(X_processed, y)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(preprocessor, PREPROCESSOR_PATH)

    return model, preprocessor, df


def ensure_model_artifacts(data_path: str | Path | None = None):
    if not MODEL_PATH.exists() or not PREPROCESSOR_PATH.exists():
        train_model(data_path)

    model = joblib.load(MODEL_PATH)
    preprocessor = joblib.load(PREPROCESSOR_PATH)
    return model, preprocessor


def evaluate_model(data_path: str | Path | None = None) -> dict[str, float | str]:
    dataset_path = ensure_dataset(data_path)
    df = pd.read_csv(dataset_path)

    feature_cols = get_feature_columns(df)
    X = df[feature_cols]
    y = df["label"]

    preprocessor = build_preprocessor(df)
    X_processed = preprocessor.fit_transform(X)

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced_subsample",
    )
    clf.fit(X_processed, y)

    predictions = clf.predict(X_processed)
    report = {
        "accuracy": accuracy_score(y, predictions),
        "precision": precision_score(y, predictions, average="weighted", zero_division=0),
        "recall": recall_score(y, predictions, average="weighted", zero_division=0),
        "f1": f1_score(y, predictions, average="weighted", zero_division=0),
        "classification_report": classification_report(y, predictions),
    }
    return report
