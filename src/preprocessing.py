from __future__ import annotations

from typing import Tuple

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

TARGET_COLUMN = "label"


def get_feature_columns(df: pd.DataFrame) -> list[str]:
    exclude = {"timestamp", "src_ip", "dst_ip", "attack_type", TARGET_COLUMN}
    return [col for col in df.columns if col not in exclude]


def build_preprocessor(df: pd.DataFrame) -> ColumnTransformer:
    feature_cols = get_feature_columns(df)
    numeric_cols = df[feature_cols].select_dtypes(include=["number"]).columns.tolist()
    categorical_cols = [col for col in feature_cols if col not in numeric_cols]

    transformers = []
    if numeric_cols:
        transformers.append(
            (
                "numeric",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="median")),
                        ("scaler", StandardScaler()),
                    ]
                ),
                numeric_cols,
            )
        )
    if categorical_cols:
        transformers.append(
            (
                "categorical",
                Pipeline(
                    steps=[
                        ("imputer", SimpleImputer(strategy="most_frequent")),
                        ("encoder", OneHotEncoder(handle_unknown="ignore")),
                    ]
                ),
                categorical_cols,
            )
        )

    if not transformers:
        raise ValueError("No usable feature columns were found in the dataset.")

    return ColumnTransformer(transformers=transformers, remainder="drop")


def prepare_training_data(df: pd.DataFrame, test_size: float = 0.25, random_state: int = 42):
    feature_cols = get_feature_columns(df)
    X = df[feature_cols]
    y = df[TARGET_COLUMN]

    preprocessor = build_preprocessor(df)
    X_processed = preprocessor.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_processed,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    return X_train, X_test, y_train, y_test, preprocessor


def build_model_input(df: pd.DataFrame):
    feature_cols = get_feature_columns(df)
    preprocessor = build_preprocessor(df)
    transformed = preprocessor.fit_transform(df[feature_cols])
    return transformed, preprocessor
