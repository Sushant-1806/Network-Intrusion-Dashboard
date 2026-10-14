from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from src.data_loader import load_dataset
from src.eda import (
    build_attack_distribution,
    build_flow_scatter,
    build_port_activity,
    build_protocol_chart,
    describe_dataset,
)
from src.intrusion_detector import label_to_severity, predict_dataframe, predict_dataset
from src.train_model import ensure_model_artifacts
from src.utils import safe_format


st.set_page_config(page_title="Network Intrusion Dashboard", page_icon="🛡️", layout="wide")

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_PATH = PROJECT_ROOT / "data" / "network_traffic.csv"


st.markdown(
    """
    <style>
    html, body, [data-testid="stAppViewContainer"] {
        background: #08111f;
        color: #e5eefc;
        font-family: 'Segoe UI', sans-serif;
    }
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }
    div[data-testid="stSidebar"] {
        background: #0c1729;
        border-right: 1px solid rgba(148, 163, 184, 0.2);
    }
    .stMetric {
        background: rgba(15, 23, 42, 0.8);
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 14px;
        padding: 1rem;
        box-shadow: 0 10px 25px rgba(15, 23, 42, 0.2);
    }
    .kpi-value {
        font-size: 2rem;
        font-weight: 700;
    }
    .small-muted {
        color: #94a3b8;
        font-size: 0.82rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data
def load_dashboard_data(file_path: str = str(DATA_PATH)):
    df = load_dataset(file_path)
    model, preprocessor = ensure_model_artifacts(file_path)
    predictions = predict_dataset(model, preprocessor, file_path)
    return df, model, preprocessor, predictions


def render_security_overview(df: pd.DataFrame, predictions: pd.DataFrame):
    label_counts = df["label"].value_counts().reindex(["Benign", "Suspicious", "Malicious"], fill_value=0)
    suspicious_ratio = (label_counts["Malicious"] + label_counts["Suspicious"]) / len(df) * 100
    avg_confidence = predictions["confidence"].mean() * 100
    highest_risk = df.loc[df["risk_score"].idxmax(), ["src_ip", "dst_ip", "risk_score", "label"]]

    c1, c2, c3, c4, c5 = st.columns(5)
    metrics = [
        ("TOTAL CONNECTIONS", len(df), "Live network flow count"),
        ("BENIGN TRAFFIC", int(label_counts["Benign"]), "Normal behaviour"),
        ("SUSPICIOUS", int(label_counts["Suspicious"]), "Needs investigation"),
        ("MALICIOUS", int(label_counts["Malicious"]), "Confirmed attacks"),
        ("THREAT INDEX", f"{suspicious_ratio:.1f}%", "Risk ratio"),
    ]

    for col, metric in zip((c1, c2, c3, c4, c5), metrics):
        title, value, subtitle = metric
        with col:
            st.markdown(f"<div class='small-muted'>{title}</div>", unsafe_allow_html=True)
            st.markdown(f"<div class='kpi-value'>{value}</div>", unsafe_allow_html=True)
            st.caption(subtitle)

    st.markdown("---")
    left, right = st.columns([1.8, 1.2])
    with left:
        fig = px.pie(
            df,
            names="label",
            values=df.index,
            title="Traffic Composition",
            color="label",
            color_discrete_map={
                "Benign": "#22c55e",
                "Suspicious": "#f59e0b",
                "Malicious": "#ef4444",
            },
        )
        fig.update_traces(textinfo="percent+label")
        st.plotly_chart(fig, width="stretch")

    with right:
        severity_counts = predictions["predicted_label"].value_counts().reindex(["Benign", "Suspicious", "Malicious"], fill_value=0)
        st.subheader("Security Status")
        status_map = {
            "Benign": ("Healthy", "#22c55e"),
            "Suspicious": ("Investigate", "#f59e0b"),
            "Malicious": ("Critical", "#ef4444"),
        }
        for label in ["Benign", "Suspicious", "Malicious"]:
            text, color = status_map[label]
            value = int(severity_counts[label])
            st.markdown(
                f"<div style='display:flex; justify-content:space-between; margin-bottom: 0.5rem;'><span>{text}</span><span style='color:{color}; font-weight:700;'>{value}</span></div>",
                unsafe_allow_html=True,
            )
        st.progress(min(1.0, suspicious_ratio / 100.0))
        st.caption(f"Mean model confidence: {avg_confidence:.1f}%")
        st.caption(f"Peak risk flow: {highest_risk['src_ip']} -> {highest_risk['dst_ip']} ({int(highest_risk['risk_score'])})")

    st.markdown("---")
    st.subheader("Operational Intelligence")
    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.plotly_chart(build_protocol_chart(df), width="stretch")
    with chart_col2:
        st.plotly_chart(build_attack_distribution(df), width="stretch")

    st.markdown("---")
    risk_timeline = df.groupby("label").agg(count=("label", "size"), risk_mean=("risk_score", "mean")).reset_index()
    st.plotly_chart(
        px.bar(
            risk_timeline,
            x="label",
            y="count",
            color="label",
            title="Risk by Label",
            color_discrete_map={
                "Benign": "#22c55e",
                "Suspicious": "#f59e0b",
                "Malicious": "#ef4444",
            },
        ),
        width="stretch",
    )


def render_traffic_analysis(df: pd.DataFrame):
    st.subheader("Traffic Analysis")
    left, right = st.columns(2)
    with left:
        st.plotly_chart(build_flow_scatter(df), width="stretch")
    with right:
        st.plotly_chart(build_port_activity(df), width="stretch")

    st.markdown("---")
    st.subheader("Flow Summary")
    numeric_summary = df[["duration_ms", "packets", "bytes_in", "bytes_out", "flow_rate", "risk_score"]].describe().T
    st.dataframe(numeric_summary, width="stretch")


def render_intrusion_detection(df: pd.DataFrame, model, preprocessor, source_path: str = str(DATA_PATH)):
    st.subheader("Intrusion Detection")
    predictions = predict_dataframe(model, preprocessor, df)
    prediction_summary = predictions["predicted_label"].value_counts().reindex(["Benign", "Suspicious", "Malicious"], fill_value=0)

    total_predictions = predictions["predicted_label"].count()
    st.metric("Model Prediction Coverage", total_predictions)

    st.dataframe(
        predictions[["src_ip", "dst_ip", "protocol", "attack_type", "predicted_label", "confidence"]].sort_values("confidence", ascending=False).head(25),
        width="stretch",
    )

    st.markdown("---")
    c1, c2, c3 = st.columns(3)
    for col, label in zip((c1, c2, c3), ["Benign", "Suspicious", "Malicious"]):
        count = int(prediction_summary[label])
        with col:
            st.markdown(f"<div class='small-muted'>{label}</div>", unsafe_allow_html=True)
            st.markdown(f"<div class='kpi-value'>{count}</div>", unsafe_allow_html=True)


def render_threat_intelligence(df: pd.DataFrame):
    st.subheader("Threat Intelligence")
    top_sources = df[df["label"] != "Benign"]["src_ip"].value_counts().head(10).reset_index()
    top_sources.columns = ["source_ip", "events"]
    st.plotly_chart(px.bar(top_sources, x="source_ip", y="events", title="Most Active Suspicious Sources"), width="stretch")

    attack_breakdown = df.groupby(["attack_type", "label"]).size().reset_index(name="count")
    st.dataframe(attack_breakdown, width="stretch")


def render_model_page(df: pd.DataFrame, model, preprocessor, source_path: str = str(DATA_PATH)):
    st.subheader("Model Performance")
    from src.train_model import evaluate_model

    metrics = evaluate_model(source_path)
    for key in ["accuracy", "precision", "recall", "f1"]:
        st.metric(key.upper(), round(float(metrics[key]), 4))

    st.text_area("Classification Report", metrics["classification_report"], height=250)

    transformed_feature_names = preprocessor.get_feature_names_out()
    feature_importance = pd.DataFrame(
        {
            "feature": transformed_feature_names,
            "importance": model.feature_importances_,
        }
    ).sort_values("importance", ascending=False)
    st.dataframe(feature_importance.head(15), width="stretch")


def render_dataset_eda(df: pd.DataFrame):
    st.subheader("Dataset Overview")
    overview = describe_dataset(df)
    for key, value in overview.items():
        st.caption(f"{key}: {value}")

    st.dataframe(df.head(100), width="stretch")

    st.markdown("---")
    st.subheader("Flow Features")
    st.dataframe(df[["protocol", "duration_ms", "packets", "bytes_in", "bytes_out", "risk_score", "label"]].head(30), width="stretch")


def main():
    st.sidebar.title("Controls")
    uploaded_file = st.sidebar.file_uploader("Upload traffic CSV", type=["csv"], help="Use your own network traffic dataset if available.")

    source_path = str(DATA_PATH)
    if uploaded_file is not None:
        uploaded_df = pd.read_csv(uploaded_file)
        if "label" not in uploaded_df.columns:
            st.sidebar.warning("The uploaded file must include a 'label' column to run intrusion detection.")
            df, model, preprocessor, predictions = load_dashboard_data(source_path)
        else:
            source_path = str(DATA_PATH)
            df = uploaded_df
            model, preprocessor = ensure_model_artifacts(source_path)
            predictions = predict_dataframe(model, preprocessor, df)
            st.sidebar.success(f"Loaded {len(df)} rows from your uploaded dataset.")
    else:
        df, model, preprocessor, predictions = load_dashboard_data(source_path)

    pages = [
        "Security Overview",
        "Traffic Analysis",
        "Intrusion Detection",
        "Threat Intelligence",
        "ML Model",
        "Dataset / EDA",
    ]

    page = st.sidebar.radio("Navigation", pages)

    if page == "Security Overview":
        render_security_overview(df, predictions)
    elif page == "Traffic Analysis":
        render_traffic_analysis(df)
    elif page == "Intrusion Detection":
        render_intrusion_detection(df, model, preprocessor, source_path)
    elif page == "Threat Intelligence":
        render_threat_intelligence(df)
    elif page == "ML Model":
        render_model_page(df, model, preprocessor, source_path)
    else:
        render_dataset_eda(df)

    st.sidebar.markdown("---")
    st.sidebar.caption("Project: Network Traffic Analyzer + Intrusion Detection Dashboard")


if __name__ == "__main__":
    main()
