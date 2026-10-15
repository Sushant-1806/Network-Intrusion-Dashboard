# Network Traffic Analyzer and Intrusion Detection Dashboard

## Project Presentation

Good morning everyone. Today I am presenting my project, **Network Traffic Analyzer and Intrusion Detection Dashboard**.

This is a Python and Streamlit application designed to help a security analyst understand network activity and identify potentially suspicious or malicious connections. The project combines exploratory data analysis, machine learning, and interactive visualizations in one security-operations-center-style dashboard.

The main idea is simple: instead of inspecting thousands of network records manually, we provide a visual summary of the traffic and use a trained machine learning model to classify each connection as **Benign**, **Suspicious**, or **Malicious**.

---

## Problem Statement

Modern networks generate a large amount of traffic every second. Hidden inside that traffic can be port scanning, botnet activity, credential attacks, denial-of-service traffic, malware beaconing, or data exfiltration.

Manual investigation is slow and difficult to scale. This project addresses that problem by:

1. Loading network-flow data from a CSV file.
2. Summarizing the traffic through charts and key metrics.
3. Preprocessing numerical and categorical features.
4. Applying a Random Forest classification model.
5. Displaying predictions, confidence scores, risk information, and attack patterns.

This makes the project useful as an academic demonstration of how machine learning can support network security monitoring.

---

## What the Dashboard Provides

The application is divided into six sections.

### 1. Security Overview

This is the main SOC-style summary page. It shows:

- Total number of network connections.
- Benign, suspicious, and malicious traffic counts.
- Overall threat index.
- Traffic composition.
- Model confidence.
- Highest-risk flow.
- Protocol activity and attack distribution.

This page answers the first question a security analyst usually asks: **“What is the current security situation?”**

### 2. Traffic Analysis

This section explains the behaviour of the network flows using:

- Traffic intensity versus connection duration.
- Top destination ports.
- A statistical summary of durations, packets, bytes, flow rates, and risk scores.

It helps us understand how normal and abnormal traffic differ.

### 3. Intrusion Detection

This section runs the trained model against the dataset and displays:

- Predicted security labels.
- Prediction confidence.
- Source and destination IP addresses.
- Protocol and attack type.
- A table of the highest-confidence predictions.

The three summary cards make it easy to see how many flows the model classified into each category.

### 4. Threat Intelligence

This page focuses on suspicious activity. It identifies:

- The most active suspicious source IP addresses.
- The number of events associated with each source.
- The relationship between attack types and security labels.

This gives an analyst a starting point for investigating repeat offenders.

### 5. ML Model

This page reports the model's:

- Accuracy.
- Precision.
- Recall.
- F1 score.
- Classification report.
- Most important transformed features.

The model uses a Random Forest classifier with 300 trees and balanced class weighting.

### 6. Dataset / EDA

This page provides a direct look at the data. It displays:

- Dataset size.
- Number of columns.
- Missing values.
- Duplicate rows.
- Counts for each security label.
- Sample rows and selected flow features.

It is useful for validating the input data before relying on the predictions.

---

## How the System Works

The project follows this workflow:

```text
CSV traffic data
        |
        v
Data loading and validation
        |
        v
Feature selection
        |
        v
Missing-value handling, scaling, and one-hot encoding
        |
        v
Random Forest classification
        |
        v
Predicted label and confidence score
        |
        v
Streamlit dashboard and Plotly charts
```

The preprocessing pipeline separates numerical and categorical columns:

- Numerical columns are filled using median imputation and standardized.
- Categorical columns are filled using the most frequent value and one-hot encoded.
- Identifying fields such as IP addresses, timestamps, and attack descriptions are excluded from training.

The trained model and preprocessing pipeline are saved in the `models/` directory. On startup, the application loads those artifacts, and it creates them automatically if they are not available.

---

## Dataset

The repository includes a synthetic network-flow dataset at `data/network_traffic.csv`. If the file is missing, the application generates a reproducible dataset with 24,000 records.

The generated traffic contains examples of:

- Benign traffic.
- Suspicious traffic such as port scans, botnets, and credential stuffing.
- Malicious traffic such as DDoS, malware beaconing, and data exfiltration.

Each flow contains fields such as:

- Timestamp.
- Source and destination IP addresses.
- Protocol and ports.
- Duration, packets, and byte counts.
- Packet size and flow rate.
- TCP flags and connection state.
- Failed login count.
- DNS tunnelling indicator.
- Risk score.
- Attack type and ground-truth label.

The dataset is intended for demonstration, learning, and viva presentation purposes. It is not a replacement for production network telemetry.

The dashboard also provides a sidebar option to upload another CSV file. The uploaded data must include a `label` column for intrusion detection to run.

---

## Project Structure

```text
network-intrusion-dashboard/
├── app.py                         # Streamlit interface and page rendering
├── data/
│   └── network_traffic.csv        # Network-flow dataset
├── models/
│   ├── intrusion_model.pkl        # Trained Random Forest model
│   └── preprocessing_pipeline.pkl # Saved feature preprocessing pipeline
├── src/
│   ├── __init__.py
│   ├── data_loader.py             # Dataset loading and synthetic generation
│   ├── preprocessing.py           # Feature selection and transformations
│   ├── eda.py                     # Dataset summaries and Plotly charts
│   ├── train_model.py             # Training, evaluation, and model artifacts
│   ├── intrusion_detector.py      # Predictions and severity mapping
│   └── utils.py                   # Shared formatting helpers
├── requirements.txt               # Python dependencies
├── .gitignore
└── README.md
```

---

## How to Run the Project

### 1. Create a virtual environment

```powershell
python -m venv .venv
```

### 2. Activate it on Windows

```powershell
.venv\Scripts\activate
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Start the dashboard

```powershell
streamlit run app.py
```

Streamlit will print a local URL, usually `http://localhost:8501`. Open that address in a browser to use the dashboard.

---

## Technologies Used

- **Python** for the application and machine learning workflow.
- **Streamlit** for the interactive web dashboard.
- **Pandas and NumPy** for data manipulation.
- **Scikit-learn** for preprocessing, model training, and evaluation.
- **Plotly** for interactive charts.
- **Joblib** for saving and loading the model artifacts.

---

## Project Strengths

The key strengths of this project are:

- It combines data analysis and prediction in one application.
- The interface is designed around a realistic SOC workflow.
- The code is separated into reusable modules.
- The preprocessing pipeline is saved together with the model.
- The application supports both the included dataset and user-uploaded CSV files.
- The dashboard makes technical results easier to understand during a presentation.

---

## Limitations

There are several limitations to keep in mind:

- The included data is synthetic, not collected from a live network.
- The model is evaluated on data it was trained on in the current implementation, so the displayed metrics are demonstration metrics rather than an unbiased production benchmark.
- The dashboard expects a compatible tabular schema when a new CSV is uploaded.
- IP addresses and timestamps are intentionally excluded from model training, even though they remain useful for investigation.
- A real deployment would require streaming data ingestion, model monitoring, access control, and a stronger validation strategy.

---

## Future Scope

The project could be extended by:

- Connecting to live packet or flow sources such as NetFlow, Zeek, or a SIEM.
- Adding time-based streaming and alert notifications.
- Using a held-out test set and cross-validation for more reliable evaluation.
- Adding explainable-AI views for individual predictions.
- Storing analyst feedback and retraining the model with new labelled data.
- Adding authentication, audit logging, and role-based access control.
- Deploying the dashboard to a secured cloud or internal SOC environment.

---

## Conclusion

To conclude, this project demonstrates how machine learning and interactive visualization can work together for network security monitoring. The dashboard turns raw network-flow records into understandable security insights, while the Random Forest model provides an automated first layer of intrusion detection.

Although this is an educational prototype based on synthetic data, it provides a strong foundation for a more advanced security analytics system. It shows the complete journey from data loading and preprocessing to model prediction, evaluation, visualization, and analyst-oriented investigation.
