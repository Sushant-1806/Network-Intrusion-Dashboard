# Network Traffic Analyzer + Intrusion Detection Dashboard

This project is a polished Python-based cybersecurity dashboard for analyzing network activity and detecting suspicious or malicious traffic using a machine learning model.

## Project Highlights

- Traffic dashboard with SOC-style dark theme
- Exploratory data analysis (EDA) for network datasets
- Feature engineering and preprocessing pipeline
- Machine learning-based intrusion detection
- Interactive charts with Plotly
- Threat analysis and attack breakdowns
- Clean modular Python structure

## Dataset

This project includes a synthetic but realistic network traffic dataset generated on first run if a CSV file is not already present in the `data/` folder.

## Project Structure

```text
network-intrusion-dashboard/
├── app.py
├── data/
│   └── network_traffic.csv
├── models/
│   ├── intrusion_model.pkl
│   └── preprocessing_pipeline.pkl
├── src/
│   ├── __init__.py
│   ├── data_loader.py
│   ├── preprocessing.py
│   ├── eda.py
│   ├── train_model.py
│   ├── intrusion_detector.py
│   └── utils.py
├── requirements.txt
├── .gitignore
├── README.md
└── assets/
```

## Run the project

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Notes

- The generated dataset is suitable for academic demonstration and viva presentations.
- The model is a Random Forest classifier trained on flow-based network traffic metrics.
- The app is intentionally designed to look like a realistic SOC dashboard.
