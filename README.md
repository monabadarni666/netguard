<img width="2880" height="1617" alt="image" src="https://github.com/user-attachments/assets/82e0d40d-fb69-4e17-b768-54320ba36d0a" /># NetGuard

### AI-Powered Real-Time Network Anomaly Detection Platform

NetGuard is an end-to-end cybersecurity platform for real-time network monitoring and anomaly detection.

It captures live network traffic, converts packets into bidirectional flows, extracts network-flow features, analyzes traffic using machine learning, stores security events in PostgreSQL, and visualizes activity through a real-time React dashboard.

---

## Dashboard

> A screenshot of the live dashboard will be added here.
<img width="1440" height="809" alt="צילום מסך 2026-10-12 ב-17 47 25" src="https://github.com/user-attachments/assets/8ce64b55-930c-4dd3-9b0b-65352e1a74e3" />


---

## Overview

NetGuard was developed as a complete machine-learning cybersecurity system.

The project started with a supervised intrusion-detection model trained on the **UNSW-NB15** cybersecurity dataset using a Random Forest classifier.

When the model was connected to real network traffic captured with Scapy, the live traffic distributions were significantly different from the dataset distributions.

This exposed an important real-world machine-learning problem:

**Domain Shift**

Instead of forcing the original classifier to operate on incompatible live traffic, the live architecture was redesigned around anomaly detection.

The final live engine uses a **One-Class SVM** trained on normal traffic collected directly from the monitored endpoint.

---

## Architecture

```text
                         NetGuard
                            |
              +-------------+-------------+
              |                           |
              |                           |
       Offline IDS Pipeline        Live Monitoring Pipeline
              |                           |
              v                           v
        UNSW-NB15 Dataset          Real Network Traffic
              |                           |
              v                           v
         Preprocessing              Scapy Capture
              |                           |
              v                           v
      Random Forest Model       Bidirectional Flow Builder
              |                           |
              v                           v
        POST /predict             11 Live Flow Features
                                          |
                                          v
                                 POST /predict/live
                                          |
                                          v
                                   One-Class SVM V3
                                          |
                         +----------------+----------------+
                         |                                 |
                         v                                 v
                    PostgreSQL                       Risk Engine
                         |
                         v
                   React Dashboard
```

---

## Main Features

- Real-time packet capture
- Bidirectional flow aggregation
- Local-to-remote flow normalization
- TCP and UDP traffic monitoring
- Machine-learning anomaly detection
- Risk-score calculation
- Severity classification
- PostgreSQL event storage
- FastAPI REST API
- Real-time React dashboard
- Protocol analytics
- Severity analytics
- Recent anomaly alerts
- Automatic dashboard refresh

---

## Technology Stack

### Machine Learning

- Python
- pandas
- NumPy
- scikit-learn
- Random Forest
- One-Class SVM
- Isolation Forest
- Local Outlier Factor
- joblib
- Jupyter Notebook

### Network Monitoring

- Scapy
- TCP / UDP packet capture
- Bidirectional flow aggregation
- Real-time feature extraction

### Backend

- FastAPI
- Uvicorn
- SQLAlchemy
- PostgreSQL
- psycopg

### Frontend

- React
- TypeScript
- Vite
- Recharts
- CSS

---

# Machine Learning Development

## Phase 1 — UNSW-NB15 Intrusion Detection

The first NetGuard model was trained on the UNSW-NB15 cybersecurity dataset.

The supervised model uses:

- 42 input features
- One-hot encoding for categorical variables
- Random Forest classification
- A custom classification threshold

Selected classification threshold:

```text
0.55
```

Observed test performance:

```text
Accuracy:      87.11%
Attack Recall: 98.59%
```

Confusion matrix:

```text
[[27030,  9970],
 [  640, 44692]]
```

The supervised dataset model remains available through:

```text
POST /predict
```

---

# Real-World Traffic Challenge

The UNSW-NB15 model performed well on the dataset, but applying it directly to real Scapy traffic produced a large number of alerts during ordinary network use.

The reason was that the statistics and semantics of features generated from real packet capture did not perfectly match those in UNSW-NB15.

Several experiments were performed:

- 11-feature live Random Forest
- Reduced feature sets
- Direction-normalized flows
- Direction-invariant feature engineering
- Classification-threshold tuning
- Isolation Forest
- Local Outlier Factor
- One-Class SVM

Threshold tuning reduced alerts only by sacrificing attack recall, which showed that threshold adjustment alone was not enough to solve the problem.

The project therefore moved to anomaly detection for live traffic.

---

# Live Model V3

The final live-monitoring engine uses:

```text
Algorithm:              One-Class SVM
Kernel:                 RBF
nu:                     0.03
Calibration Percentile: 97.5%
Anomaly Threshold:      -1.2725288809245112
```

The model learns normal network behavior from real traffic captured from the monitored endpoint.

New flows are compared against this learned baseline.

Flows that deviate sufficiently from normal behavior are classified as anomalies.

---

## Live Features

The V3 model uses 11 features that can be directly calculated from live network traffic:

| Feature | Description |
|---|---|
| `dur` | Flow duration |
| `proto` | Transport protocol |
| `spkts` | Packets sent by the local endpoint |
| `dpkts` | Packets received |
| `sbytes` | Bytes sent |
| `dbytes` | Bytes received |
| `rate` | Packets per second |
| `sinpkt` | Average outbound inter-packet interval |
| `dinpkt` | Average inbound inter-packet interval |
| `smean` | Average outbound packet size |
| `dmean` | Average inbound packet size |

The collector normalizes every flow so that the monitored local machine is always treated as the source.

---

# Model Evaluation

## Real Normal-Traffic Baseline

A real-time validation run produced:

```text
Total flows:         143
Normal:              142
Anomalies:             1
Baseline alert rate: 0.7%
```

A later clean monitoring session after resetting the database produced:

```text
Total events:        145
Normal traffic:      145
Detected anomalies:   0
Critical alerts:       0
Average risk:        1.57
```

These results describe behavior on normal traffic.

They should **not** be interpreted as formal cyberattack-detection accuracy or false-positive rate because the flows were collected as an operational normal baseline rather than a manually labeled evaluation dataset.

---

## Synthetic Anomaly Stress Tests

Synthetic feature perturbations were used to test whether the anomaly detector responds to unusual network behavior.

At the selected 97.5th-percentile threshold:

| Scenario | Alert Rate |
|---|---:|
| Real normal baseline | 2% |
| High-rate burst | 61% |
| Outbound data spike | 85% |
| Packet-flood-like behavior | 65% |

These are synthetic anomaly stress tests.

They are not measured detection rates for real cyberattacks.

---

# Live Traffic Collector

The collector performs the following pipeline:

```text
Packet Capture
      |
      v
Bidirectional Flow Aggregation
      |
      v
Direction Normalization
      |
      v
Feature Extraction
      |
      v
Flow Filtering
      |
      v
FastAPI
      |
      v
One-Class SVM V3
      |
      v
PostgreSQL + CSV
```

Very short or meaningless flows are filtered before being sent to the AI engine.

The collector currently monitors TCP and UDP traffic.

---

# FastAPI Backend

Start the backend:

```bash
cd ~/ai-cybersecurity-platform
source .venv/bin/activate

uvicorn backend.main:app --reload
```

Interactive API documentation:

```text
http://127.0.0.1:8000/docs
```

## API Endpoints

```text
GET  /
GET  /health

GET  /features
GET  /features/live

POST /predict
POST /predict/live

GET  /events
GET  /alerts
GET  /statistics

GET  /analytics/severity
GET  /analytics/protocols
```

### `/predict`

Uses the supervised Random Forest model trained on UNSW-NB15.

### `/predict/live`

Uses the One-Class SVM V3 anomaly-detection model for real network traffic.

---

# PostgreSQL

NetGuard stores analyzed network events in PostgreSQL.

The current event schema contains:

```text
id
timestamp
prediction
risk_score
severity
protocol
service
state
duration
source_bytes
destination_bytes
is_anomaly
anomaly_score
anomaly_threshold
detection_source
```

Live V3 events are stored with:

```text
detection_source = LIVE_ANOMALY_V3
```

Example:

```text
prediction        = NORMAL
is_anomaly        = false
anomaly_score     = -1.89
anomaly_threshold = -1.2725
detection_source  = LIVE_ANOMALY_V3
```

---

# Risk Score

One-Class SVM does not produce an attack probability.

NetGuard therefore converts the anomaly score into a normalized risk value between:

```text
0 - 100
```

The configured anomaly threshold maps approximately to the middle of the risk scale.

The risk score should be interpreted as an **anomaly-risk indicator**, not as the probability that traffic is malicious.

---

# Dashboard

NetGuard includes a real-time React dashboard.

It displays:

- Total network events
- Normal traffic
- Detected anomalies
- Critical alerts
- Average anomaly risk
- Normal vs anomaly distribution
- Severity distribution
- Protocol distribution
- Recent anomaly alerts
- Recent network events
- Live AI engine information
- Detection threshold information
- System status

The dashboard automatically refreshes every 5 seconds.

Start the frontend:

```bash
cd ~/ai-cybersecurity-platform/frontend
npm run dev
```

Open:

```text
http://localhost:5173
```

---

# Running NetGuard

NetGuard normally runs using three processes.

## Terminal 1 — Backend

```bash
cd ~/ai-cybersecurity-platform

source .venv/bin/activate

uvicorn backend.main:app --reload
```

## Terminal 2 — Frontend

```bash
cd ~/ai-cybersecurity-platform/frontend

npm run dev
```

## Terminal 3 — Live Network Collector

```bash
cd ~/ai-cybersecurity-platform

source .venv/bin/activate

sudo env HOME=/var/root .venv/bin/python collector/flow_aggregator.py
```

---

# Installation

Clone the repository:

```bash
git clone https://github.com/monabadarni666/netguard.git

cd netguard
```

Create a virtual environment:

```bash
python3 -m venv .venv

source .venv/bin/activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Install frontend dependencies:

```bash
cd frontend

npm install
```

PostgreSQL is also required.

The database used during development was:

```text
ai_cybersecurity
```

---

# Project Structure

```text
netguard/
│
├── backend/
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   ├── init_db.py
│   ├── test_prediction.py
│   └── test_batch.py
│
├── collector/
│   ├── flow_aggregator.py
│   ├── live_capture.py
│   └── replay_traffic.py
│
├── frontend/
│   └── src/
│       ├── App.tsx
│       └── App.css
│
├── ml/
│   ├── data/
│   ├── models/
│   ├── notebooks/
│   └── src/
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

# Privacy and Repository Safety

Raw network-traffic data is excluded from Git.

The repository `.gitignore` excludes:

```text
ml/data/*
.venv/
frontend/node_modules/
*.joblib
.env
```

This prevents local datasets, virtual environments, model binaries, environment files, and other large or sensitive local artifacts from being committed.

---

# Limitations

NetGuard is a portfolio and educational cybersecurity project, not a production intrusion-detection system.

Current limitations include:

- The live model learns baseline behavior from one monitored endpoint.
- Normal behavior can differ between devices and networks.
- Network behavior can change over time.
- An anomaly does not necessarily represent malicious activity.
- A normal prediction does not guarantee that network traffic is safe.
- Synthetic anomaly tests are not equivalent to real attack validation.
- The risk score is not an attack probability.
- The live model binary must currently be generated locally.

---

# Future Improvements

Potential future extensions include:

- Controlled cybersecurity-lab validation
- Real labeled attack-traffic evaluation
- Adaptive network baselines
- Automated model retraining
- Explainable anomaly detection
- Automated tests
- Authentication
- Alert notifications
- Docker support
- CI/CD
- Cloud deployment
- Threat-intelligence integration
- IP and service enrichment
- Model-version tracking

---

# What This Project Demonstrates

NetGuard demonstrates practical experience with:

- Machine learning
- Cybersecurity
- Network traffic analysis
- Anomaly detection
- Domain-shift analysis
- Real-time data processing
- FastAPI
- REST APIs
- PostgreSQL
- SQLAlchemy
- React
- TypeScript
- Data visualization
- Full-stack development
- End-to-end ML system integration

---

## Author

**Mona Badarni**

B.Sc. Computer Science & Software Engineering Graduate

GitHub: [monabadarni666](https://github.com/monabadarni666)
