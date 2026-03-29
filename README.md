# 🛡️ Cyber Risk Assessment & Threat Intelligence Platform

## 📌 Overview

This project is a **Cyber Risk Assessment and Threat Intelligence Platform** built using Python, Flask, and Streamlit. It scans target systems, detects vulnerabilities, assigns risk scores, and integrates external threat intelligence using the VirusTotal API.

The system helps in identifying potential security risks and visualizing them through dashboards.

---

## 🚀 Features

* 🔍 Port Scanning using Nmap
* 🛡️ Vulnerability Detection
* ⚠️ Risk Scoring System
* 🗄️ SQLite Database Storage
* 📊 Data Visualization (Charts & Dashboard)
* 🌐 Threat Intelligence using VirusTotal API
* 📄 Report Generation
* 📧 Email Alerts (Streamlit Dashboard)

---

## 🏗️ Project Structure

```
project/
│
├── app.py
├── config.py
├── database/
│   ├── db.py
│   └── m.py
│
├── scanner/
│   ├── port_scanner.py
│   └── vulnerability_scanner.py
│
├── risk/
│   └── risk_engine.py
│
├── threat_intel/
│   └── threat_api.py
│
├── templates/
│   ├── index.html
│   └── report.html
│
├── static/
│   └── style.css
│
├── streamlit_app.py
└── reports/
```

---

## 🧠 Architecture

```
USER
  ↓
FRONTEND (HTML / Streamlit)
  ↓
BACKEND (Flask)
  ├── Port Scanner
  ├── Vulnerability Scanner
  ├── Risk Engine
  ├── Threat Intelligence API
  ↓
DATABASE (SQLite - cyber_risk.db)
  ↓
FRONTEND (Results + Charts)
```

---

## ⚙️ Technologies Used

* Python
* Flask
* Streamlit
* SQLite
* Nmap
* Chart.js / Plotly
* VirusTotal API

---

## 📂 Modules Description

### 🔹 database/db.py

* Handles database connection
* Creates `scan_results` table

### 🔹 database/m.py

* Inserts and fetches scan results

### 🔹 scanner/port_scanner.py

* Scans open ports using Nmap

### 🔹 scanner/vulnerability_scanner.py

* Maps ports to vulnerabilities

### 🔹 risk/risk_engine.py

* Assigns risk scores

### 🔹 threat_intel/threat_api.py

* Fetches threat intelligence data

### 🔹 app.py

* Main Flask application
* Controls workflow

### 🔹 streamlit_app.py

* Advanced dashboard with charts and alerts

---

## 🗄️ Database

* **Database Name:** `cyber_risk.db`
* **Table:** `scan_results`

| Column     | Description   |
| ---------- | ------------- |
| id         | Primary Key   |
| port       | Port Number   |
| issue      | Vulnerability |
| risk_score | Risk Level    |

---

## ▶️ How to Run

### 1️⃣ Install Requirements

```bash
pip install flask streamlit pandas plotly python-nmap requests
```

### 2️⃣ Run Flask App

```bash
python app.py
```

### 3️⃣ Run Streamlit Dashboard

```bash
streamlit run streamlit_app.py
```

---

## 🧪 Sample Targets

* testasp.vulnweb.com
* testphp.vulnweb.com
* zero.webappsecurity.com

---

## 📊 Output

* Displays open ports and vulnerabilities
* Shows risk scores
* Provides charts and analytics
* Displays threat intelligence (IP, ISP, Country)

---

## ⚠️ Challenges

* Integrating Nmap with Python
* Handling API errors
* Designing dashboard UI
* Managing database operations

---

## 📈 Future Scope

* Add AI-based risk prediction
* Integrate more APIs (Shodan, Nessus)
* Deploy on cloud
* Add authentication system
---

## 📌 Note

* Use valid API key for VirusTotal
* Nmap must be installed in system

---

## 🎯 Conclusion

This project provides a complete solution for **cyber risk detection, analysis, and visualization**, helping users identify vulnerabilities efficiently.

## 👩‍💻 Presented By

**SP Keerthi**

