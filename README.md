🔹 Project Overview

The Cyber Risk Assessment & Threat Intelligence Platform is a Python-based web application designed to identify, analyze, and evaluate cybersecurity risks in real-time. The system integrates vulnerability scanning, port scanning, and threat intelligence APIs to provide actionable insights and generate detailed reports.
The platform follows the concept of a Threat Intelligence Platform (TIP), which collects, analyzes, and correlates threat data from multiple sources to help organizations detect and prevent cyber attacks.

🔹 Key Features
🔍 Port Scanning – Detects open ports using custom scanning logic
🛡️ Vulnerability Detection – Identifies potential system weaknesses
📊 Risk Scoring Engine – Calculates risk levels (Low / Medium / High)
🌐 Threat Intelligence Integration – Uses APIs like VirusTotal
📄 PDF Report Generation – Downloadable security reports
📈 Dashboard Visualization – Displays risks and scan results

🔹 Modules / Files Used
📁 Backend (Core Logic)
app.py → Main Flask application (routing + UI handling)
config.py → Configuration variables (thresholds, API keys)
database/
db.py → Database initialization
operations.py → Insert & fetch scan results
📁 Scanner Modules
port_scanner.py → Scans open ports
vulnerability_scanner.py → Detects vulnerabilities
📁 Risk Analysis
risk_engine.py → Calculates risk score based on:
Open ports
Vulnerabilities
Threat intelligence data
📁 Threat Intelligence
virustotal_api.py → Fetches threat data from VirusTotal
📁 Reports
pdf_report.py → Generates downloadable PDF reports
📁 Frontend
templates/
index.html
login.html
register.html
static/style.css → UI design and styling

🔹 Technologies Used
Backend: Python, Flask
Frontend: HTML, CSS
Database: SQLite
APIs: VirusTotal API
Libraries: FPDF, Requests

🔹 How the System Works
User enters target (IP / domain)
System performs:
Port scanning
Vulnerability analysis
Data is sent to the risk engine
Risk score is calculated
Threat intelligence is fetched from external APIs
Results are stored in database
Dashboard displays results
User can download PDF report

🔹 Future Enhancements
🔔 Real-time alerts
🤖 AI-based risk prediction
🌍 Integration with more threat intelligence sources (Shodan, MISP)
📊 Advanced analytics dashboard

🔹 Conclusion
This project demonstrates how cyber risk assessment and threat intelligence can be automated using modern tools. It helps in proactive detection of threats, improving security posture, and enabling better decision-making in cybersecurity environments.

Presented By
SP Keerthi
