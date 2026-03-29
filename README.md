Web Vulnerability Scanner
Overview
This project is a simple web vulnerability scanning system that detects common security issues in a given website URL. It includes a scanner, a dashboard for visualization, and an email alert system.

Features
Detects vulnerabilities like:

Missing security headers
Cross-Site Scripting (XSS)
SQL Injection
Open Redirect
Server Information Disclosure
Displays results in an interactive dashboard

Calculates overall risk score

Sends email alerts for High and Critical vulnerabilities

Technologies Used
Python
Streamlit
Requests
Pandas
smtplib (for email alerts)
Setup Instructions
Install Python (3.x)
Install required libraries: py -m pip install requests beautifulsoup4 streamlit pandas
Run the application: streamlit run dashboard.py
Usage
Enter a website URL
Click "Scan"
View vulnerabilities and risk score
Email Alert Setup
Enable 2-Step Verification in Gmail
Generate App Password
Update credentials in email_alert.py
AI Tools Used
ChatGPT was used to assist in code development and understanding concepts.
