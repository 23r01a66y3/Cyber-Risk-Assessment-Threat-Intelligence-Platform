import smtplib
from email.mime.text import MIMEText

def send_alert(email, findings, url):

    high_critical = [f for f in findings if f["severity"] in ["High", "Critical"]]

    if not high_critical:
        return

    body = f"""
    <h3>Security Alert</h3>
    <p><b>Target URL:</b> {url}</p>

    <table border="1">
    <tr><th>Name</th><th>Severity</th><th>Score</th></tr>
    """

    for f in high_critical:
        body += f"<tr><td>{f['name']}</td><td>{f['severity']}</td><td>{f['score']}</td></tr>"

    body += "</table>"

    msg = MIMEText(body, "html")
    msg["Subject"] = "High Risk Vulnerability Detected"
    msg["From"] = "your_email@gmail.com"
    msg["To"] = email

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login("your_email@gmail.com", "paid lvfg nqgh uziv")

    server.send_message(msg)
    server.quit()
