from flask import Flask, render_template, request, send_file
from database.db import init_db
from database.operations import insert_result, fetch_results

from scanner.port_scanner import scan_ports
from scanner.vulnerability_scanner import detect_vulnerabilities
from risk.risk_engine import calculate_risk

from threat_intel.virustotal_api import get_virustotal_data
from reports.pdf_report import generate_pdf

from config import HIGH_RISK_THRESHOLD

app = Flask(__name__)
init_db()

# 🔹 MAIN DASHBOARD
@app.route("/", methods=["GET", "POST"])
def index():
    alert = None
    threat_data = None

    if request.method == "POST":
        target = request.form["target"]

        ports = scan_ports(target)
        vulns = detect_vulnerabilities(ports)
        risks = calculate_risk(vulns)

        for r in risks:
            insert_result(r["port"], r["issue"], r["risk_score"])

            if r["risk_score"] >= HIGH_RISK_THRESHOLD:
                alert = "⚠ HIGH RISK DETECTED!"

        # 🔹 VirusTotal
        try:
            threat_data = get_virustotal_data(target)
            # ensure keys always exist
            if "error" not in threat_data:
                threat_data = get_virustotal_data(target)
                threat_data.setdefault("malicious", 0)
                threat_data.setdefault("country", "N/A")
                threat_data.setdefault("isp", "N/A")
        except Exception as e:
            threat_data = {"error": str(e)}

    # 🔥 FETCH DATA
    data = fetch_results()

    # ✅ REMOVE DUPLICATE PORTS (FIX)
    unique = {}
    for r in data:
        port = r[1]
        if port not in unique:
            unique[port] = r

    clean_data = list(unique.values())

    # 🔹 PREPARE CHART DATA
    ports = [r[1] for r in clean_data]
    scores = [r[3] for r in clean_data]

    return render_template(
        "index.html",
        data=clean_data,
        ports=ports,
        scores=scores,
        alert=alert,
        threat=threat_data
    )


# 🔹 HISTORY PAGE (UNCHANGED)
@app.route("/history")
def history():
    data = fetch_results()

    ports = [r[1] for r in data]
    scores = [r[3] for r in data]

    return render_template(
        "history.html",
        data=data,
        ports=ports,
        scores=scores
    )


# 🔹 PDF EXPORT
@app.route("/report")
def report():
    data = fetch_results()
    pdf = generate_pdf(data)
    return send_file(pdf, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)