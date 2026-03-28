import streamlit as st
import pandas as pd
import plotly.express as px
import time
import os
from scanner.port_scanner import scan_ports
from scanner.vulnerability_scanner import detect_vulnerabilities
from risk.risk_engine import calculate_risk
from threat_intel.threat_api import get_threat_data
from reports.pdf_report import generate_pdf
import threat_intel.threat_api as ta
# 🔹 PAGE CONFIG FOR DARK/WIDE THEME LIKE CYBERSCAN PRO
st.set_page_config(page_title="CyberScan Pro", page_icon="🛡️", layout="wide")
# 🔹 CUSTOM CSS TO MATCH IMAGE EXACTLY (OPTIONAL FINE-TUNING)
st.markdown("""
<style>
    /* Styling to match the screenshot vibe */
    .stButton>button { border-radius: 8px; }
    .stMetric { background-color: rgba(255,255,255,0.05); padding: 15px; border-radius: 10px; }
</style>
""", unsafe_allow_html=True)
# 🔹 SIDEBAR CONFIGURATION
st.sidebar.title("⚙️ Configuration")
vt_api_key = st.sidebar.text_input("VirusTotal API Key", type="password", placeholder="Paste your API key here")
if not vt_api_key:
    st.sidebar.warning("No API key found", icon="⚠️")
else:
    st.sidebar.success("API key loaded", icon="✅")
st.sidebar.markdown("---")
st.sidebar.subheader("📧 Email Alerts")
gmail_user = st.sidebar.text_input("Gmail Address", placeholder="you@gmail.com")
gmail_pass = st.sidebar.text_input("App Password", type="password", placeholder="16-digit app password")
alert_to = st.sidebar.text_input("Send Alert To", placeholder="admin@company.com")
st.sidebar.markdown("---")
st.sidebar.title("🎯 Scan Targets")
st.sidebar.caption("One target per line")
default_targets = "testasp.vulnweb.com\ntestphp.vulnweb.com\nzero.webappsecurity.com"
targets_input = st.sidebar.text_area("Targets input", default_targets, height=120, label_visibility="collapsed")
targets = [t.strip() for t in targets_input.split("\n") if t.strip()]
st.sidebar.caption(f"{len(targets)} target(s) configured")
# Button
run_scan = st.sidebar.button("🚀 Run Full Scan", use_container_width=True, type="primary")
# 🔹 MAIN PANEL
st.title("🛡️ CyberScan Pro")
st.caption("Professional Network Reconnaissance & Threat Intelligence Dashboard")
# Initialize Session State
if 'scan_data' not in st.session_state:
    st.session_state.scan_data = [] 
    st.session_state.threat_data = {}
if run_scan:
    if not targets:
        st.error("Please configure at least one target.")
    else:
        st.session_state.scan_data = [] 
        st.session_state.threat_data = {}
        
        # Patch VT API key so the backend uses what user typed in
        if vt_api_key:
            ta.API_KEY = vt_api_key
        with st.spinner("Running full scan..."):
            for t in targets:
                try:
                    ports = scan_ports(t)
                    if ports:
                        vulns = detect_vulnerabilities(ports)
                        risks = calculate_risk(vulns)
                        for r in risks:
                            st.session_state.scan_data.append({
                                "Target": t,
                                "Port": r["port"],
                                "Issue": r["issue"],
                                "Risk Score": r["risk_score"]
                            })
                    else:
                        st.session_state.scan_data.append({
                            "Target": t, "Port": "-", "Issue": "No Open Ports", "Risk Score": 0
                        })
                    # Threat Intel
                    if vt_api_key:
                        t_data = get_threat_data(t)
                        st.session_state.threat_data[t] = t_data
                except Exception as e:
                    st.error(f"Error scanning {t}: {str(e)}")
# Determine what data to show (Sample vs Actual)
if not st.session_state.scan_data and not run_scan:
    st.info("No scan run yet — showing sample data. Configure targets and click Run Full Scan.")
    # Sample Data to match screenshot
    data = [
        {"Target": "192.168.1.3", "Port": 80, "Issue": "http", "Risk Score": 10},
        {"Target": "192.168.1.3", "Port": 8080, "Issue": "http-proxy", "Risk Score": 10},
        {"Target": "192.168.1.3", "Port": 23, "Issue": "telnet", "Risk Score": 10},
        {"Target": "192.168.1.2", "Port": 21, "Issue": "ftp", "Risk Score": 6},
        {"Target": "192.168.1.2", "Port": 443, "Issue": "https", "Risk Score": 6},
        {"Target": "192.168.1.1", "Port": 80, "Issue": "http", "Risk Score": 1},
        {"Target": "192.168.1.1", "Port": 22, "Issue": "ssh", "Risk Score": 1},
    ]
    df = pd.DataFrame(data)
    total_hosts = 3
    open_ports = 7
    unique_services = 6
    max_score = 10
    high_risk = 5
    is_sample = True
else:
    df = pd.DataFrame(st.session_state.scan_data)
    if not df.empty:
        total_hosts = df["Target"].nunique()
        # Count only valid ports
        valid_ports = df[df["Port"] != "-"]
        open_ports = len(valid_ports)
        unique_services = valid_ports["Issue"].nunique()
        max_score = df["Risk Score"].max()
        high_risk = len(df[df["Risk Score"] >= 7])
    else:
        total_hosts = open_ports = unique_services = max_score = high_risk = 0
    is_sample = False
# 🔹 KEY METRICS (Matches Image 5)
st.header("📊 Key Metrics")
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("🖥️ Total Hosts", total_hosts)
col2.metric("🔓 Open Ports", open_ports)
col3.metric("⚙️ Unique Services", unique_services)
col4.metric("💀 Max Risk Score", max_score)
col5.metric("🚨 High Risk Entries", high_risk)
st.markdown("<br>", unsafe_allow_html=True)
# 🔹 TABS TO MATCH IMAGE 5
tab1, tab2, tab3, tab4 = st.tabs(["📑 Scan Data", "📈 Charts", "🚨 Threat Intel", "📥 Export"])
with tab1:
    st.subheader("📋 Scan Results")
    st.caption(f"Showing {len(df)} of {len(df)} rows after filters")
    if not df.empty:
        st.dataframe(df, use_container_width=True)
with tab2:
    if not df.empty:
        st.markdown("### 📈 Interactive Charts")
        st.caption("Hover for details • Drag to zoom • Double-click to reset • Click legend to toggle")
        
        valid_df = df[df["Port"] != "-"]
        
        # Aggregation by Target
        target_stats = df.groupby("Target").agg(
            Open_Ports=("Port", lambda x: sum(x != "-")),
            Total_Risk=("Risk Score", "sum")
        ).reset_index()
        
        # Add VT Malicious data
        vt_scores = []
        for t in target_stats["Target"]:
            malicious = 0
            if "threat_data" in st.session_state and t in st.session_state.threat_data:
                td = st.session_state.threat_data[t]
                if "abuse_score" in td: malicious = td["abuse_score"]
                elif "malicious" in td: malicious = td["malicious"]
            vt_scores.append(malicious)
        target_stats["Malicious Reports"] = vt_scores
        
        # Sample fallback for rich visualizations if no scans happen
        if is_sample:
            target_stats["Malicious Reports"] = [0, 2, 5] if len(target_stats) >= 3 else [1] * len(target_stats)
            
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("##### Open Ports per Host")
            fig1 = px.bar(target_stats, x="Target", y="Open_Ports", color="Open_Ports", 
                          color_continuous_scale="Blues", text="Open_Ports")
            fig1.update_layout(xaxis_title="IP / Host", yaxis_title="Open Ports", margin=dict(l=0, r=0, t=30, b=0))
            st.plotly_chart(fig1, use_container_width=True)
            
        with c2:
            st.markdown("##### Total Risk Score per Host")
            fig2 = px.bar(target_stats, x="Target", y="Total_Risk", color="Total_Risk", 
                          color_continuous_scale="Reds", text="Total_Risk")
            fig2.update_layout(xaxis_title="IP / Host", yaxis_title="Total Risk", margin=dict(l=0, r=0, t=30, b=0))
            st.plotly_chart(fig2, use_container_width=True)
            
        c3, c4 = st.columns(2)
        with c3:
            st.markdown("##### Services Exposed")
            if not valid_df.empty:
                issue_counts = valid_df["Issue"].value_counts().reset_index()
                issue_counts.columns = ["Issue", "Count"]
                fig3 = px.bar(issue_counts, y="Issue", x="Count", color="Issue", orientation="h")
                fig3.update_layout(showlegend=False, xaxis_title="Count", yaxis_title="Issue", margin=dict(l=0, r=0, t=30, b=0))
                st.plotly_chart(fig3, use_container_width=True)
            else:
                st.info("No exposed services.")
            
        with c4:
            st.markdown("##### Severity Distribution")
            if not valid_df.empty:
                sev_df = valid_df.copy()
                def get_sev(s):
                    if s >= 9: return "Critical"
                    if s >= 7: return "High"
                    if s >= 4: return "Medium"
                    return "Low"
                sev_df["Severity"] = sev_df["Risk Score"].apply(get_sev)
                fig4 = px.pie(sev_df, names="Severity", hole=0.3)
                fig4.update_layout(margin=dict(l=0, r=0, t=30, b=0))
                st.plotly_chart(fig4, use_container_width=True)
            else:
                st.info("No severity data.")
            
        st.markdown("---")
        st.markdown("### 🎯 Risk vs Exposure")
        st.caption("Bubble size = VirusTotal malicious reports. Hover each bubble for details.")
        
        bubble_size = target_stats["Malicious Reports"] + 1 # avoid zero size
        fig5 = px.scatter(target_stats, x="Open_Ports", y="Total_Risk", size=bubble_size,
                          color="Total_Risk", color_continuous_scale="RdYlGn_r", text="Target")
        fig5.update_traces(textposition='top center')
        fig5.update_layout(xaxis_title="Open Ports", yaxis_title="Total Risk")
        st.plotly_chart(fig5, use_container_width=True)
        
        st.markdown("---")
        st.markdown("### 🦠 VirusTotal Intelligence")
        st.caption("VirusTotal Detections vs Risk Score per Host")
        melted = target_stats.melt(id_vars=["Target"], value_vars=["Malicious Reports", "Total_Risk"], 
                                   var_name="Metric", value_name="Score")
        fig6 = px.bar(melted, x="Target", y="Score", color="Metric", barmode="group")
        fig6.update_layout(xaxis_title="IP / Host", yaxis_title="Score")
        st.plotly_chart(fig6, use_container_width=True)
with tab3:
    st.subheader("🚨 Threat Intelligence")
    if is_sample:
         st.warning("Showing mock threat intelligence block (No scan run).")
         st.json({
             "ip": "testphp.vulnweb.com",
             "abuse_score": 0,
             "country": "US",
             "isp": "Acme Hosting Inc."
         })
    else:
        if not vt_api_key:
            st.error("VirusTotal API Key missing. Configure in sidebar to see Threat Intel.")
        elif not st.session_state.threat_data:
            st.info("No threat data available.")
        else:
            for t, info in st.session_state.threat_data.items():
                st.write(f"**Target: {t}**")
                if "error" in info:
                    if "401" in info["error"]:
                        st.error(f"Authentication Error: Invalid VT API Key for {t}")
                    else:
                        st.error(info["error"])
                else:
                     st.json(info)
                     
    st.markdown("---")
    st.markdown("### 🔍 Per-Host Risk Breakdown")
    
    breakdown_data = []
    
    valid_df = df[df["Port"] != "-"] if not df.empty else pd.DataFrame()
    targets_list = df['Target'].unique() if not df.empty else []
    
    for t in targets_list:
        host_df = df[df['Target'] == t]
        valid_host_df = valid_df[valid_df['Target'] == t] if not valid_df.empty else pd.DataFrame()
        
        total_ports = len(valid_host_df)
        high_risk_ports = len(valid_host_df[valid_host_df['Risk Score'] >= 6]) if not valid_host_df.empty else 0
        max_risk = host_df['Risk Score'].max() if not host_df.empty else 0
        
        vt_reports = 0
        if is_sample:
            if '1.3' in t: vt_reports = 5
            elif '1.2' in t: vt_reports = 2
            elif '1.1' in t: vt_reports = 0
        else:
            if "threat_data" in st.session_state and t in st.session_state.threat_data:
                td = st.session_state.threat_data[t]
                if "abuse_score" in td: vt_reports = td["abuse_score"]
                elif "malicious" in td: vt_reports = td["malicious"]
                
        services = ", ".join(valid_host_df['Issue'].unique()) if not valid_host_df.empty else "-"
        
        breakdown_data.append({
            "IP": t,
            "Total Ports": total_ports,
            "High Risk Ports": high_risk_ports,
            "Max Risk Score": max_risk,
            "Malicious Reports": vt_reports,
            "Services": services
        })
        
    breakdown_df = pd.DataFrame(breakdown_data)
    
    if not breakdown_df.empty:
        st.dataframe(breakdown_df, use_container_width=True, hide_index=True)
    else:
        st.info("No data available for breakdown.")

    st.markdown("<br><br>", unsafe_allow_html=True)
    st.markdown("### 📧 Send Alert Email")
    
    total_hr = breakdown_df["High Risk Ports"].sum() if not breakdown_df.empty else 0
    btn_text = f"🚨 Send Alert Email ({total_hr} high-risk entries)"
    
    if not gmail_user or not gmail_pass or not alert_to:
        st.warning("⚠️ Fill in Your Gmail Address, App Password, and Send Alert To in the sidebar to enable email alerts.")
        st.button(btn_text, disabled=True)
    else:
        if st.button(btn_text):
            if breakdown_df.empty:
                st.error("No data to send!")
            else:
                try:
                    import smtplib
                    from email.mime.text import MIMEText
                    from email.mime.multipart import MIMEMultipart
                    
                    msg = MIMEMultipart()
                    msg['From'] = gmail_user
                    msg['To'] = alert_to
                    msg['Subject'] = "CyberScan Pro: Security Alert - High Risk Entries Detected"
                
                    html = f"""
                    <html>
                      <body style="font-family: Arial, sans-serif;">
                        <h2 style="color: #d9534f;">CyberScan Pro Security Alert</h2>
                        <p>High risk entries have been detected in the latest scan. Please review the per-host breakdown below:</p>
                        {breakdown_df.to_html(index=False, border=1, classes='table table-striped')}
                        <br>
                        <p>Please log in to the dashboard for additional details.</p>
                      </body>
                    </html>
                    """
                    msg.attach(MIMEText(html, 'html'))
                    
                    with st.spinner("Sending email..."):
                        server = smtplib.SMTP('smtp.gmail.com', 587)
                        server.starttls()
                        server.login(gmail_user, gmail_pass)
                        server.sendmail(gmail_user, alert_to, msg.as_string())
                        server.quit()
                    st.success("✅ Alert email sent successfully!")
                except Exception as e:
                    st.error(f"Failed to send email: {str(e)}")

with tab4:
    st.subheader("📥 Export Reports")
    st.write("Generate a PDF compliance report of the current scan data.")
    
    if st.button("Generate PDF Report", type="primary"):
        if not df.empty:
            # Map columns for backend code compat
            pdf_data = []
            for i, row in df.iterrows():
                 pdf_data.append((i, row["Port"], row["Issue"], row["Risk Score"]))
                 
            try:
                with st.spinner("Compiling PDF..."):
                    file_path = generate_pdf(pdf_data)
                    with open(file_path, "rb") as f:
                        btn = st.download_button(
                            label="Download Cyber Risk Report",
                            data=f,
                            file_name="cyber_risk_compliance_report.pdf",
                            mime="application/pdf"
                        )
            except Exception as e:
                st.error(f"Report generation error: {str(e)}")
        else:
            st.warning("No data available to export.")