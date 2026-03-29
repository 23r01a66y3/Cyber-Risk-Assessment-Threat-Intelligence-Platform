import streamlit as st
import pandas as pd
from scanner import scan_website
from email_alert import send_alert

st.title("Web Vulnerability Scanner")

url = st.text_input("Enter Website URL")

if st.button("Scan"):
    results = scan_website(url)

    if not results:
        st.success("No vulnerabilities found")
    else:
        df = pd.DataFrame(results)

        st.subheader("Scan Results")
        st.dataframe(df)

        st.subheader("Severity Distribution")
        st.bar_chart(df["severity"].value_counts())

        risk_score = df["score"].mean()
        st.subheader(f"Overall Risk Score: {round(risk_score,2)}")

        send_alert("your_email@gmail.com", results, url)
