import streamlit as st
import pandas as pd
import requests

API_URL = "http://localhost:8000"

# -----------------------------------
# Streamlit Login
# -----------------------------------
def login():
    st.title("🔐 Login Required")

    if "token" not in st.session_state:
        st.session_state.token = None

    if st.session_state.token:
        return  # already logged in

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        res = requests.post(f"{API_URL}/login", json={
            "username": username,
            "password": password
        })

        if res.status_code == 200:
            st.session_state.token = res.json()["access_token"]
            st.success("Login successful!")
            st.rerun()
        else:
            st.error("Invalid username or password")

    st.stop()


# ------------------------------
# 1. Require login
# ------------------------------
login()

st.title("🔐 Fortigate Security Dashboard")
st.set_page_config(layout="wide")
# ------------------------------
# Sidebar filters
# ------------------------------
search_text = st.sidebar.text_input("Search (IP, user, URL, etc)")
limit = st.sidebar.slider("Max logs to load", 100, 5000, 1000)
days = st.sidebar.slider("Load last X days", 1, 7, 3)

# ------------------------------
# Fetch logs from FastAPI
# ------------------------------
if st.button("Load Logs"):
    query_payload = {
        "query": search_text or "*",
        "limit": limit,
        "days": days
    }

    res = requests.post(
        f"{API_URL}/es/search",
        json=query_payload,
        headers={"Authorization": f"Bearer {st.session_state.token}"}
    )

    if res.status_code != 200:
        st.error("API error: " + res.text)
        st.stop()

    hits = res.json()["results"]

    records = []
    for hit in hits:
        src = hit["_source"]
        records.append({
            "timestamp": src.get("@timestamp"),
            "src_ip": src.get("srcip") or src.get("remip") or src.get("srcaddr") or src.get("src"),
            "dst_ip": src.get("dstip"),
            "src_port": src.get("srcport"),
            "dst_port": src.get("dstport"),
            "user": src.get("user"),
            "action": src.get("action"),
            "event_type": src.get("type"),
            "msg": src.get("msg"),
            "severity": src.get("severity"),
            "policyid": src.get("policyid"),
        })

    df = pd.DataFrame(records)

    if df.empty:
        st.warning("No logs found.")
        st.stop()

    # ------------------------------
    # Your dashboard stays the same
    # ------------------------------
    st.subheader("🔎 Security Highlights")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Logs", len(df))
    col2.metric("Blocked Traffic", len(df[df["action"] == "deny"]))
    col3.metric("High Severity Events", len(df[df["severity"] == "high"]))
    col4.metric("Unique Source IPs", df["src_ip"].nunique())

    # ... (all your other charts and tables pasted here)

    # ---------------------------------------------------
    # 7. Security Detections
    # ---------------------------------------------------
    st.subheader("🚨 Potential Security Issues")

    findings = []

    # High severity events
    high_sev = df[df["severity"] == "high"]
    if len(high_sev) > 0:
        findings.append(f"🔴 {len(high_sev)} high-severity alerts detected.")

    # Failed attempts
    failed_attempts = df[df["msg"].str.contains("failed", na=False)]
    if len(failed_attempts) > 10:
        findings.append(f"🟠 {len(failed_attempts)} failed authentication attempts detected.")

    # Show detail of failed attempts
    if len(failed_attempts) > 0:
        st.subheader("🟠 Failed Authentication Attempt Details")
        st.dataframe(failed_attempts[[
            "timestamp", "src_ip", "dst_ip", "user", "msg", "severity", "policyid"
        ]], height=300)
        
    # ---------------------------------------------------
    # Failed Attempts Analysis
    # ---------------------------------------------------
    st.subheader("🟠 Failed Authentication Analysis")

    # 1. Count failed attempts per IP
    failed_by_ip = (
        failed_attempts["src_ip"]
        .fillna("Unknown")
        .value_counts()
        .reset_index()
    )
    failed_by_ip.columns = ["src_ip", "failed_count"]

    st.write("### 🌐 Failed Attempts Per Source IP")
    st.dataframe(failed_by_ip)

    # 2. Count failed attempts per user
    failed_by_user = (
        failed_attempts["user"]
        .fillna("Unknown")
        .value_counts()
        .reset_index()
    )
    failed_by_user.columns = ["user", "failed_count"]

    st.write("### 👤 Failed Attempts Per User")
    st.dataframe(failed_by_user)

    # 3. Highlight suspicious IPs (>5 failed attempts)
    suspicious_failed_ips = failed_by_ip[failed_by_ip["failed_count"] > 5]

    st.write("### 🔥 Suspicious IPs with >5 Failed Attempts")
    if suspicious_failed_ips.empty:
        st.success("No suspicious high-volume failed-attempt IPs detected.")
    else:
        st.error("⚠️ Suspicious high failed-attempt IPs detected!")
        st.dataframe(suspicious_failed_ips)

    # IPs with excessive activity
    ip_counts = df["src_ip"].value_counts()
    suspicious_ips = ip_counts[ip_counts > 50]

    if len(suspicious_ips) > 0:
        findings.append(f"🟡 {len(suspicious_ips)} IPs show abnormal traffic volume.")

    # Show results
    if findings:
        for f in findings:
            st.warning(f)
    else:
        st.success("No major issues detected.")
    # IPs with excessive activity (>50 logs)
    ip_counts = df["src_ip"].value_counts()
    suspicious_ips = ip_counts[ip_counts > 50]

    if len(suspicious_ips) > 0:
        findings.append(f"🟡 {len(suspicious_ips)} IPs show abnormal traffic volume.")

        st.subheader("🟡 Suspicious High-Volume Source IPs")
        suspicious_df = pd.DataFrame({
            "src_ip": suspicious_ips.index,
            "event_count": suspicious_ips.values
        })

    st.table(suspicious_df)





    st.subheader("📄 Raw Logs")
    st.dataframe(df, height=400)

    st.info("Dashboard Loaded Successfully.")
