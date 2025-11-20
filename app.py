import streamlit as st

import pandas as pd 

from elasticsearch import Elasticsearch
from datetime import datetime,timedelta

st.set_page_config(page_title="Fortigate Security Dashboard", layout="wide")

# ------------------------------
# 1. Connect to Elasticsearch
# ------------------------------
@st.cache_resource
def es_client():
    return Elasticsearch("http://localhost:9200")

 

es=es_client()


# ------------------------------
# 2. Sidebar Filter UI
# ------------------------------
st.sidebar.title("Filters")

search_text = st.sidebar.text_input("Search (IP, user, URL, etc)")

limit = st.sidebar.slider("Max logs to load", 100, 5000, 1000)
                          
days = st.sidebar.slider("Load last X days of indexes", 1, 7, 3)


# Build index pattern automatically
index_pattern = "fortigate-*"
start_date = datetime.now() - timedelta(days=days)

st.sidebar.write(f"📅 Searching indexes since: **{start_date.date()}**")
st.sidebar.write(f"📦 Index pattern: `{index_pattern}`")


# ---------------------------------------------------
# 3. Build Elasticsearch Query
# ---------------------------------------------------
must_clause = []

if search_text:
    must_clause.append({"query_string": {"query": search_text}})
else:
    must_clause.append({"match_all": {}})

query_body = {
    "size": limit,
    "query": {
        "bool": {
            "must": must_clause,
            "filter": [
                {"range": {"@timestamp": {"gte": start_date.isoformat()}}}
            ]
        }
    },
    "sort": [{"@timestamp": {"order": "desc"}}]
}
# ---------------------------------------------------
# 4. Fetch Logs
# ---------------------------------------------------
st.title("🔐 Fortigate Security Dashboard")

try:
    response = es.search(index=index_pattern, body=query_body)
except Exception as e:
    st.error(f"Elasticsearch error: {e}")
    st.stop()

# ---------------------------------------------------
# 5. Convert Logs to DataFrame
# ---------------------------------------------------
records = []
for hit in response["hits"]["hits"]:
    src = hit["_source"]
    records.append({
        "timestamp": src.get("@timestamp"),
        "src_ip": src.get("srcip"),
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

# ---------------------------------------------------
# 6. Security Insights
# ---------------------------------------------------
st.subheader("🔎 Security Highlights")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Logs", len(df))
col2.metric("Blocked Traffic", len(df[df["action"] == "deny"]))
col3.metric("High Severity Events", len(df[df["severity"] == "high"]))
col4.metric("Unique Source IPs", df["src_ip"].nunique())

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

# ---------------------------------------------------
# 8. Raw Logs Table
# ---------------------------------------------------
st.subheader("📄 Raw Logs")
st.dataframe(df, height=400)

# ---------------------------------------------------
# 9. Charts
# ---------------------------------------------------
st.subheader("📊 Traffic Visualization")

traffic_by_ip = df["src_ip"].value_counts().head(10)
st.bar_chart(traffic_by_ip)

severity_count = df["severity"].value_counts()
st.bar_chart(severity_count)

st.info("Dashboard Loaded Successfully.")
