import streamlit as st
import os
import json
from rag_engine import ThreatRAG
from PyPDF2 import PdfReader  
import tempfile
import matplotlib.pyplot as plt

# === PAGE CONFIG ===
st.set_page_config(page_title="ThreatScope", layout="centered")

# === TITLE ===
st.markdown("<h1 style='text-align:center;'>🧠 ThreatScope - AI Threat Intelligence Assistant</h1>", unsafe_allow_html=True)
st.markdown("<div style='text-align:center;color:gray;'>Upload threat reports, logs, or query MITRE-based intelligence.</div>", unsafe_allow_html=True)

rag = ThreatRAG()

# === SIDE MENU ===
st.sidebar.title("⚙️ Options")
mode = st.sidebar.radio("Select input mode:", ["Ask Question", "Analyze File"])

# === BUILD INDEX ===
if st.sidebar.button("🔄 Build / Refresh Index"):
    rag.build_index()
    st.sidebar.success("Index successfully rebuilt!")

# === MODEL SELECTION ===
model_choice = st.sidebar.selectbox(
    "Choose a model:",
    ["qwen2.5:0.5b", "llama3.2:1b"],
    index=0,
)

# === SESSION STATE ===
if "history" not in st.session_state:
    st.session_state.history = []

# ==========================================
# MODE 1: Ask Question (Existing RAG)
# ==========================================
if mode == "Ask Question":
    st.subheader("💬 Ask a question about APTs, threat reports, or MITRE tactics")

    st.markdown("<div class='chat-container'>", unsafe_allow_html=True)
    for q, a in st.session_state.history:
        st.markdown(f"<div class='user-bubble'>{q}</div>", unsafe_allow_html=True)
        st.markdown(f"<div class='bot-bubble'>{a}</div>", unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

    query = st.text_input("Ask a new question:", placeholder="e.g., What tools does APT29 use?")
    col1, col2 = st.columns([1, 1])
    with col1:
        send = st.button("Ask")
    with col2:
        clear = st.button("Clear Chat")

    if send:
        if not query.strip():
            st.warning("Please enter a question.")
        else:
            with st.spinner(f"Querying intelligence data using {model_choice}..."):
                answer = rag.query(query, model_choice)
                # Clean markdown fences from answer
                clean_answer = answer.strip()
                if clean_answer.startswith("```"):
                    clean_answer = clean_answer.replace("```json", "").replace("```", "").strip()
                st.session_state.history.append((query, clean_answer))
                st.rerun()

    if clear:
        st.session_state.history.clear()
        st.rerun()

# ==========================================
# 🧾 MODE 2: Analyze File (PDF / Logs)
# ==========================================
else:
    st.subheader("📂 Upload or select a file for cyber analysis")

    option = st.radio("Choose source:", ["Upload file", "Select from data/threat_reports"])
    file_text = ""

    if option == "Upload file":
        uploaded = st.file_uploader("Upload a PDF, TXT, or LOG file", type=["pdf", "txt", "log"])
        if uploaded:
            if uploaded.name.endswith(".pdf"):
                reader = PdfReader(uploaded)
                file_text = "\n".join([page.extract_text() for page in reader.pages if page.extract_text()])
            else:
                file_text = uploaded.read().decode("utf-8")

    elif option == "Select from data/threat_reports":
        files = [f for f in os.listdir("data/threat_reports") if f.endswith((".txt", ".pdf", ".log"))]
        selected = st.selectbox("Select a file:", files)
        if selected:
            path = os.path.join("data/threat_reports", selected)
            if selected.endswith(".pdf"):
                reader = PdfReader(path)
                file_text = "\n".join([page.extract_text() for page in reader.pages if page.extract_text()])
            else:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    file_text = f.read()

    # === Only continue if file was loaded ===
    if file_text:
        st.success("File loaded successfully!")
        st.text_area("File Preview", file_text[:1500], height=250)

        # ===== Mode Selection =====
        st.markdown("### Analysis Settings")
        user_mode = st.radio(
            "Choose analysis mode:",
            ["Auto Detect", "IR (Incident Response)", "Threat Intel", "Hybrid"],
            index=0
        )

        if st.button("Analyze Cyber Threats"):
            with st.spinner("Analyzing file for cyber intelligence..."):
                forced_mode = None if user_mode == "Auto Detect" else user_mode.split()[0]
                result = rag.query(file_text, model_choice, forced_mode)

                # === Clean up the model output (remove markdown fences) ===
                clean_result = result.strip()
                if clean_result.startswith("```"):
                    clean_result = clean_result.replace("```json", "").replace("```", "").strip()

                # === Extract detected mode for UI ===
                try:
                    result_json = json.loads(clean_result)
                    detected_mode = result_json.get("mode", "Unknown")
                except Exception:
                    detected_mode = "Unknown"

                st.markdown(f"**Detected Mode:** `{detected_mode}`")

                # === Color theme ===
                color_map = {
                    "IR": "#ffcccc",
                    "Threat Intel": "#cce5ff",
                    "Hybrid": "#e0ccff",
                    "Unknown": "#f0f0f0"
                }
                bg_color = color_map.get(detected_mode, "#f0f0f0")

                st.markdown(
                    f"<div style='background-color:{bg_color};padding:15px;border-radius:10px;'>"
                    f"<h4> Cyber Analysis Report</h4>"
                    f"<pre style='white-space:pre-wrap;'>{clean_result}</pre></div>",
                    unsafe_allow_html=True
                )

               # === Quick Dashboard ===
try:
    data = json.loads(clean_result)
    metrics = {
        "Internal Hosts": len(data.get("internal_hosts", [])),
        "External IPs": len(data.get("external_ips", [])),
        "IOCs": len(data.get("ioc", [])),
        "MITRE": len(data.get("mitre", []))
    }

    st.markdown("### ThreatScope Dashboard")

    # גרף 1 - פרטים כלליים
    fig1, ax1 = plt.subplots()
    ax1.bar(metrics.keys(), metrics.values(), color="#6c63ff")
    ax1.set_ylabel("Count")
    ax1.set_title("Detected Elements Overview")
    st.pyplot(fig1)

    # גרף 2 - התפלגות חומרה
    severity_count = {"High": 0, "Medium": 0, "Low": 0}
    for section in ["observed_activity", "ioc"]:
        for event in data.get(section, []):
            sev = event.get("severity", "")
            if sev in severity_count:
                severity_count[sev] += 1

    # אם אין מידע על חומרה – נשתמש בערך הכללי
    if data.get("severity") in severity_count:
        severity_count[data["severity"]] += 1

    if any(severity_count.values()):
        st.markdown("### Severity Distribution")
        fig2, ax2 = plt.subplots()
        colors = ["#ff4c4c", "#ffcc00", "#66cc66"]
        ax2.bar(severity_count.keys(), severity_count.values(), color=colors)
        ax2.set_ylabel("Count")
        ax2.set_title("Severity Levels Across Events")
        st.pyplot(fig2)

    # גרף 3 - Timeline (אם יש תאריכים)
    if "observed_activity" in data:
        try:
            import pandas as pd
            events = data["observed_activity"]
            df = pd.DataFrame(events)
            if "date_time" in df.columns:
                df["date_time"] = pd.to_datetime(df["date_time"], errors="coerce")
                df = df.dropna(subset=["date_time"])
                st.markdown("###  Event Timeline")
                fig3, ax3 = plt.subplots()
                ax3.plot(df["date_time"], range(len(df)), marker="o")
                ax3.set_xlabel("Time")
                ax3.set_ylabel("Event Progression")
                ax3.set_title("Attack Timeline")
                st.pyplot(fig3)
        except Exception:
            pass

    st.download_button("⬇️ Download JSON Report", clean_result, file_name="threat_report.json")

except Exception:
    st.info("Dashboard unavailable (no JSON parsed).")
