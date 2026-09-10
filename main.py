import streamlit as st
from src.dashboard_tab import render_quantum_risk_tab

st.set_page_config(page_title="QuantumWatch Dashboard", layout="wide")

# Add as a tab or sidebar page option
tab1, tab2 = st.tabs(["Dashboard Overview", "Quantum Risk Evaluator"])

with tab2:
    render_quantum_risk_tab()