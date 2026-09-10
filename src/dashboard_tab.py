import streamlit as st
import plotly.express as px
import pandas as pd
from src.quantum_risk import QuantumRiskEngine, AddressTarget
from src.report_generator import ForensicReportGenerator

def render_quantum_risk_tab():
    st.header("⚡ Quantum Risk & Forensic Threat Evaluator")
    st.markdown("Assess cryptographic decay (HNDL) and runtime anomaly vectors across EVM addresses.")

    col1, col2 = st.columns([1, 2])

    with col1:
        st.subheader("Target Configuration")
        address = st.text_input("EVM Target Address", "0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
        value_usd = st.number_input("Secured Capital ($ USD)", min_value=0.0, value=1500000.0, step=50000.0)
        pubkey_exposed = st.checkbox("Public Key Exposed On-Chain", value=True)
        
        st.subheader("Model Inputs")
        gat_score = st.slider("GAT Spatial Anomaly Score", 0.0, 1.0, 0.65)
        trace_score = st.slider("EVM Trace Anomaly Score", 0.0, 1.0, 0.82)
        crqc_year = st.slider("Projected CRQC Year", 2028, 2040, 2033)

        # Calculate metrics
        engine = QuantumRiskEngine(target_crqc_year=crqc_year)
        target = AddressTarget(address, value_usd, pubkey_exposed, gat_score, trace_score)
        result = engine.evaluate_target(target)

    with col2:
        st.subheader("Risk Decomposition")
        
        # Radar Visualization
        radar_df = pd.DataFrame(dict(
            r=[result['hndl_score'], result['gat_score'], result['trace_score'], result['composite_score']],
            theta=['HNDL Index', 'GAT Spatial', 'EVM Trace', 'Composite Score']
        ))
        fig = px.line_polar(radar_df, r='r', theta='theta', line_close=True, range_r=[0, 100])
        fig.update_traces(fill='toself')
        st.plotly_chart(fig, use_container_width=True)

        # Metric Displays
        m1, m2, m3 = st.columns(3)
        m1.metric("Composite Threat", f"{result['composite_score']}/100", result['risk_tier'])
        m2.metric("HNDL Index", f"{result['hndl_score']}/100")
        m3.metric("PQC Action", "MIGRATE" if result['pqc_migration_required'] else "SAFE")

        # Report Export Section
        md_report = ForensicReportGenerator.generate_markdown(result)
        st.subheader("Audit Report Preview")
        st.text_area("Markdown Summary", md_report, height=180)
        st.download_button(
            label="Download Security Report (.md)",
            data=md_report,
            file_name=f"quantumwatch_audit_{address[:8]}.md",
            mime="text/markdown"
        )