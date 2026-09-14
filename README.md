# QuantumWatch

**AI-Augmented Forensics, Multi-Chain Risk Scoring, and Post-Quantum Threat Intelligence**

QuantumWatch is an institutional-grade security framework designed to evaluate cryptographic decay, Harvest Now Decrypt Later (HNDL) exposure, graph anomalies, and regulatory compliance risks across EVM chains (Ethereum Mainnet, Base, Arbitrum).

---

## Core Capabilities

* **Quantum Cryptographic Decay Engine:** Quantifies HNDL vulnerability indices based on public key exposure, time-to-CRQC projections, and secured asset value ($USD$).
* **Live Multi-Chain Data Ingestion:** Queries live RPC endpoints across Ethereum Mainnet, Base, and Arbitrum to track address nonces, ETH balances, and signature exposures.
* **OFAC Sanctions Oracle Screening:** Queries the Chainalysis On-Chain Sanctions Oracle (`0x40C57923924B5c5c5455c48D93317139ADDaC8fb`) via RPC `eth_call` overrides to flag restricted entities.
* **Institutional Forensic Reporting:** Produces structured Markdown security audits and automated Suspicious Activity Report (SAR/STR) intake templates for compliance teams and Financial Intelligence Units (FIUs).
* **Automated Threat Webhook Alerter:** Dispatches real-time structured alert payloads to Slack, Discord, or institutional security operations endpoints upon critical threat detection.
* **CI/CD Security Automation:** Native CLI runner and GitHub Actions workflow to run background security audits during code pushes or automated pipelines.

---

## System Architecture

| Component | Module | Responsibilities |
| --- | --- | --- |
| **Risk Engine** | `src/quantum_risk.py` | Computes HNDL index, composite threat scores ($S_{\text{Threat}}$), and risk tier overrides. |
| **Chain Fetcher** | `src/chain_fetcher.py` | Connects to RPC nodes, fetches native balances, tracks nonces, and checks OFAC sanctions. |
| **Report Generator** | `src/report_generator.py` | Converts evaluation metrics into court-ready Markdown audits and SAR/STR compliance intake files. |
| **Alert Dispatcher** | `src/alert_dispatcher.py` | Sends formatted JSON alert payloads to Slack or custom webhook channels. |
| **UI Dashboard** | `src/dashboard_tab.py` | Interactive Streamlit module featuring Plotly radar charts, target configuration, and export controls. |
| **CLI Runner** | `cli.py` | Command-line interface supporting manual inputs, live RPC scans, and CI/CD status flags. |

---

## Directory Structure

```text
quantumwatch/
├── .github/
│   └── workflows/
│       └── quantumwatch_scan.yml     # Automated CI/CD security pipeline
├── src/
│   ├── quantum_risk.py               # Cryptographic decay & composite scoring engine
│   ├── chain_fetcher.py              # Multi-chain RPC & OFAC oracle fetcher
│   ├── report_generator.py           # Markdown audit & SAR compliance generator
│   ├── alert_dispatcher.py           # Real-time webhook alerting dispatcher
│   └── dashboard_tab.py              # Streamlit interactive UI tab module
├── cli.py                            # Command-line interface runner
├── main.py                           # Dashboard entrypoint application
├── requirements.txt                  # Python dependency manifest
└── README.md                         # Repository documentation

```

---

## Quickstart

**1. Clone Repository & Setup Environment**

```bash
git clone https://github.com/yourusername/quantumwatch.git
cd quantumwatch

python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

```

**2. Run a Live CLI Forensic Scan**

Scan a public address on Ethereum Mainnet using live RPC queries:

```bash
python cli.py \
  --address "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" \
  --chain ethereum \
  --live \
  --gat-score 0.25 \
  --trace-score 0.15 \
  --out-report audit_summary.md \
  --out-sar sar_filing.txt

```

**3. Command-Line Options**

| Flag | Type | Description |
| --- | --- | --- |
| `--address` | `str` | Target EVM address to evaluate (Required). |
| `--chain` | `str` | Blockchain network (`ethereum`, `base`, `arbitrum`). Default: `ethereum`. |
| `--live` | `flag` | Query live RPC nodes for balances, nonces, and sanctions status. |
| `--value-usd` | `float` | Secured value in USD (used if `--live` is omitted). |
| `--pubkey-exposed` | `flag` | Set if public key is exposed on-chain (used if `--live` is omitted). |
| `--gat-score` | `float` | Graph anomaly score normalized between `0.0` and `1.0`. Default: `0.1`. |
| `--trace-score` | `float` | EVM trace anomaly score normalized between `0.0` and `1.0`. Default: `0.1`. |
| `--out-report` | `str` | Target path to save generated Markdown audit report. |
| `--out-sar` | `str` | Target path to save SAR/STR compliance intake file. |
| `--webhook` | `str` | Custom webhook URL for emergency alert dispatches. |

**4. Launch Interactive Streamlit Dashboard**

```bash
streamlit run main.py

```

---

## Mathematical Risk Framework

1. **Harvest Now, Decrypt Later (HNDL) Vulnerability Index ($V_{\text{HNDL}}$):**

$$V_{\text{HNDL}} = \frac{\alpha \cdot \log_{10}(S_{\text{value}} + 1) + \beta \cdot P_{\text{exposed}}}{1 - e^{-\lambda \cdot (T_{\text{CRQC}} - T_{\text{current}})}}$$

Where:

* $S_{\text{value}}$ is the total secured asset value in USD.
* $P_{\text{exposed}} \in \{0, 1\}$ indicates if outbound ECDSA signature exposure has occurred.
* $T_{\text{CRQC}}$ is the targeted projection year for quantum advantage (Default: 2033).
* $\lambda$ controls the exponential decay rate curve (Default: 0.15).

2. **Composite Threat Score ($S_{\text{Threat}}$):**

$$S_{\text{Threat}} = w_1 \cdot S_{\text{GAT}} + w_2 \cdot S_{\text{Trace}} + w_3 \cdot V_{\text{HNDL}}$$

*Note: Addresses flagged by the OFAC Sanctions Oracle automatically override $S_{\text{Threat}}$ to **100 (CRITICAL - SANCTIONED)**.*

---

## Continuous Integration (CI/CD)

The repository includes a GitHub Actions workflow located at `.github/workflows/quantumwatch_scan.yml`. Every commit or pull request triggers an automated background security audit. If a target evaluates to a **CRITICAL** threat level ($S_{\text{Threat}} \ge 75.0$), the pipeline exits with status code `1` and uploads the generated audit artifact for review.

---

## License

This project is licensed under the MIT License.