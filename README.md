# QuantumWatch

**AI-Augmented Forensic & Quantum Threat Intelligence for Tokenized RWA**

A forensic analysis and threat intelligence platform for tokenized real-world assets (RWA), combining on-chain data pipelines, AI-based anomaly detection (GNN + LLM), and a post-quantum cryptography readiness audit of major RWA token standards.

## Architecture

┌─────────────────────────────────────────────────────────────────┐
│ QUANTUMWATCH │
├─────────────┬──────────────┬───────────────┬───────────────────┤
│ DATA LAYER │ DETECTION │ QUANTUM │ REPORTING │
│ │ LAYER │ LAYER │ │
│ Etherscan │ GNN Anomaly │ PQC Readiness │ Auto-Report │
│ Alchemy RPC │ Scoring │ Audit │ Dashboard │
│ DeFiLlama │ LLM Tx │ HNDL Risk │ Court-Ready │
│ RWA.xyz │ Classifier │ Model │ Output │
│ Sanctions │ Oracle Manip │ Migration │ │
│ Lists │ Detector │ Playbook │ │
│ Arkham │ Cross-Chain │ │ │
│ Labels │ Tracker │ │ │
└─────────────┴──────────────┴───────────────┴───────────────────┘

## Quickstart

```bash
# 1. Clone
git clone https://github.com/yourusername/quantumwatch.git
cd quantumwatch

# 2. Setup
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Configure
cp .env.example .env
# Edit .env with your API keys (free tiers available)

# 4. Run data pipeline
python src/data/fetch_onchain.py

# 5. Run detection
python src/detection/anomaly_heuristic.py

# 6. Run quantum audit
python src/quantum/pqc_readiness_audit.py

# 7. Launch dashboard
streamlit run src/reporting/dashboard.py   

Project Structure
quantumwatch/
├── README.md
├── requirements.txt
├── Dockerfile
├── .env.example
├── .gitignore
├── docs/
│   ├── report.md              # Main written report
│   ├── methodology.md         # Data collection & analysis methodology
│   ├── quantum_threat_model.md
│   ├── ai_forensics.md
│   ├── case_study.md
│   └── figures/
├── src/
│   ├── data/
│   │   ├── fetch_onchain.py
│   │   ├── fetch_rwa_metadata.py
│   │   ├── fetch_sanctions.py
│   │   └── build_graph.py
│   ├── detection/
│   │   ├── anomaly_heuristic.py
│   │   ├── anomaly_gnn.py
│   │   ├── llm_classifier.py
│   │   ├── oracle_manipulation.py
│   │   └── cross_chain_tracker.py
│   ├── quantum/
│   │   ├── pqc_readiness_audit.py
│   │   ├── harvest_decrypt_risk.py
│   │   └── migration_playbook.py
│   ├── reporting/
│   │   ├── generate_report.py
│   │   └── dashboard.py
│   └── utils/
│       ├── clustering.py
│       ├── peeling_detection.py
│       └── entity_resolution.py
├── notebooks/
│   ├── 01_data_exploration.ipynb
│   ├── 02_graph_construction.ipynb
│   ├── 03_anomaly_detection.ipynb
│   ├── 04_rwa_risk_scoring.ipynb
│   ├── 05_quantum_threat_model.ipynb
│   └── 06_case_study_exploit.ipynb
├── data/
│   ├── raw/
│   └── processed/
└── tests/   

Key References
Feng & Fan, "BlockLens: Detecting Malicious Transactions in Ethereum Using LLM Techniques," ISC 2025
NIST FIPS 203/204/205 (PQC Standards, Aug 2024)
Google Quantum AI Whitepaper (Mar 2026)
Federal Reserve Analysis (Sept 2025)
RWA.xyz market data

License
MIT

---

## `.gitignore`

.venv/
pycache/
*.pyc
.env
data/raw/
data/processed/
.ipynb_checkpoints/
*.parquet
*.pkl
.DS_Store


---

## `src/data/fetch_onchain.py`

```python
"""
QuantumWatch - On-Chain Data Pipeline
Pulls token transfer data from EVM chains for RWA protocols.

Data sources:
  - Etherscan API (free tier: 5 req/sec)
  - Alchemy RPC (free tier: 300 req/day)
  - DeFiLlama API (free, no key)
"""

import requests
import pandas as pd
import time
import os
from pathlib import Path
from dotenv import load_dotenv
from tqdm import tqdm

load_dotenv()

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
ALCHEMY_API_KEY = os.getenv("ALCHEMY_API_KEY", "")
ETHERSCAN_API = "https://api.etherscan.io/v2/api"
ALCHEMY_RPC = f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}"

# RWA Protocol Token Contracts (Ethereum Mainnet)
RWA_TOKENS = {
    "ondo_usdy": {
        "address": "0x96F6eF951840721AdBF46Ac996b59E0235CB985C",
        "name": "Ondo USDY",
        "decimals": 6,
        "category": "tokenized_treasury",
    },
    "ondo_ousg": {
        "address": "0x1B19C19393e2d034D8Ff31ff34c81252FcBbee92",
        "name": "Ondo OUSG",
        "decimals": 2,
        "category": "tokenized_treasury",
    },
    # Add more protocols here as you expand
    # "centrifuge_pool1": {
    #     "address": "0x...",
    #     "name": "Centrifuge Pool 1",
    #     "decimals": 18,
    #     "category": "private_credit",
    # },
    # "maple_syrup": {
    #     "address": "0x...",
    #     "name": "Maple Syrup",
    #     "decimals": 18,
    #     "category": "institutional_credit",
    # },
}

DATA_DIR = Path("data/raw")
DATA_DIR.mkdir(parents=True, exist_ok=True)


def get_token_transfers(token_address: str, page: int = 1, offset: int = 100) -> pd.DataFrame:
    """Fetch ERC-20 token transfers from Etherscan API."""
    params = {
        "chainid": 1,
        "module": "account",
        "action": "tokentx",
        "contractaddress": token_address,
        "page": page,
        "offset": offset,
        "sort": "desc",
    }
    if ETHERSCAN_API_KEY:
        params["apikey"] = ETHERSCAN_API_KEY

    resp = requests.get(ETHERSCAN_API, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    if data.get("status") == "0" and "Max rate limit reached" in data.get("message", ""):
        time.sleep(3)
        return get_token_transfers(token_address, page, offset)

    results = data.get("result", [])
    if not isinstance(results, list):
        return pd.DataFrame()

    df = pd.DataFrame(results)
    if df.empty:
        return df

    # Parse and type columns
    df["value"] = pd.to_numeric(df["value"], errors="coerce")
    df["timeStamp"] = pd.to_numeric(df["timeStamp"], errors="coerce")
    df["blockNumber"] = pd.to_numeric(df["blockNumber"], errors="coerce")
    df["gasUsed"] = pd.to_numeric(df["gasUsed"], errors="coerce")
    df["status"] = pd.to_numeric(df["status"], errors="coerce")

    return df


def fetch_protocol(token_key: str, max_pages: int = 10) -> pd.DataFrame:
    """Fetch up to max_pages*100 transfers for a single token."""
    token = RWA_TOKENS[token_key]
    all_pages = []

    for page in tqdm(range(1, max_pages + 1), desc=f"  {token['name']}"):
        df = get_token_transfers(token["address"], page=page)
        if df.empty:
            break
        df["protocol"] = token_key
        df["token_name"] = token["name"]
        df["token_address"] = token["address"]
        df["decimals"] = token["decimals"]
        df["category"] = token["category"]
        all_pages.append(df)
        time.sleep(0.25)  # Respect rate limits

    if not all_pages:
        return pd.DataFrame()

    result = pd.concat(all_pages, ignore_index=True)
    # Convert to human-readable value
    result["value_human"] = result["value"] / (10 ** result["decimals"])
    return result


def fetch_all(max_pages_per_token: int = 10) -> pd.DataFrame:
    """Fetch data for all configured RWA tokens."""
    print(f"Fetching data for {len(RWA_TOKENS)} RWA tokens...")
    all_data = []

    for token_key in RWA_TOKENS:
        print(f"\nFetching: {RWA_TOKENS[token_key]['name']}")
        df = fetch_protocol(token_key, max_pages=max_pages_per_token)
        print(f"  Retrieved {len(df)} transactions")
        all_data.append(df)

    combined = pd.concat(all_data, ignore_index=True)
    combined.to_parquet(DATA_DIR / "rwa_all.parquet")
    print(f"\nTotal: {len(combined)} transactions, "
          f"{combined['from'].nunique()} unique senders, "
          f"{combined['to'].nunique()} unique receivers")
    print(f"Saved to {DATA_DIR / 'rwa_all.parquet'}")
    return combined


def fetch_protocol_tvl() -> pd.DataFrame:
    """Fetch TVL data from DeFiLlama (free, no API key)."""
    resp = requests.get("https://api.llama.fi/protocols", timeout=30)
    resp.raise_for_status()
    protocols = resp.json()

    # Filter for RWA-related protocols
    rwa_keywords = ["ondo", "securitize", "centrifuge", "maple", "frax",
                    "blackrock", "franklin", "van eck", "hashnote"]
    rwa_protocols = [
        p for p in protocols
        if any(kw in p.get("name", "").lower() for kw in rwa_keywords)
    ]

    df = pd.DataFrame(rwa_protocols)
    if not df.empty:
        df = df[["name", "symbol", "tvl", "chain", "category"]].dropna()
        df.to_csv(DATA_DIR / "rwa_tvl.csv", index=False)
        print(f"Saved TVL data for {len(df)} RWA protocols")

    return df


if __name__ == "__main__":
    fetch_all(max_pages_per_token=10)
    fetch_protocol_tvl()   
   