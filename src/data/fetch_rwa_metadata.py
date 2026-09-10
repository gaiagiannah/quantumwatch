"""
QuantumWatch - RWA Metadata & Reserve Data
Pulls issuer identity, reserve attestations, and token standard info.
"""

import requests
import pandas as pd
import json
from pathlib import Path

DATA_DIR = Path("data/raw")
DATA_DIR.mkdir(parents=True, exist_ok=True)


def fetch_ondo_metadata() -> dict:
    """Fetch Ondo Finance protocol metadata from their docs/API."""
    # Ondo publishes contract addresses and metadata
    metadata = {
        "ondo_usdy": {
            "issuer": "Ondo Finance (Ondo USDY LLC, Delaware)",
            "underlying": "Short-term US Treasuries + bank demand deposits",
            "token_standard": "ERC-20",
            "chains": ["Ethereum", "Arbitrum", "BNB Chain", "Mantle", "Sui", "Aptos", "Stellar", "Sei", "Plume", "Noble"],
            "oracle": "USDYOracleWrapper (0x87b126e5518b6a1Bb8465779b4607C45C643DF90)",
            "blocklist_contract": "0xd8c8174691d936E2C80114EC449037b13421B0a8",
            "custodian": "Coinbase Prime",
            "regulatory": "Non-US investors (blocklist-based)",
            "min_investment": "$100,000 (redemption)",
        },
        "ondo_ousg": {
            "issuer": "Ondo Finance (Ondo OUSG LLC, Delaware)",
            "underlying": "Short-term US Treasuries",
            "token_standard": "ERC-20",
            "chains": ["Ethereum"],
            "oracle": "OndoOracle (0x9Cad45a8BF0Ed41Ff33074449B357C7a1fAb4094)",
            "custodian": "Coinbase Prime",
            "regulatory": "Non-US investors",
        },
    }
    return metadata


def fetch_chainlink_oracle_data() -> pd.DataFrame:
    """
    Fetch Chainlink oracle data for RWA-relevant feeds.
    Source: data.chain.link (free)
    """
    # Chainlink data API
    # For USDY, the oracle is Ondo's own, but Chainlink provides
    # the underlying Treasury yield data
    feeds = {
        "US Treasury 1-3 Month Bill": "0x...",  # Look up on data.chain.link
        "US Treasury 3-6 Month Bill": "0x...",
    }

    # For now, document the oracle architecture
    oracle_report = {
        "ondo_usdy_oracle": {
            "type": "Custom (Ondo Oracle Wrapper)",
            "address": "0x87b126e5518b6a1Bb8465779b4607C45C643DF90",
            "description": "Wrapper that always references the current canonical USDY oracle implementation",
            "risk": "Single oracle dependency; if compromised, all USDY pricing is affected",
        },
        "ondo_ousg_oracle": {
            "type": "Custom (Ondo Oracle)",
            "address": "0x9Cad45a8BF0Ed41Ff33074449B357C7a1fAb4094",
            "description": "Unified interface for retrieving token price data",
            "risk": "Single oracle dependency",
        },
    }
    return pd.DataFrame(oracle_report).T


def fetch_rwa_market_data() -> dict:
    """Fetch aggregate RWA market data from RWA.xyz."""
    try:
        resp = requests.get("https://api.rwa.xyz/v1/overview", timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"RWA.xyz API not available: {e}")
        # Fallback: use DeFiLlama categories
        resp = requests.get("https://api.llama.fi/v2/historicalChainTvl", timeout=30)
        return {"source": "defillama_fallback", "data": resp.json() if resp.status_code == 200 else {}}


def save_metadata():
    """Compile and save all RWA metadata."""
    metadata = fetch_ondo_metadata()
    oracles = fetch_chainlink_oracle_data()
    market = fetch_rwa_market_data()

    output = {
        "generated": pd.Timestamp.now().isoformat(),
        "protocols": metadata,
        "oracles": oracles.to_dict(),
        "market_overview": market,
    }

    path = DATA_DIR / "rwa_metadata.json"
    with open(path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"RWA metadata saved to {path}")


if __name__ == "__main__":
    save_metadata()   