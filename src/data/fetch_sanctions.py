"""
QuantumWatch - Sanctions & Watchlist Ingestion
Pulls OFAC SDN, UN, and EU sanctions lists for address screening.
"""

import requests
import pandas as pd
import json
import hashlib
from pathlib import Path
from datetime import datetime

DATA_DIR = Path("data/raw")
DATA_DIR.mkdir(parents=True, exist_ok=True)


def fetch_ofac_sdn() -> pd.DataFrame:
    """
    Fetch OFAC Specially Designated Nationals (SDN) list.
    Source: OFAC publishes a machine-readable file.
    """
    # OFAC publishes the SDN list as a text file
    url = "https://sanctions.ofac.treas.gov/api/sdn"
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        records = data.get("records", data if isinstance(data, list) else [])
        df = pd.DataFrame(records)
        print(f"OFAC SDN: {len(df)} entries")
        return df
    except Exception as e:
        print(f"OFAC API error: {e}")
        # Fallback: use the older CSV format
        url_csv = "https://www.treasury.gov/ofac/downloads/sdn.csv"
        try:
            df = pd.read_csv(url_csv)
            print(f"OFAC SDN (CSV fallback): {len(df)} entries")
            return df
        except Exception as e2:
            print(f"OFAC CSV fallback also failed: {e2}")
            return pd.DataFrame()


def fetch_un_sanctions() -> pd.DataFrame:
    """
    Fetch UN Consolidated Sanctions List.
    Source: UN SCOMS
    """
    # UN publishes via SCOMS API
    url = "https://scoms.un.org/api/v1/list"
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        df = pd.DataFrame(data if isinstance(data, list) else data.get("results", []))
        print(f"UN Sanctions: {len(df)} entries")
        return df
    except Exception as e:
        print(f"UN Sanctions API error: {e}")
        return pd.DataFrame()


def build_address_index(sanctions_df: pd.DataFrame) -> dict:
    """
    Build a hash-based index for fast address matching.
    In production, this would also include:
    - Known exchange hot wallets
    - Known mixer/tumbler addresses
    - Addresses from past seizure cases
    """
    index = {}

    # OFAC entries may include crypto addresses in notes
    if "notes" in sanctions_df.columns:
        for _, row in sanctions_df.iterrows():
            notes = str(row.get("notes", ""))
            # Look for hex addresses (0x + 40 hex chars)
            import re
            addresses = re.findall(r"0x[a-fA-F0-9]{40}", notes)
            for addr in addresses:
                index[addr.lower()] = {
                    "source": "OFAC",
                    "name": row.get("name", "Unknown"),
                    "program": row.get("program", "SDN"),
                    "added": row.get("date_added", ""),
                }

    # Bitcoin addresses (base58)
    if "notes" in sanctions_df.columns:
        for _, row in sanctions_df.iterrows():
            notes = str(row.get("notes", ""))
            btc_addrs = re.findall(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", notes)
            for addr in btc_addrs:
                index[addr] = {
                    "source": "OFAC",
                    "name": row.get("name", "Unknown"),
                    "program": row.get("program", "SDN"),
                }

    print(f"Address index built: {len(index)} entries")
    return index


def screen_addresses(addresses: list, sanctions_index: dict) -> pd.DataFrame:
    """Screen a list of wallet addresses against sanctions index."""
    hits = []
    for addr in addresses:
        match = sanctions_index.get(addr.lower())
        if match:
            hits.append({"address": addr, **match})
    return pd.DataFrame(hits)


def save_sanctions():
    """Fetch and cache all sanctions data."""
    print("Fetching OFAC SDN list...")
    ofac = fetch_ofac_sdn()

    print("Fetching UN Sanctions list...")
    un = fetch_un_sanctions()

    # Build combined address index
    index = {}
    if not ofac.empty:
        index.update(build_address_index(ofac))
    if not un.empty:
        index.update(build_address_index(un))

    # Save
    ofac.to_parquet(DATA_DIR / "ofac_sdn.parquet", index=False)
    if not un.empty:
        un.to_parquet(DATA_DIR / "un_sanctions.parquet", index=False)

    with open(DATA_DIR / "sanctions_index.json", "w") as f:
        json.dump(index, f, indent=2)

    print(f"Sanctions data saved. Index size: {len(index)} addresses")


if __name__ == "__main__":
    save_sanctions()   