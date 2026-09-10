"""
QuantumWatch - OSINT Entity Resolution
Links wallet addresses to real-world entities using free OSINT sources.

Methods:
  1. ENS name resolution (Ethereum Name Service)
  2. GitHub / social media pivots (via username enumeration)
  3. Exchange deposit address matching
  4. Known entity databases (seed labels + Arkham/DeBank exports)

All methods are free and permissionless.
"""

import requests
import pandas as pd
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

PROCESSED_DIR = Path("data/processed")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# SEED LABELS (expand via Arkham/DeBank manual exports)
# ============================================================

KNOWN_ENTITIES: Dict[str, str] = {
    # --- Ondo Finance ---
    "0x96f6ef951840721adbf46ac996b59e0235cb985c": "Ondo USDY Token",
    "0x1b19c19393e2d034d8ff31ff34c81252fcbbee92": "Ondo OUSG Token",
    "0x87b126e5518b6a1bb8465779b4607c45c643df90": "Ondo USDY Oracle Wrapper",
    "0x9cad45a8bf0ed41ff33074449b357c7a1fab4094": "Ondo Oracle",
    "0xd8c8174691d936e2c80114ec449037b13421b0a8": "Ondo USDY Blocklist",

    # --- Major Exchanges (deposit/withdrawal hot wallets) ---
    # Look these up on Etherscan (verified contracts) or Arkham
    # "0x...": "Coinbase (Hot Wallet)",
    # "0x...": "Binance (Hot Wallet)",
    # "0x...": "Kraken (Hot Wallet)",
    # "0x...": "OKX (Hot Wallet)",

    # --- Protocol Contracts ---
    # "0x...": "Uniswap V3 Router",
    # "0x...": "Aave V3 LendingPool",

    # --- Known Illicit (from public seizure cases) ---
    # "0x...": "Silk Road 2.0 (seized, 2021)",
    # "0x...": "TCO Mixer (decommissioned)",
}

# Exchange deposit address patterns (for matching)
# In production, scrape these from exchange deposit pages or use
# the Etherscan "exchange" labels
EXCHANGE_PATTERNS: Dict[str, List[str]] = {
    # "coinbase": ["0x...", "0x..."],
    # "binance": ["0x...", "0x..."],
    # "kraken": ["0x...", "0x..."],
}


# ============================================================
# ENS RESOLUTION
# ============================================================

def resolve_ens(address: str, rpc_url: str = "https://eth.llamarpc.com") -> Optional[str]:
    """
    Reverse-resolve an Ethereum address to its ENS name.
    Uses public RPC (no API key needed).

    Returns:
        ENS name (e.g., "vitalik.eth") or None
    """
    try:
        # EIP-6392: addr.reverse.ens (new) or addr.reverse.ens (old)
        # Using the simpler approach: call the ENS registry
        # For a public RPC, use the "ens_name" method if available

        # Method 1: Use public Etherscan API (simpler)
        resp = requests.get(
            f"https://api.etherscan.io/api?module=ens&action=addrToName&address={address}",
            timeout=10
        )
        data = resp.json()
        if data.get("status") == "1" and data.get("result"):
            return data["result"]
        return None
    except Exception as e:
        print(f"  ENS resolution error for {address[:10]}...: {e}")
        return None


def resolve_ens_batch(addresses: List[str]) -> Dict[str, Optional[str]]:
    """Resolve ENS for a batch of addresses."""
    results = {}
    for i, addr in enumerate(addresses):
        results[addr] = resolve_ens(addr)
        if (i + 1) % 50 == 0:
            print(f"  ENS: {i+1}/{len(addresses)} resolved")
    return results


# ============================================================
# GITHUB / SOCIAL PIVOTS
# ============================================================

def pivot_github(username: str) -> Dict[str, Optional[str]]:
    """
    Given a username (from ENS or other source), check if it exists on GitHub.
    Free, no API key needed for basic check (rate-limited to 60 req/hr).
    """
    try:
        resp = requests.get(f"https://api.github.com/users/{username}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "github": data.get("html_url"),
                "github_name": data.get("name"),
                "github_email": data.get("email"),  # Usually null unless public
                "github_bio": data.get("bio"),
                "github_location": data.get("location"),
                "github_company": data.get("company"),
            }
        return {}
    except Exception:
        return {}


def pivot_social(username: str) -> Dict[str, Optional[str]]:
    """
    Check if a username exists on common platforms.
    Free, no API keys (uses public profile pages).
    """
    checks = {
        "twitter": f"https://twitter.com/{username}",
        "linkedin": f"https://www.linkedin.com/in/{username}",
        "medium": f"https://medium.com/@{username}",
    }

    results = {}
    for platform, url in checks.items():
        try:
            resp = requests.head(url, timeout=5, allow_redirects=True)
            results[platform] = url if resp.status_code == 200 else None
        except Exception:
            results[platform] = None

    return results


def extract_username_from_ens(ens_name: str) -> Optional[str]:
    """Extract potential username from ENS name."""
    if not ens_name or not ens_name.endswith(".eth"):
        return None
    # "vitalik.eth" -> "vitalik"
    # "0xabc.eth" -> "0xabc" (less useful)
    base = ens_name.replace(".eth", "")
    if base.startswith("0x"):
        return None
    return base


# ============================================================
# EXCHANGE ADDRESS MATCHING
# ============================================================

def match_exchange(address: str) -> Optional[str]:
    """
    Check if an address is a known exchange deposit/withdrawal address.
    Uses the EXCHANGE_PATTERNS dict + Etherscan labels.
    """
    # Check local patterns
    addr_lower = address.lower()
    for exchange, addresses in EXCHANGE_PATTERNS.items():
        if addr_lower in [a.lower() for a in addresses]:
            return exchange

    # Check Etherscan label (free API)
    try:
        resp = requests.get(
            f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&page=1&offset=1&sort=desc",
            timeout=10
        )
        data = resp.json()
        if data.get("result"):
            # Etherscan sometimes labels in the "to" or "from" name
            pass  # Etherscan free API doesn't expose labels directly
    except Exception:
        pass

    return None


# ============================================================
# SANCTIONS MATCHING (delegates to fetch_sanctions)
# ============================================================

def match_sanctions(address: str, sanctions_index: Optional[dict] = None) -> Optional[dict]:
    """
    Check if an address appears in sanctions lists.
    Loads index from disk if not provided.
    """
    if sanctions_index is None:
        index_path = Path("data/raw/sanctions_index.json")
        if index_path.exists():
            with open(index_path) as f:
                sanctions_index = json.load(f)
        else:
            sanctions_index = {}

    match = sanctions_index.get(address.lower())
    return match


# ============================================================
# MAIN RESOLUTION PIPELINE
# ============================================================

def resolve_entity(address: str) -> Dict:
    """
    Full entity resolution for a single address.
    Combines all methods: ENS, social pivots, exchange matching, sanctions.

    Returns:
        dict with all resolved attributes
    """
    result = {
        "address": address,
        "ens_name": None,
        "exchange": None,
        "sanctions_hit": None,
        "social": {},
        "github": {},
        "known_label": KNOWN_ENTITIES.get(address.lower()),
    }

    # 1. Check known labels first (fastest)
    if result["known_label"]:
        return result

    # 2. ENS resolution
    result["ens_name"] = resolve_ens(address)

    # 3. If ENS found, try social pivots
    if result["ens_name"]:
        username = extract_username_from_ens(result["ens_name"])
        if username:
            result["github"] = pivot_github(username)
            result["social"] = pivot_social(username)

    # 4. Exchange matching
    result["exchange"] = match_exchange(address)

    # 5. Sanctions check
    result["sanctions_hit"] = match_sanctions(address)

    return result


def resolve_batch(addresses: List[str]) -> pd.DataFrame:
    """
    Resolve a batch of addresses.
    Returns a DataFrame with all resolved attributes.
    """
    print(f"Resolving {len(addresses)} addresses...")
    results = []

    for i, addr in enumerate(addresses):
        result = resolve_entity(addr)
        results.append(result)

        if (i + 1) % 20 == 0:
            print(f"  {i+1}/{len(addresses)} resolved")

    df = pd.DataFrame(results)
    df.to_csv(PROCESSED_DIR / "entity_resolution.csv", index=False)
    print(f"Saved to {PROCESSED_DIR / 'entity_resolution.csv'}")

    # Summary
    ens_found = df["ens_name"].notna().sum()
    exchange_found = df["exchange"].notna().sum()
    sanctions_hit = df["sanctions_hit"].notna().sum()
    known_labeled = df["known_label"].notna().sum()

    print(f"\n=== Resolution Summary ===")
    print(f"  Known labels:     {known_labeled}/{len(df)}")
    print(f"  ENS resolved:     {ens_found}/{len(df)}")
    print(f"  Exchange matched: {exchange_found}/{len(df)}")
    print(f"  Sanctions hits:   {sanctions_hit}/{len(df)}")

    return df


def load_external_labels(source: str = "arkham") -> Dict[str, str]:
    """
    Load entity labels from an external export file.
    Expected format: CSV with columns [address, label]

    How to get these exports:
      - Arkham: Go to arkhamintelligence.com -> search entity -> export
      - DeBank: Manual (no bulk export on free tier)
      - Etherscan: "Verified contracts" list for protocol addresses
    """
    label_files = {
        "arkham": Path("data/raw/arkham_labels.csv"),
        "debank": Path("data/raw/debank_labels.csv"),
        "manual": Path("data/raw/manual_labels.csv"),
    }

    path = label_files.get(source)
    if not path or not path.exists():
        print(f"  No labels file found for source '{source}' at {path}")
        return {}

    df = pd.read_csv(path)
    if "address" not in df.columns or "label" not in df.columns:
        print(f"  Expected columns: [address, label]. Got: {list(df.columns)}")
        return {}

    labels = dict(zip(df["address"].str.lower(), df["label"]))
    print(f"  Loaded {len(labels)} labels from {source}")
    return labels


def merge_labels(new_labels: Dict[str, str]) -> None:
    """Merge new labels into the in-memory KNOWN_ENTITIES dict."""
    global KNOWN_ENTITIES
    for addr, label in new_labels.items():
        if addr not in KNOWN_ENTITIES:
            KNOWN_ENTITIES[addr] = label
    print(f"  Total known entities: {len(KNOWN_ENTITIES)}")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    from pathlib import Path
    import sys

    DATA_DIR = Path("data/raw")

    # Load external labels if available
    for source in ["arkham", "manual"]:
        labels = load_external_labels(source)
        if labels:
            merge_labels(labels)

    print(f"\nKnown entities loaded: {len(KNOWN_ENTITIES)}")

    # If we have data, resolve the top addresses
    data_path = DATA_DIR / "rwa_all.parquet"
    if data_path.exists():
        df = pd.read_parquet(data_path)
        # Get top 50 most active addresses
        all_addrs = list(set(df["from"].tolist() + df["to"].tolist()))
        # Sort by frequency
        freq = pd.concat([df["from"], df["to"]]).value_counts()
        top_addrs = list(freq.head(50).index)

        print(f"\nResolving top {len(top_addrs)} addresses...")
        results = resolve_batch(top_addrs)

        # Show interesting results
        interesting = results[
            results["ens_name"].notna() |
            results["exchange"].notna() |
            results["sanctions_hit"].notna() |
            results["known_label"].notna()
        ]
        if not interesting.empty:
            print(f"\n=== Interesting Findings ({len(interesting)}) ===")
            print(interesting[["address", "ens_name", "exchange", "known_label"]].to_string())
        else:
            print("\nNo entities resolved (expected for small dataset).")
            print("Tip: Add labels via data/raw/arkham_labels.csv or manual_labels.csv")
    else:
        print("\nNo data found. Run src/data/fetch_onchain.py first.")
        print("Or test with a known address:")
        test = resolve_entity("0x96f6ef951840721adbf46ac996b59e0235cb985c")
        print(json.dumps(test, indent=2, default=str))   