"""
QuantumWatch - Heuristic Anomaly Detection
Rule-based detection of suspicious transaction patterns.
This is the baseline; the GNN and LLM layers build on top.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple

DATA_DIR = Path("data/raw")
PROCESSED_DIR = Path("data/processed")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


def detect_large_transfers(df: pd.DataFrame, percentile: float = 99) -> pd.Series:
    """Flag transfers above the Nth percentile by value."""
    threshold = df["value_human"].quantile(percentile / 100)
    return df["value_human"] > threshold


def detect_rapid_sequential(df: pd.DataFrame, max_seconds: int = 60) -> pd.Series:
    """Flag addresses that send multiple transfers within max_seconds."""
    df = df.copy()
    df["timeStamp"] = pd.to_numeric(df["timeStamp"], errors="coerce")
    df = df.sort_values(["from", "timeStamp"])
    df["time_diff"] = df.groupby("from")["timeStamp"].diff()
    return df["time_diff"] < max_seconds


def detect_structuring(df: pd.DataFrame, threshold_usd: float = 1000, min_count: int = 10) -> pd.Series:
    """
    Flag addresses that make many small transfers (structuring / smurfing).
    Classic money laundering pattern: break large amounts into small pieces
    below reporting thresholds.
    """
    small = df[df["value_human"] < threshold_usd]
    counts = small.groupby("from").size()
    structuring_addrs = set(counts[counts >= min_count].index)
    return df["from"].isin(structuring_addrs)


def detect_round_trips(df: pd.DataFrame) -> pd.Series:
    """
    Detect round-trip transfers: A -> B -> A within a short window.
    Common in layering and wash trading.
    """
    df = df.copy()
    df["timeStamp"] = pd.to_numeric(df["timeStamp"], errors="coerce")

    # Create reverse pairs
    reverse = df[["from", "to", "value_human", "timeStamp"]].rename(
        columns={"from": "to", "to": "from"}
    )
    merged = df.merge(reverse, on=["from", "to"], suffixes=("_a", "_b"))
    merged["time_diff"] = abs(merged["timeStamp_a"] - merged["timeStamp_b"])
    round_trip_mask = merged["time_diff"] < 3600  # Within 1 hour

    # Mark original transactions involved in round trips
    round_trip_txs = set(merged.loc[round_trip_mask, "hash"].dropna())
    return df["hash"].isin(round_trip_txs)


def detect_new_wallet_burst(df: pd.DataFrame, window_hours: int = 1) -> pd.Series:
    """
    Flag wallets that appear for the first time and immediately
    make multiple transfers (disposable wallet pattern).
    """
    df = df.copy()
    df["timeStamp"] = pd.to_numeric(df["timeStamp"], errors="coerce")

    first_seen = df.groupby("from")["timeStamp"].transform("min")
    df["is_first_window"] = (df["timeStamp"] - first_seen) < (window_hours * 3600)

    # Count transfers in first window
    first_window_counts = df[df["is_first_window"]].groupby("from").size()
    burst_addrs = set(first_window_counts[first_window_counts >= 5].index)

    return df["from"].isin(burst_addrs)


def detect_concentration(df: pd.DataFrame, top_n: int = 5) -> pd.Series:
    """
    Flag when a small number of addresses account for a disproportionate
    share of total volume (centralization / custodian pattern).
    """
    total_by_addr = df.groupby("from")["value_human"].sum().sort_values(ascending=False)
    top_addrs = set(total_by_addr.head(top_n).index)
    return df["from"].isin(top_addrs)


def run_all_heuristics(df: pd.DataFrame) -> pd.DataFrame:
    """Run all heuristic detectors and combine into a composite score."""
    df = df.copy()

    flags = {
        "large_transfer": detect_large_transfers(df),
        "rapid_sequential": detect_rapid_sequential(df),
        "structuring": detect_structuring(df),
        "round_trip": detect_round_trips(df),
        "new_wallet_burst": detect_new_wallet_burst(df),
        "concentration": detect_concentration(df),
    }

    for name, flag in flags.items():
        df[f"flag_{name}"] = flag

    # Composite score: weighted sum
    weights = {
        "flag_large_transfer": 1,
        "flag_rapid_sequential": 2,
        "flag_structuring": 3,
        "flag_round_trip": 3,
        "flag_new_wallet_burst": 2,
        "flag_concentration": 1,
    }

    df["anomaly_score"] = sum(df[col].astype(int) * w for col, w in weights.items())
    df["anomaly_level"] = pd.cut(
        df["anomaly_score"],
        bins=[-1, 1, 3, 5, 100],
        labels=["low", "medium", "high", "critical"],
    )

    return df


def main():
    print("Loading data...")
    df = pd.read_parquet(DATA_DIR / "rwa_all.parquet")
    print(f"  {len(df)} transactions")

    print("Running heuristic detection...")
    result = run_all_heuristics(df)

    # Summary
    print("\n=== Anomaly Summary ===")
    print(result["anomaly_level"].value_counts().to_string())

    print("\n=== Top Flagged Transactions ===")
    top = result[result["anomaly_score"] >= 3].sort_values(
        "anomaly_score", ascending=False
    ).head(20)
    print(top[["from", "to", "value_human", "anomaly_score", "anomaly_level", "protocol"]].to_string())

    # Save
    result.to_parquet(PROCESSED_DIR / "rwa_flagged.parquet", index=False)
    top.to_csv(PROCESSED_DIR / "top_flagged.csv", index=False)
    print(f"\nSaved to {PROCESSED_DIR / 'rwa_flagged.parquet'}")


if __name__ == "__main__":
    main()   