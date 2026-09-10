"""
QuantumWatch - Peeling Chain / Layering Detection
Detects the classic money laundering pattern of
incrementally dispersing funds through a chain of addresses.
"""

import pandas as pd
import numpy as np
import networkx as nx
from typing import List, Dict
from dataclasses import dataclass


@dataclass
class PeelingChain:
    """A detected peeling chain."""
    start_address: str
    end_address: str
    hops: int
    total_value: float
    value_decay: float  # How much value decreases per hop
    time_span_seconds: float
    addresses: List[str]
    risk_score: float


def detect_peeling_chains(
    tx_data: pd.DataFrame,
    min_hops: int = 3,
    max_hops: int = 15,
    min_decay: float = 0.05,  # At least 5% decrease per hop
    max_decay: float = 0.50,  # At most 50% decrease per hop
    max_time_span_hours: float = 72,
) -> List[PeelingChain]:
    """
    Detect peeling chains in transaction data.

    Pattern:
      A -> B -> C -> D -> E
      where each hop transfers slightly less than the previous,
      within a reasonable time window.
    """
    tx_data = tx_data.copy()
    tx_data["timeStamp"] = pd.to_numeric(tx_data["timeStamp"], errors="coerce")
    tx_data["value_human"] = pd.to_numeric(tx_data["value_human"], errors="coerce")
    tx_data = tx_data.sort_values("timeStamp")

    # Build adjacency: for each address, list of outgoing transfers
    outgoing = {}
    for _, row in tx_data.iterrows():
        sender = row["from"]
        if sender not in outgoing:
            outgoing[sender] = []
        outgoing[sender].append({
            "to": row["to"],
            "value": row["value_human"],
            "time": row["timeStamp"],
            "hash": row.get("hash", ""),
        })

    # Sort outgoing by time
    for addr in outgoing:
        outgoing[addr].sort(key=lambda x: x["time"])

    chains = []

    for start_addr, transfers in outgoing.items():
        # Try to follow a peeling path from this address
        for i, first_hop in enumerate(transfers):
            path = [start_addr, first_hop["to"]]
            prev_value = first_hop["value"]
            prev_time = first_hop["time"]

            for _ in range(min_hops - 1, max_hops):
                current = path[-1]
                next_transfers = outgoing.get(current, [])

                # Find the next transfer that fits the peeling pattern
                next_hop = None
                for t in next_transfers:
                    if t["time"] < prev_time:
                        continue
                    if t["time"] - prev_time > max_time_span_hours * 3600:
                        break

                    value_change = (prev_value - t["value"]) / max(prev_value, 1e-8)
                    if min_decay <= value_change <= max_decay:
                        next_hop = t
                        break

                if next_hop is None:
                    break

                path.append(next_hop["to"])
                prev_value = next_hop["value"]
                prev_time = next_hop["time"]

            if len(path) >= min_hops + 1:  # +1 because we count nodes, not edges
                # Calculate metrics
                total_value = transfers[0]["value"]
                final_value = prev_value
                time_span = (prev_time - transfers[0]["time"])

                # Risk score: more hops + faster = higher risk
                hops = len(path) - 1
                speed = hops / max(time_span / 3600, 0.1)  # Hops per hour
                risk = min(10, (hops * 0.5) + (speed * 0.3) + (1 - final_value / total_value) * 2)

                chains.append(PeelingChain(
                    start_address=start_addr,
                    end_address=path[-1],
                    hops=hops,
                    total_value=total_value,
                    value_decay=(total_value - final_value) / total_value,
                    time_span_seconds=time_span,
                    addresses=path,
                    risk_score=round(risk, 2),
                ))

    # Deduplicate (same start+end with same hop count)
    seen = set()
    unique_chains = []
    for chain in chains:
        key = (chain.start_address, chain.end_address, chain.hops)
        if key not in seen:
            seen.add(key)
            unique_chains.append(chain)

    unique_chains.sort(key=lambda c: c.risk_score, reverse=True)
    return unique_chains


def summarize_chains(chains: List[PeelingChain]) -> pd.DataFrame:
    """Create a summary DataFrame of detected chains."""
    if not chains:
        return pd.DataFrame()

    df = pd.DataFrame([
        {
            "start": c.start_address,
            "end": c.end_address,
            "hops": c.hops,
            "total_value": c.total_value,
            "value_decay_pct": round(c.value_decay * 100, 2),
            "time_span_hours": round(c.time_span_seconds / 3600, 2),
            "risk_score": c.risk_score,
        }
        for c in chains
    ])
    return df


if __name__ == "__main__":
    from pathlib import Path
    df = pd.read_parquet(Path("data/raw/rwa_all.parquet"))

    print("Detecting peeling chains...")
    chains = detect_peeling_chains(df, min_hops=3, max_hops=10)
    print(f"Found {len(chains)} peeling chains")

    if chains:
        summary = summarize_chains(chains)
        print(summary.head(20).to_string())
        summary.to_csv(Path("data/processed/peeling_chains.csv"), index=False)   