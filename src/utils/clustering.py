"""
QuantumWatch - Wallet Clustering Utilities
Groups addresses likely controlled by the same entity.
"""

import networkx as nx
import pandas as pd
import numpy as np
from typing import List, Tuple
from collections import defaultdict


def cluster_by_input_sharing(tx_data: pd.DataFrame) -> List[List[str]]:
    """
    Cluster addresses that share inputs (Bitcoin-style).
    For EVM, use: addresses that appear together in the same
    multi-output transaction or that fund each other.
    """
    # For EVM: cluster by co-occurrence in same block
    # Addresses that transact with each other frequently are likely related
    co_occurrence = defaultdict(int)

    for _, row in tx_data.iterrows():
        sender = row["from"]
        receiver = row["to"]
        co_occurrence[(sender, receiver)] += 1
        co_occurrence[(receiver, sender)] += 1

    # Build co-occurrence graph
    G = nx.Graph()
    for (a, b), count in co_occurrence.items():
        G.add_edge(a, b, weight=count)

    # Find connected components
    clusters = list(nx.connected_components(G))
    return [list(c) for c in clusters if len(c) > 1]


def cluster_by_timing(tx_data: pd.DataFrame, window_seconds: int = 30) -> List[List[str]]:
    """
    Cluster addresses that transact within a tight time window.
    Suggests automated control (bot, script, or single operator).
    """
    tx_data = tx_data.copy()
    tx_data["timeStamp"] = pd.to_numeric(tx_data["timeStamp"], errors="coerce")
    tx_data = tx_data.sort_values("timeStamp")

    # Group by time windows
    tx_data["time_window"] = tx_data["timeStamp"] // window_seconds

    clusters = []
    for window, group in tx_data.groupby("time_window"):
        addresses = set(group["from"].tolist() + group["to"].tolist())
        if len(addresses) > 1:
            clusters.append(list(addresses))

    return clusters


def cluster_by_amount_pattern(tx_data: pd.DataFrame) -> List[List[str]]:
    """
    Cluster addresses with similar amount patterns.
    Addresses that send/receive the same unique amounts are likely related.
    """
    # Find amounts that appear in multiple addresses' txs
    amount_to_senders = defaultdict(set)
    amount_to_receivers = defaultdict(set)

    for _, row in tx_data.iterrows():
        amt = row["value"]  # Raw value (unique fingerprint)
        amount_to_senders[amt].add(row["from"])
        amount_to_receivers[amt].add(row["to"])

    # Build link graph
    G = nx.Graph()
    for amt, senders in amount_to_senders.items():
        if len(senders) > 1:
            senders = list(senders)
            for i in range(len(senders)):
                for j in range(i + 1, len(senders)):
                    G.add_edge(senders[i], senders[j])

    for amt, receivers in amount_to_receivers.items():
        if len(receivers) > 1:
            receivers = list(receivers)
            for i in range(len(receivers)):
                for j in range(i + 1, len(receivers)):
                    G.add_edge(receivers[i], receivers[j])

    clusters = list(nx.connected_components(G))
    return [list(c) for c in clusters if len(c) > 1]


def merge_clusters(clusters: List[List[str]]) -> List[List[str]]:
    """Merge overlapping clusters using union-find."""
    parent = {}

    def find(x):
        if x not in parent:
            parent[x] = x
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    for cluster in clusters:
        if not cluster:
            continue
        first = cluster[0]
        for addr in cluster[1:]:
            union(first, addr)

    # Group by root
    groups = defaultdict(set)
    for addr in parent:
        groups[find(addr)].add(addr)

    return [list(g) for g in groups.values() if len(g) > 1]


def cluster_all(tx_data: pd.DataFrame) -> dict:
    """Run all clustering methods and merge results."""
    print("Clustering by input sharing...")
    c1 = cluster_by_input_sharing(tx_data)
    print(f"  {len(c1)} clusters")

    print("Clustering by timing...")
    c2 = cluster_by_timing(tx_data)
    print(f"  {len(c2)} clusters")

    print("Clustering by amount pattern...")
    c3 = cluster_by_amount_pattern(tx_data)
    print(f"  {len(c3)} clusters")

    print("Merging clusters...")
    merged = merge_clusters(c1 + c2 + c3)
    print(f"  {len(merged)} final clusters")

    # Size distribution
    sizes = [len(c) for c in merged]
    print(f"  Cluster sizes: min={min(sizes)}, max={max(sizes)}, "
          f"median={int(np.median(sizes))}, total={sum(sizes)}")

    return {
        "input_sharing": c1,
        "timing": c2,
        "amount_pattern": c3,
        "merged": merged,
    }


if __name__ == "__main__":
    from pathlib import Path
    df = pd.read_parquet(Path("data/raw/rwa_all.parquet"))
    results = cluster_all(df)
    print(f"\nTop 5 largest clusters:")
    for i, cluster in enumerate(sorted(results["merged"], key=len, reverse=True)[:5]):
        print(f"  Cluster {i+1}: {len(cluster)} addresses")   