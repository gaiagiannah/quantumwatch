"""
QuantumWatch - Address Relationship Graph Construction
Builds a directed graph of wallet interactions from token transfer data.
"""

import networkx as nx
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Optional
import json

DATA_DIR = Path("data/raw")
PROCESSED_DIR = Path("data/processed")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


def build_transfer_graph(df: pd.DataFrame) -> nx.DiGraph:
    """
    Build a directed graph where:
      - Nodes = wallet addresses
      - Edges = token transfers (directed: from -> to)
      - Edge attributes: value, timestamp, protocol, tx hash
    """
    G = nx.DiGraph()

    # Add edges with aggregated attributes
    grouped = df.groupby(["from", "to"]).agg(
        total_value=("value_human", "sum"),
        count=("value_human", "count"),
        first_seen=("timeStamp", "min"),
        last_seen=("timeStamp", "max"),
        protocols=("protocol", lambda x: list(set(x))),
        tx_hashes=("hash", "list"),
    ).reset_index()

    for _, row in grouped.iterrows():
        G.add_edge(
            row["from"], row["to"],
            total_value=row["total_value"],
            count=row["count"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            protocols=row["protocols"],
        )

    # Add node attributes
    for addr in G.nodes():
        out_degree = G.out_degree(addr)
        in_degree = G.in_degree(addr)
        total_out = sum(G[addr][n]["total_value"] for n in G.successors(addr)) if out_degree > 0 else 0
        total_in = sum(G[n][addr]["total_value"] for n in G.predecessors(addr)) if in_degree > 0 else 0

        G.nodes[addr]["out_degree"] = out_degree
        G.nodes[addr]["in_degree"] = in_degree
        G.nodes[addr]["total_out"] = total_out
        G.nodes[addr]["total_in"] = total_in
        G.nodes[addr]["net_flow"] = total_in - total_out

    return G


def add_labels(G: nx.DiGraph, labels: dict) -> nx.DiGraph:
    """Add entity labels to known addresses."""
    for addr, label in labels.items():
        if addr in G:
            G.nodes[addr]["label"] = label
            G.nodes[addr]["known"] = True
    return G


def detect_communities(G: nx.DiGraph) -> dict:
    """
    Detect communities (clusters of wallets that interact frequently).
    Uses Louvain method on the underlying undirected graph.
    """
    undirected = G.to_undirected()
    communities = nx.community.louvain_communities(undirected, weight="count", seed=42)

    # Assign community IDs
    community_map = {}
    for i, comm in enumerate(communities):
        for node in comm:
            community_map[node] = i
            G.nodes[node]["community"] = i

    return community_map


def find_hubs(G: nx.DiGraph, top_n: int = 20) -> pd.DataFrame:
    """Find the most connected wallets (likely exchanges, custodians, protocols)."""
    scores = []
    for node in G.nodes():
        scores.append({
            "address": node,
            "in_degree": G.in_degree(node),
            "out_degree": G.out_degree(node),
            "total_in": G.nodes[node]["total_in"],
            "total_out": G.nodes[node]["total_out"],
            "label": G.nodes[node].get("label", ""),
            "betweenness": 0,  # Placeholder (expensive to compute on large graphs)
        })

    df = pd.DataFrame(scores)
    df["total_degree"] = df["in_degree"] + df["out_degree"]
    df = df.sort_values("total_degree", ascending=False).head(top_n)
    return df


def find_peeling_chains(G: nx.DiGraph, min_hops: int = 3, max_hops: int = 10) -> list:
    """
    Detect peeling chains: sequential transfers where each hop
    sends to a new address with slightly decreasing amounts.
    """
    chains = []

    for start_node in G.nodes():
        if G.out_degree(start_node) < min_hops:
            continue

        # Walk forward up to max_hops
        current = start_node
        path = [current]
        prev_value = G.nodes[current].get("total_in", 0)

        for _ in range(max_hops):
            successors = list(G.successors(current))
            if not successors:
                break

            # Pick the successor with the largest transfer
            next_node = max(successors, key=lambda n: G[current][n]["total_value"])
            hop_value = G[current][next_node]["total_value"]

            # Check if value is decreasing (peeling pattern)
            if prev_value > 0 and hop_value < prev_value * 0.95:
                path.append(next_node)
                current = next_node
                prev_value = hop_value
            else:
                break

        if len(path) >= min_hops:
            chains.append(path)

    return chains


def save_graph(G: nx.DiGraph):
    """Save graph to disk (pickle for speed, JSON for portability)."""
    nx.write_pickled(G, PROCESSED_DIR / "rwa_graph.pkl")

    # Also save a summary
    summary = {
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "density": round(nx.density(G), 6),
        "avg_degree": round(2 * G.number_of_edges() / max(G.number_of_nodes(), 1), 2),
        "connected_components": nx.number_weakly_connected_components(G),
    }
    with open(PROCESSED_DIR / "graph_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"Graph saved: {summary}")


def main():
    """Full graph construction pipeline."""
    print("Loading transfer data...")
    df = pd.read_parquet(DATA_DIR / "rwa_all.parquet")
    print(f"  {len(df)} transactions")

    print("Building graph...")
    G = build_transfer_graph(df)
    print(f"  {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # Load known labels
    labels_path = DATA_DIR / "known_entities.json"
    if labels_path.exists():
        with open(labels_path) as f:
            labels = json.load(f)
        G = add_labels(G, labels)
        print(f"  {len(labels)} labels applied")

    print("Detecting communities...")
    communities = detect_communities(G)
    print(f"  {len(communities)} communities found")

    print("Finding hubs...")
    hubs = find_hubs(G, top_n=20)
    print(hubs[["address", "total_degree", "total_in", "total_out", "label"]].to_string())
    hubs.to_csv(PROCESSED_DIR / "hubs.csv", index=False)

    print("Finding peeling chains...")
    chains = find_peeling_chains(G)
    print(f"  {len(chains)} peeling chains detected")
    if chains:
        for i, chain in enumerate(chains[:5]):
            print(f"  Chain {i+1}: {' -> '.join(a[:10] for a in chain)}")

    save_graph(G)


if __name__ == "__main__":
    main()   