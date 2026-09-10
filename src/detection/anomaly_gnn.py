"""
QuantumWatch - Graph Neural Network Anomaly Detection
Trains a GAT (Graph Attention Network) model on the address graph
to score nodes for anomaly.

Inspired by:
  - GNN + LLM Crypto Anomaly Detection (arXiv 2506.14933)
  - BlockFound (open-source blockchain anomaly detection)

Requires: torch, torch-geometric
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import GATConv, global_mean_pool
import networkx as nx
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score
import warnings
warnings.filterwarnings("ignore")

PROCESSED_DIR = Path("data/processed")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# Verified exploit addresses from public post-mortems
# Expand this list as you research. Sources:
#   - DeFiHackLabs (defihacklabs.com)
#   - Slowmist post-mortems (slowmist.io)
#   - Immunefi public bounty reports (immunefi.com)
EXPLOIT_ADDRESSES = {
    # Add verified exploit addresses here.
    # Format: "0xabc...": "Description, date"
    # Example:
    # "0x1234...": "Wormhole bridge exploit, Feb 2022",
    # "0x5678...": "Ondo oracle manipulation, Apr 2025",
}   

def graph_to_pyg(G: nx.DiGraph) -> Data:
    """Convert NetworkX DiGraph to PyG Data object."""
    nodes = list(G.nodes())
    node_idx = {node: i for i, node in enumerate(nodes)}

    # Node features: [in_degree, out_degree, total_in, total_out, net_flow, community]
    features = []
    for node in nodes:
        attrs = G.nodes[node]
        features.append([
            min(attrs.get("in_degree", 0), 100),
            min(attrs.get("out_degree", 0), 100),
            min(np.log1p(attrs.get("total_in", 0)), 30),
            min(np.log1p(attrs.get("total_out", 0)), 30),
            np.log1p(abs(attrs.get("net_flow", 0))) * np.sign(attrs.get("net_flow", 0)),
            min(attrs.get("community", 0), 50),
        ])
    x = torch.tensor(features, dtype=torch.float)

    # Edge features: [total_value, count]
    edge_list = []
    edge_attrs = []
    for u, v, data in G.edges(data=True):
        edge_list.append([node_idx[u], node_idx[v]])
        edge_attrs.append([
            min(np.log1p(data.get("total_value", 0)), 30),
            min(data.get("count", 1), 50),
        ])

    edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous() if edge_list else torch.zeros((2, 0), dtype=torch.long)
    edge_attr = torch.tensor(edge_attrs, dtype=torch.float) if edge_attrs else torch.zeros((0, 2))

    # Labels: 0 = normal, 1 = verified exploit address
    # Source: DeFiHackLabs, Slowmist, Immunefi public post-mortems
    labels = []
    for node in nodes:
        labels.append(1 if node.lower() in EXPLOIT_ADDRESSES else 0)
    y = torch.tensor(labels, dtype=torch.long)   

    return Data(x=x, edge_index=edge_index, edge_attr=edge_attr, y=y)


class RWAAnomalyGNN(nn.Module):
    """
    Graph Attention Network for RWA anomaly detection.
    Architecture: GATConv x2 -> Global Pool -> Linear -> Sigmoid
    """

    def __init__(self, in_channels: int, hidden: int = 64, out_channels: int = 1,
                 heads: int = 4, dropout: float = 0.1):
        super().__init__()
        self.dropout = dropout

        self.conv1 = GATConv(in_channels, hidden, heads=heads, dropout=dropout,
                             edge_dim=2, concat=True)
        self.conv2 = GATConv(hidden * heads, hidden, heads=heads, dropout=dropout,
                             edge_dim=2, concat=True)

        # Node-level prediction
        self.node_head = nn.Sequential(
            nn.Linear(hidden * heads, 32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, 1),
        )

        # Graph-level prediction (optional)
        self.graph_head = nn.Sequential(
            nn.Linear(hidden * heads, 32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, 1),
        )

    def forward(self, data: Data) -> dict:
        x, edge_index, edge_attr = data.x, data.edge_index, data.edge_attr

        x = F.dropout(x, p=0.1, training=self.training)
        x = self.conv1(x, edge_index, edge_attr)
        x = F.elu(x)
        x = F.dropout(x, p=0.1, training=self.training)
        x = self.conv2(x, edge_index, edge_attr)
        x = F.elu(x)

        node_scores = self.node_head(x).squeeze(-1)
        graph_score = self.graph_head(global_mean_pool(x, data.batch)).squeeze(-1)

        return {"node_scores": node_scores, "graph_score": graph_score}


def train_model(G: nx.DiGraph, epochs: int = 100, lr: float = 0.001) -> dict:
    """Train the GNN model and return metrics."""
    print("Converting graph to PyG format...")
    data = graph_to_pyg(G)
    print(f"  Nodes: {data.x.shape[0]}, Edges: {data.edge_index.shape[1]}")
    print(f"  Positive samples: {data.y.sum().item()}, Negative: {(data.y == 0).sum().item()}")

    # Split
    mask_train, mask_val = train_test_split(
        range(len(data.y)), test_size=0.2, random_state=42,
        stratify=data.y.numpy() if data.y.sum() > 0 else None
    )
    train_mask = torch.zeros(len(data.y), dtype=torch.bool)
    val_mask = torch.zeros(len(data.y), dtype=torch.bool)
    train_mask[list(mask_train)] = True
    val_mask[list(mask_val)] = True

    model = RWAAnomalyGNN(in_channels=data.x.shape[1])
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    criterion = nn.BCEWithLogitsLoss()

    print(f"\nTraining for {epochs} epochs...")
    best_f1 = 0
    history = []

    for epoch in range(epochs):
        model.train()
        optimizer.zero_grad()
        out = model(data)
        loss = criterion(out["node_scores"][train_mask], data.y[train_mask].float())
        loss.backward()
        optimizer.step()

        if (epoch + 1) % 10 == 0:
            model.eval()
            with torch.no_grad():
                out_val = model(data)
                preds = (torch.sigmoid(out_val["node_scores"][val_mask]) > 0.5).long()
                f1 = f1_score(data.y[val_mask].numpy(), preds.numpy(), zero_division=0)
            history.append({"epoch": epoch + 1, "loss": loss.item(), "val_f1": f1})
            print(f"  Epoch {epoch+1:3d} | Loss: {loss.item():.4f} | Val F1: {f1:.4f}")
            if f1 > best_f1:
                best_f1 = f1
                torch.save(model.state_dict(), PROCESSED_DIR / "gnn_best.pt")

    print(f"\nBest Val F1: {best_f1:.4f}")
    return {"model": model, "history": history, "best_f1": best_f1}


def score_all_nodes(G: nx.DiGraph) -> pd.DataFrame:
    """Score all nodes using the trained model."""
    model_path = PROCESSED_DIR / "gnn_best.pt"
    if not model_path.exists():
        print("No trained model found. Run train_model() first.")
        return pd.DataFrame()

    data = graph_to_pyg(G)
    model = RWAAnomalyGNN(in_channels=data.x.shape[1])
    model.load_state_dict(torch.load(model_path, weights_only=True))
    model.eval()

    with torch.no_grad():
        out = model(data)
        scores = torch.sigmoid(out["node_scores"]).numpy()

    nodes = list(G.nodes())
    df = pd.DataFrame({
        "address": nodes,
        "gnn_score": scores,
        "label": G.nodes() and [G.nodes[n].get("label", "") for n in nodes],
    })
    df = df.sort_values("gnn_score", ascending=False)
    df.to_csv(PROCESSED_DIR / "gnn_scores.csv", index=False)
    print(f"\nGNN scores saved. Top 10:")
    print(df.head(10).to_string())
    return df


if __name__ == "__main__":
    import networkx as nx

    print("Loading graph...")
    G = nx.read_pickled(PROCESSED_DIR / "rwa_graph.pkl")
    print(f"  {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # Train
    result = train_model(G, epochs=100)

    # Score
    score_all_nodes(G)   