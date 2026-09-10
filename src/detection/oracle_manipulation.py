"""
QuantumWatch - Oracle Manipulation Detector
Detects potential oracle price manipulation in RWA protocols.

Methodology:
  1. Track oracle price updates over time
  2. Flag deviations from expected range (z-score > threshold)
  3. Correlate with subsequent liquidation or transfer events
  4. Check for single-source oracle dependency (concentration risk)
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import List, Dict
import json

PROCESSED_DIR = Path("data/processed")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


class OracleManipulationDetector:
    """
    Detects oracle manipulation patterns in RWA protocols.

    Attack vectors:
    1. Flash loan + oracle update: Borrow large amount, manipulate price,
       trigger wrongful liquidation, repay loan.
    2. Oracle downtime: If oracle is stale, prices diverge from reality.
    3. Single-source dependency: One oracle controls all pricing.
    4. Timestamp manipulation: Update oracle at inopportune moments.
    """

    def __init__(self, z_threshold: float = 3.0, max_staleness_hours: float = 24.0):
        self.z_threshold = z_threshold
        self.max_staleness_hours = max_staleness_hours

    def compute_price_zscores(self, prices: pd.Series) -> pd.Series:
        """Compute rolling z-scores for price deviations."""
        rolling_mean = prices.rolling(window=50, min_periods=10).mean()
        rolling_std = prices.rolling(window=50, min_periods=10).std()
        zscores = (prices - rolling_mean) / (rolling_std + 1e-8)
        return zscores

    def detect_anomalies(self, oracle_data: pd.DataFrame) -> pd.DataFrame:
        """
        Detect anomalies in oracle price feed.

        Expected columns:
          - timestamp: Unix timestamp of price update
          - price: Reported price
          - source: Oracle source identifier
          - protocol: Which RWA protocol
        """
        df = oracle_data.copy()
        df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
        df["price"] = pd.to_numeric(df["price"], errors="coerce")
        df = df.sort_values("timestamp").reset_index(drop=True)

        # Z-score detection
        df["zscore"] = self.compute_price_zscores(df["price"])
        df["flag_zscore"] = df["zscore"].abs() > self.z_threshold

        # Staleness detection
        df["time_diff_hours"] = df["timestamp"].diff() / 3600
        df["flag_stale"] = df["time_diff_hours"] > self.max_staleness_hours

        # Rapid update detection (multiple updates in short window)
        df["updates_per_hour"] = df.groupby("protocol")["timestamp"].transform(
            lambda x: (x - x.shift(1) < 3600).astype(int)
        )
        df["flag_rapid"] = df["updates_per_hour"] > 5

        # Composite
        df["oracle_risk_score"] = (
            df["flag_zscore"].astype(int) * 3 +
            df["flag_stale"].astype(int) * 2 +
            df["flag_rapid"].astype(int) * 1
        )

        return df

    def assess_oracle_concentration(self, protocol_oracles: Dict[str, List[str]]) -> pd.DataFrame:
        """
        Assess oracle concentration risk per protocol.
        If a protocol relies on a single oracle, it's a single point of failure.
        """
        results = []
        for protocol, oracles in protocol_oracles.items():
            unique_oracles = len(set(oracles))
            concentration = 1.0 / max(unique_oracles, 1)
            risk = "HIGH" if unique_oracles == 1 else ("MEDIUM" if unique_oracles <= 3 else "LOW")
            results.append({
                "protocol": protocol,
                "num_oracles": unique_oracles,
                "oracles": list(set(oracles)),
                "concentration_score": concentration,
                "risk_level": risk,
            })
        return pd.DataFrame(results)

    def generate_report(self, df: pd.DataFrame) -> str:
        """Generate a human-readable report of oracle anomalies."""
        anomalies = df[df["oracle_risk_score"] > 0]
        if anomalies.empty:
            return "No oracle anomalies detected."

        lines = [
            "=== ORACLE MANIPULATION REPORT ===",
            f"Total updates analyzed: {len(df)}",
            f"Anomalies detected: {len(anomalies)}",
            "",
        ]

        for _, row in anomalies.iterrows():
            lines.append(
                f"  [{row.get('protocol', 'unknown')}] "
                f"t={row['timestamp']} | "
                f"price={row['price']:.6f} | "
                f"z={row['zscore']:.2f} | "
                f"risk={row['oracle_risk_score']}"
            )

        return "\n".join(lines)


def main():
    """
    Demo with synthetic data.
    In production, feed this with real oracle data from:
    - Chainlink data feeds (data.chain.link)
    - Ondo's USDYOracleWrapper
    - Protocol-specific oracle contracts
    """
    print("Oracle Manipulation Detector")
    print("=" * 50)

    # Synthetic data for demo
    np.random.seed(42)
    n = 1000
    timestamps = np.arange(n) * 3600  # Hourly
    base_price = 1.0
    prices = base_price + np.random.normal(0, 0.001, n)

    # Inject an anomaly at position 500
    prices[500] = base_price + 0.05  # 5% spike

    df = pd.DataFrame({
        "timestamp": timestamps,
        "price": prices,
        "source": "chainlink",
        "protocol": "ondo_usdy",
    })

    detector = OracleManipulationDetector(z_threshold=3.0)
    result = detector.detect_anomalies(df)

    anomalies = result[result["oracle_risk_score"] > 0]
    print(f"Anomalies found: {len(anomalies)}")
    if not anomalies.empty:
        print(anomalies[["timestamp", "price", "zscore", "oracle_risk_score"]].to_string())

    # Oracle concentration assessment
    protocol_oracles = {
        "ondo_usdy": ["ondo_oracle_wrapper"],  # Single oracle!
        "ondo_ousg": ["ondo_oracle"],  # Single oracle!
        "centrifuge_pool1": ["chainlink", "pyth"],  # Two oracles
    }
    concentration = detector.assess_oracle_concentration(protocol_oracles)
    print("\nOracle Concentration Risk:")
    print(concentration.to_string())

    # Save
    result.to_parquet(PROCESSED_DIR / "oracle_analysis.parquet", index=False)
    print(f"\nSaved to {PROCESSED_DIR / 'oracle_analysis.parquet'}")


if __name__ == "__main__":
    main()   