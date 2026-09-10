import math
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class AddressTarget:
    address: str
    secp256k1_value_usd: float
    pubkey_exposed: bool
    gat_anomaly_score: float      # Normalized [0.0 - 1.0]
    trace_anomaly_score: float    # Normalized [0.0 - 1.0]

class QuantumRiskEngine:
    """
    Evaluates quantum cryptographic decay and combines multi-modal anomaly inputs.
    """
    def __init__(
        self,
        target_crqc_year: int = 2033,
        current_year: float = 2026.7,
        lambda_decay: float = 0.15,
        alpha_val: float = 0.6,
        beta_exp: float = 0.4
    ):
        self.t_crqc = target_crqc_year
        self.t_curr = current_year
        self.lambda_decay = lambda_decay
        self.alpha = alpha_val
        self.beta = beta_exp

    def calculate_hndl_score(self, value_usd: float, pubkey_exposed: bool) -> float:
        """Calculates Harvest Now, Decrypt Later (HNDL) cryptographic exposure index."""
        time_delta = max(0.1, self.t_crqc - self.t_curr)
        time_decay = 1.0 / (1.0 - math.exp(-self.lambda_decay * time_delta))
        value_factor = math.log10(value_usd + 1.0) if value_usd > 0 else 0.0
        exposure_factor = 1.0 if pubkey_exposed else 0.0
        
        raw_v = time_decay * (self.alpha * value_factor + self.beta * exposure_factor)
        return min(100.0, round(raw_v, 2))

    def evaluate_target(self, target: AddressTarget) -> Dict[str, Any]:
        """Calculates composite threat score across GAT graph, EVM traces, and quantum risk."""
        hndl_score = self.calculate_hndl_score(target.secp256k1_value_usd, target.pubkey_exposed)
        
        # Weighted composite: 35% GAT, 35% Trace, 30% HNDL
        composite = (0.35 * target.gat_anomaly_score * 100.0) + \
                    (0.35 * target.trace_anomaly_score * 100.0) + \
                    (0.30 * hndl_score)
        composite = round(composite, 2)
        
        if composite >= 75.0:
            risk_tier = "CRITICAL"
        elif composite >= 50.0:
            risk_tier = "HIGH"
        elif composite >= 25.0:
            risk_tier = "MEDIUM"
        else:
            risk_tier = "LOW"

        pqc_needed = target.pubkey_exposed or composite >= 50.0

        return {
            "address": target.address,
            "secp256k1_value_usd": target.secp256k1_value_usd,
            "pubkey_exposed": target.pubkey_exposed,
            "gat_score": round(target.gat_anomaly_score * 100.0, 2),
            "trace_score": round(target.trace_anomaly_score * 100.0, 2),
            "hndl_score": hndl_score,
            "composite_score": composite,
            "risk_tier": risk_tier,
            "pqc_migration_required": pqc_needed,
            "recommended_standard": "NIST FIPS 204 (ML-DSA)" if pqc_needed else "secp256k1 (Standard)"
        }

if __name__ == "__main__":
    engine = QuantumRiskEngine()
    test_target = AddressTarget(
        address="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        secp256k1_value_usd=1_500_000.0,
        pubkey_exposed=True,
        gat_anomaly_score=0.65,
        trace_anomaly_score=0.82
    )
    print("Risk Engine Output:\n", engine.evaluate_target(test_target))