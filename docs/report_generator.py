from datetime import datetime, timezone
from typing import Dict, Any

class ForensicReportGenerator:
    """
    Generates structured Markdown security audit reports from QuantumWatch assessment metrics.
    """
    @staticmethod
    def generate_markdown(assessment: Dict[str, Any]) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        report = f"""# QuantumWatch Forensic Analysis & PQC Audit
**Target Address:** `{assessment['address']}`  
**Scan Timestamp:** `{timestamp}`  
**Composite Threat Level:** **{assessment['composite_score']}/100** (`{assessment['risk_tier']}`)

---

### Executive Summary
| Metric | Assessment Value | Risk Threshold |
| :--- | :--- | :--- |
| **Harvest Now Decrypt Later (HNDL) Index** | `{assessment['hndl_score']}/100` | `< 25.0` |
| **GAT Graph Spatial Anomaly** | `{assessment['gat_score']}%` | `< 15.0%` |
| **EVM Trace Pattern Anomaly** | `{assessment['trace_score']}%` | `< 10.0%` |
| **On-Chain Public Key Exposed** | `{'YES (CRITICAL)' if assessment['pubkey_exposed'] else 'NO'}` | `NO` |
| **PQC Migration Status** | `{'REQUIRED IMMEDIATELY' if assessment['pqc_migration_required'] else 'STANDBY'}` | `STANDBY` |

---

### Cryptographic Vulnerability Assessment
* **Secured Value at Risk:** `${assessment['secp256k1_value_usd']:,.2f}` secured via legacy ECDSA/secp256k1.
* **Target Post-Quantum Standard:** {assessment['recommended_standard']}
* **Quantum Exposure Vector:** {'Public key is publicly exposed via outbound transaction signature. ECDSA key exchange is vulnerable to Shor\'s algorithm on a CRQC.' if assessment['pubkey_exposed'] else 'Public key remains unexposed (address hash protection active).'}

---

### Actionable Remediation Steps
1. **Signature Migration:** {'Initiate immediate migration of funds to a Post-Quantum Cryptography (PQC) vault supporting NIST FIPS 204 (ML-DSA).' if assessment['pqc_migration_required'] else 'Maintain standard operational security; monitor for unintended outbound signature exposures.'}
2. **Timelock & Proxy Governance:** Audit cross-chain bridge controls and multisig timelocks against signature spoofing vectors.
3. **Continuous Monitoring:** Keep address queued in QuantumWatch GNN mempool monitoring pipelines.
"""
        return report

if __name__ == "__main__":
    from src.quantum_risk import QuantumRiskEngine, AddressTarget
    
    engine = QuantumRiskEngine()
    test_target = AddressTarget(
        address="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        secp256k1_value_usd=1_500_000.0,
        pubkey_exposed=True,
        gat_anomaly_score=0.65,
        trace_anomaly_score=0.82
    )
    result = engine.evaluate_target(test_target)
    
    generator = ForensicReportGenerator()
    print(generator.generate_markdown(result))