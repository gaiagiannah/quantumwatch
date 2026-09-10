"""
QuantumWatch - Harvest-Now-Decrypt-Later (HNDL) Risk Model
Models the HNDL attack vector specific to blockchain and tokenized RWA.

The unique blockchain HNDL risk:
  - All transaction data is PUBLIC and PERMANENT
  - Unlike TLS (where data is encrypted in transit), blockchain
    stores everything in cleartext on a public ledger
  - The "harvest" is already happening: anyone can read the chain
  - The "decrypt" applies to:
    a) Data that was encrypted with ECDSA/ECDH and stored on-chain
    b) Off-chain data whose security depends on on-chain keys
    c) RWA investor identity data tied to wallet addresses

Reference: Federal Reserve Analysis (Sept 2025)
"""

import json
import pandas as pd
from pathlib import Path
from dataclasses import dataclass
from typing import List
from datetime import datetime

PROCESSED_DIR = Path("data/processed")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class HNDLVector:
    """A specific HNDL attack vector."""
    name: str
    description: str
    data_exposed: str
    sensitivity_duration: str  # How long the data remains sensitive
    current_exposure: str  # What's exposed today
    crqc_impact: str  # What changes when CRQC arrives
    mitigation: str
    risk_score: float  # 1-10


def get_hndl_vectors() -> List[HNDLVector]:
    """Define all HNDL vectors for tokenized RWA."""
    return [
        HNDLVector(
            name="Wallet Address Identity Correlation",
            description=(
                "Blockchain addresses are pseudonymous but persistent. "
                "An adversary records the mapping between wallet addresses "
                "and real-world identities (via exchange KYC leaks, "
                "social media, court records) TODAY. When CRQC arrives, "
                "they can retroactively link all historical transactions "
                "to specific individuals."
            ),
            data_exposed="All historical transaction records (public, permanent)",
            sensitivity_duration="Permanent (blockchain is immutable)",
            current_exposure=(
                "Address-to-identity mappings already exist in "
                "Chainalysis, Elliptic, TRM Labs databases. "
                "Exchange KYC data is the critical link."
            ),
            crqc_impact=(
                "CRQC enables forging transaction signatures, "
                "which breaks the pseudonymity assumption entirely. "
                "An adversary could prove which wallet belongs to whom "
                "by forging a signature that only the real key holder could make."
            ),
            mitigation=(
                "Use fresh addresses per transaction (breaks correlation). "
                "Deploy PQC signatures before CRQC. "
                "Regulatory: require data minimization in KYC storage."
            ),
            risk_score=8.5,
        ),
        HNDLVector(
            name="RWA Investor Privacy",
            description=(
                "Tokenized RWA platforms (especially ERC-1400/3643) "
                "store investor identity on-chain or link it to on-chain "
                "tokens. An adversary who records the token-to-investor "
                "mapping today can, after CRQC, retroactively expose "
                "the full investment history of any individual."
            ),
            data_exposed="Investor identities, purchase history, holding periods, redemption patterns",
            sensitivity_duration="5-20 years (investment records have long sensitivity)",
            current_exposure=(
                "On-chain token balances are public. "
                "ERC-1400/3643 identity registries link addresses to KYC data. "
                "Off-chain: platform databases hold full investor info."
            ),
            crqc_impact=(
                "CRQC enables forging identity attestations, "
                "allowing an adversary to impersonate any investor "
                "and access their RWA holdings."
            ),
            mitigation=(
                "Use zero-knowledge proofs for identity verification "
                "(don't store identity on-chain). "
                "Deploy PQC for identity signatures. "
                "Encrypt off-chain investor data with PQC KEM."
            ),
            risk_score=9.0,
        ),
        HNDLVector(
            name="Oracle Data Integrity",
            description=(
                "Oracle price feeds are signed with ECDSA. An adversary "
                "records all historical oracle updates TODAY. After CRQC, "
                "they could forge oracle updates, retroactively altering "
                "the price history and triggering wrongful liquidations "
                "or enabling profitable backdated trades."
            ),
            data_exposed="All historical oracle price updates and their signatures",
            sensitivity_duration="Permanent (price history is used for dispute resolution)",
            current_exposure=(
                "All oracle updates are public on-chain. "
                "Signatures are ECDSA (quantum-vulnerable). "
                "Ondo's USDYOracleWrapper is a single point of failure."
            ),
            crqc_impact=(
                "CRQC allows forging oracle signatures, "
                "enabling retroactive price manipulation. "
                "All historical DeFi positions could be disputed."
            ),
            mitigation=(
                "Deploy PQC-signed oracle updates. "
                "Use multi-oracle consensus (reduce single-source risk). "
                "Implement timelocked oracle updates."
            ),
            risk_score=7.5,
        ),
        HNDLVector(
            name="Smart Contract Admin Keys",
            description=(
                "RWA protocol admin keys (upgrade, pause, mint) are "
                "ECDSA. An adversary records the public admin key TODAY. "
                "After CRQC, they derive the private key and gain "
                "full control of the protocol, including all RWA tokens."
            ),
            data_exposed="Admin public keys (public), all protocol state",
            sensitivity_duration="Until key rotation (typically never in practice)",
            current_exposure=(
                "Admin keys are embedded in smart contracts. "
                "Public key is visible on-chain. "
                "No rotation mechanism in most RWA protocols."
            ),
            crqc_impact=(
                "CRQC derives private key from public key. "
                "Attacker gains full protocol control: "
                "mint unlimited tokens, drain reserves, "
                "disable all safeguards."
            ),
            mitigation=(
                "Use multi-sig with PQC keys. "
                "Implement timelocked upgrades. "
                "Use hardware security modules. "
                "Plan for PQC key rotation before CRQC."
            ),
            risk_score=9.5,
        ),
        HNDLVector(
            name="Cross-Chain Bridge State",
            description=(
                "Bridge contracts maintain state across chains. "
                "The state is signed with ECDSA. An adversary records "
                "bridge state TODAY. After CRQC, they forge bridge "
                "messages, enabling double-spending across all connected chains."
            ),
            data_exposed="All bridge transaction history and state commitments",
            sensitivity_duration="Permanent (bridge state is cumulative)",
            current_exposure=(
                "Bridge contracts are public. "
                "State transitions are signed with ECDSA. "
                "Multi-chain RWA (Ondo on 10+ chains) increases exposure."
            ),
            crqc_impact=(
                "CRQC enables forging bridge messages. "
                "An attacker could mint unlimited tokens on any "
                "connected chain, draining all bridged RWA assets."
            ),
            mitigation=(
                "Deploy PQC-signed bridge messages. "
                "Use light client verification (reduce trust in signatures). "
                "Limit bridge TVL. "
                "Implement circuit breakers for anomalous bridge activity."
            ),
            risk_score=8.8,
        ),
    ]


def compute_risk_matrix(vectors: List[HNDLVector]) -> pd.DataFrame:
    """Create a risk matrix for the HNDL vectors."""
    df = pd.DataFrame([
        {
            "vector": v.name,
            "risk_score": v.risk_score,
            "sensitivity": v.sensitivity_duration,
            "current_exposure": "HIGH" if v.risk_score >= 8 else "MEDIUM",
            "crqc_impact": "CRITICAL" if v.risk_score >= 9 else "HIGH",
        }
        for v in vectors
    ])
    df = df.sort_values("risk_score", ascending=False)
    return df


def generate_report(vectors: List[HNDLVector]) -> str:
    """Generate the HNDL risk report."""
    lines = [
        "=" * 60,
        "HARVEST-NOW-DECRYPT-LATER (HNDL) RISK REPORT",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "=" * 60,
        "",
        "EXECUTIVE SUMMARY",
        "-" * 40,
        f"Total HNDL vectors identified: {len(vectors)}",
        f"Critical risk (score >= 9): {sum(1 for v in vectors if v.risk_score >= 9)}",
        f"High risk (score 7-9): {sum(1 for v in vectors if 7 <= v.risk_score < 9)}",
        "",
        "The blockchain HNDL threat is UNIQUE compared to traditional "
        "cryptography because:",
        "  1. All data is PUBLIC (no 'harvest' step needed for on-chain data)",
        "  2. All data is PERMANENT (immutable ledger = infinite sensitivity)",
        "  3. Pseudonymity is the only privacy layer (and it's breaking)",
        "",
        "TIMELINE RISK",
        "-" * 40,
        "Google Quantum AI (Mar 2026): <500K physical qubits for ECC-256",
        "Current best estimate for CRQC: 2030-2040 (high uncertainty)",
        "NSA CNSA 2.0: Pure PQC required by 2035 for US national security",
        "Ethereum PQC migration: No committed timeline (Vitalik, Feb 2026)",
        "",
        "RECOMMENDATION: Treat the HNDL threat as ACTIVE NOW. "
        "Any RWA data with >5 year sensitivity is already at risk.",
        "",
    ]

    for v in sorted(vectors, key=lambda x: x.risk_score, reverse=True):
        lines.append(f"\n{'─' * 50}")
        lines.append(f"VECTOR: {v.name} (Risk: {v.risk_score}/10)")
        lines.append(f"  Description: {v.description}")
        lines.append(f"  Data Exposed: {v.data_exposed}")
        lines.append(f"  Sensitivity: {v.sensitivity_duration}")
        lines.append(f"  Current Exposure: {v.current_exposure}")
        lines.append(f"  CRQC Impact: {v.crqc_impact}")
        lines.append(f"  Mitigation: {v.mitigation}")

    return "\n".join(lines)


def main():
    print("Computing HNDL Risk Model...")
    vectors = get_hndl_vectors()

    # Risk matrix
    matrix = compute_risk_matrix(vectors)
    print("\n=== HNDL RISK MATRIX ===")
    print(matrix.to_string())

    # Full report
    report = generate_report(vectors)
    print(report)

    # Save
    report_path = PROCESSED_DIR / "hndl_report.txt"
    with open(report_path, "w") as f:
        f.write(report)

    matrix_path = PROCESSED_DIR / "hndl_risk_matrix.csv"
    matrix.to_csv(matrix_path, index=False)

    # JSON
    json_path = PROCESSED_DIR / "hndl_vectors.json"
    with open(json_path, "w") as f:
        json.dump([vars(v) for v in vectors], f, indent=2, default=str)

    print(f"\nSaved: {report_path}, {matrix_path}, {json_path}")


if __name__ == "__main__":
    main()   