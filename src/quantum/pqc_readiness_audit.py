"""
QuantumWatch - Post-Quantum Cryptography Readiness Audit
Audits major RWA token standards and protocols for quantum vulnerability.

Key findings framework:
  - What signature scheme does each standard use?
  - What hash functions are deployed?
  - What is the quantum vulnerability?
  - What is the PQC migration path?
  - What is the risk score?

References:
  - NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
  - Google Quantum AI Whitepaper (Mar 2026): <500K qubits for ECC-256
  - Federal Reserve Analysis (Sept 2025): HNDL risk for blockchain
  - Ethereum Post-Quantum Roadmap (Vitalik, Feb 2026)
"""

import json
import pandas as pd
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime

PROCESSED_DIR = Path("data/processed")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class CryptoComponent:
    """A single cryptographic component in a system."""
    name: str
    algorithm: str
    type: str  # "signature", "key_exchange", "hash", "encryption"
    standard: str  # e.g., "ECDSA secp256k1", "SHA-256"
    quantum_vulnerable: bool
    vulnerability_description: str
    pqc_replacement: str
    migration_difficulty: str  # "low", "medium", "high", "extreme"
    notes: str = ""


@dataclass
class PlatformAudit:
    """Audit result for a single RWA platform/standard."""
    platform: str
    token_standard: str
    components: List[CryptoComponent]
    overall_risk_score: float  # 1-10
    risk_factors: List[str]
    migration_timeline: str
    recommendations: List[str]
    audit_date: str = field(default_factory=lambda: datetime.now().isoformat())


# --- Component Definitions ---

def get_ethereum_components() -> List[CryptoComponent]:
    """Cryptographic components in Ethereum (affects all EVM-based RWA)."""
    return [
        CryptoComponent(
            name="Transaction Signature",
            algorithm="ECDSA secp256k1",
            type="signature",
            standard="EIP-155 / EIP-1559",
            quantum_vulnerable=True,
            vulnerability_description=(
                "Shor's algorithm on a CRQC breaks secp256k1 discrete log. "
                "Google (Mar 2026) estimates <500K physical qubits. "
                "All transaction signatures become forgeable."
            ),
            pqc_replacement="ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)",
            migration_difficulty="extreme",
            notes=(
                "Requires hard fork. Affects every transaction ever made. "
                "Ethereum roadmap (Vitalik, Feb 2026) identifies this as "
                "priority area 1. No timeline committed."
            ),
        ),
        CryptoComponent(
            name="Account Identity (Address)",
            algorithm="Keccak-256 (SHA-3 variant) of public key",
            type="hash",
            standard="EIP-55 (checksum)",
            quantum_vulnerable=False,
            vulnerability_description=(
                "SHA-256/Keccak-256 is quantum-resistant (Grover's gives "
                "only square-root speedup: 2^128 effective security). "
                "Address derivation is safe."
            ),
            pqc_replacement="None needed (SHA-256 is quantum-safe)",
            migration_difficulty="low",
            notes="Address format unchanged. Only the signature scheme changes.",
        ),
        CryptoComponent(
            name="Smart Contract Storage (SSTORE)",
            algorithm="SHA-256 (Merkle tree commitments)",
            type="hash",
            standard="EIP-2200 (net gas metering)",
            quantum_vulnerable=False,
            vulnerability_description=(
                "Hash-based storage commitments are quantum-resistant. "
                "State root integrity is maintained."
            ),
            pqc_replacement="None needed",
            migration_difficulty="low",
        ),
        CryptoComponent(
            name="Beacon Chain (Consensus)",
            algorithm="BLS12-381 (pairing-based signatures)",
            type="signature",
            standard="EIP-2537 (BLS precompile)",
            quantum_vulnerable=True,
            vulnerability_description=(
                "BLS signatures on BLS12-381 are vulnerable to Shor's. "
                "A CRQC could forge validator signatures, enabling "
                "consensus attacks on the Beacon Chain."
            ),
            pqc_replacement="ML-DSA-87 (FIPS 204) for validator signatures",
            migration_difficulty="extreme",
            notes=(
                "Requires consensus change. All 1M+ validators must "
                "migrate keys. Coordinated upgrade required."
            ),
        ),
        CryptoComponent(
            name="EIP-712 Typed Data (Off-chain Signing)",
            algorithm="ECDSA secp256k1",
            type="signature",
            standard="EIP-712",
            quantum_vulnerable=True,
            vulnerability_description=(
                "Used for RWA token approvals, transfer authorizations, "
                "and off-chain attestations. Same vulnerability as "
                "transaction signatures."
            ),
            pqc_replacement="ML-DSA-65 with new EIP for PQC typed data",
            migration_difficulty="high",
            notes="Critical for RWA: all token approvals use EIP-712.",
        ),
    ]


def get_erc20_components() -> List[CryptoComponent]:
    """Additional components specific to ERC-20 (used by Ondo USDY/OUSG)."""
    return [
        CryptoComponent(
            name="ERC-20 Transfer Authorization",
            algorithm="ECDSA secp256k1 (via EIP-712)",
            type="signature",
            standard="ERC-20 approve() + EIP-712",
            quantum_vulnerable=True,
            vulnerability_description=(
                "Token approvals (allowances) are signed with ECDSA. "
                "A CRQC could forge approvals, enabling unauthorized "
                "token transfers from any wallet."
            ),
            pqc_replacement="ML-DSA-65 signed approvals",
            migration_difficulty="high",
            notes=(
                "All existing approvals remain valid until revoked. "
                "Migration requires re-approval by all token holders."
            ),
        ),
        CryptoComponent(
            name="Blocklist / Allowlist (Ondo-specific)",
            algorithm="On-chain storage (no crypto)",
            type="access_control",
            standard="Ondo Blocklist contract",
            quantum_vulnerable=False,
            vulnerability_description=(
                "Access control is via on-chain storage, not crypto. "
                "Not quantum-vulnerable, but the admin key that "
                "manages the blocklist IS vulnerable (ECDSA)."
            ),
            pqc_replacement="ML-DSA-65 for admin signatures",
            migration_difficulty="medium",
            notes="Ondo USDY Blocklist: 0xd8c8174691d936E2C80114EC449037b13421B0a8",
        ),
    ]


def get_erc1400_components() -> List[CryptoComponent]:
    """Components specific to ERC-1400 (security tokens, used by some RWA)."""
    return [
        CryptoComponent(
            name="ERC-1400 Identity Verification",
            algorithm="ERC-1400 on-chain identity + ECDSA",
            type="identity",
            standard="ERC-1400 (Security Token Standard)",
            quantum_vulnerable=True,
            vulnerability_description=(
                "Identity verification relies on ECDSA-signed identity "
                "documents. A CRQC could forge investor identity proofs, "
                "bypassing KYC/AML controls."
            ),
            pqc_replacement="ML-DSA-65 signed identity documents",
            migration_difficulty="high",
            notes="Affects all ERC-1400 compliant RWA tokens.",
        ),
        CryptoComponent(
            name="ERC-1400 Transfer Restrictions",
            algorithm="On-chain logic + ECDSA (admin)",
            type="access_control",
            standard="ERC-1400 (restricted transfers)",
            quantum_vulnerable=True,
            vulnerability_description=(
                "Transfer restriction enforcement depends on admin "
                "signatures for allowlist updates. Compromise of admin "
                "key via quantum attack could disable all restrictions."
            ),
            pqc_replacement="ML-DSA-87 for admin operations",
            migration_difficulty="medium",
        ),
    ]


def get_erc3643_components() -> List[CryptoComponent]:
    """Components specific to ERC-3643 (Tokeny standard)."""
    return [
        CryptoComponent(
            name="ERC-3643 Identity Registry",
            algorithm="ERC-3643 DID + ECDSA",
            type="identity",
            standard="ERC-3643 (Tokeny)",
            quantum_vulnerable=True,
            vulnerability_description=(
                "Decentralized Identity (DID) verification uses ECDSA. "
                "Quantum attack could forge investor identities across "
                "all ERC-3643 tokens."
            ),
            pqc_replacement="ML-DSA-65 for DID signatures",
            migration_difficulty="high",
        ),
        CryptoComponent(
            name="ERC-3643 Compliance Engine",
            algorithm="On-chain + off-chain (ECDSA for attestations)",
            type="compliance",
            standard="ERC-3643",
            quantum_vulnerable=True,
            vulnerability_description=(
                "Compliance attestations (KYC, AML, sanctions) are "
                "signed off-chain and verified on-chain. Quantum attack "
                "could forge compliance attestations."
            ),
            pqc_replacement="ML-DSA-65 for attestation signatures",
            migration_difficulty="high",
        ),
    ]


# --- Platform Audits ---

def audit_ondo() -> PlatformAudit:
    """Audit Ondo Finance (USDY, OUSG)."""
    components = get_ethereum_components() + get_erc20_components()

    risk_factors = [
        "Single oracle dependency (USDYOracleWrapper)",
        "ECDSA for all transaction signatures",
        "EIP-712 for all token approvals",
        "Multi-chain deployment increases attack surface",
        "Blocklist managed by single admin key",
    ]

    recommendations = [
        "Monitor Ethereum PQC roadmap for signature scheme changes",
        "Implement hardware security modules (HSM) for admin keys as interim protection",
        "Diversify oracle sources to reduce single-point-of-failure risk",
        "Plan for ML-DSA-65 migration of EIP-712 approvals",
        "Conduct annual PQC readiness assessment",
    ]

    return PlatformAudit(
        platform="Ondo Finance",
        token_standard="ERC-20 (USDY, OUSG)",
        components=components,
        overall_risk_score=7.2,
        risk_factors=risk_factors,
        migration_timeline="2030-2035 (dependent on Ethereum hard fork)",
        recommendations=recommendations,
    )


def audit_securitize() -> PlatformAudit:
    """Audit Securitize (BUIDL and other tokenized funds)."""
    components = get_ethereum_components() + get_erc20_components() + [
        CryptoComponent(
            name="Securitize Transfer Agent",
            algorithm="ECDSA (proprietary smart contract)",
            type="access_control",
            standard="Securitize proprietary",
            quantum_vulnerable=True,
            vulnerability_description=(
                "Transfer agent operations (mint, burn, approve) are "
                "gated by Securitize's admin keys. Quantum compromise "
                "of these keys would allow unauthorized token creation."
            ),
            pqc_replacement="ML-DSA-87 for admin operations",
            migration_difficulty="high",
        ),
    ]

    return PlatformAudit(
        platform="Securitize (BUIDL)",
        token_standard="ERC-20 (Securitize wrapper)",
        components=components,
        overall_risk_score=7.5,
        risk_factors=[
            "Admin key concentration (single entity controls mint/burn)",
            "ECDSA for all operations",
            "Institutional investor base increases impact of compromise",
            "No public PQC migration plan",
        ],
        migration_timeline="2030-2035",
        recommendations=[
            "Implement multi-signature with PQC-capable keys",
            "Publish PQC migration roadmap",
            "Use HSM with PQC support for admin keys",
        ],
    )


def audit_erc1400_platforms() -> PlatformAudit:
    """Audit generic ERC-1400 security token platforms."""
    components = get_ethereum_components() + get_erc1400_components()

    return PlatformAudit(
        platform="ERC-1400 Security Token Platforms",
        token_standard="ERC-1400",
        components=components,
        overall_risk_score=7.8,
        risk_factors=[
            "Identity verification fully dependent on ECDSA",
            "Transfer restrictions can be disabled via admin key compromise",
            "Regulatory compliance depends on cryptographic integrity",
            "No standardized PQC migration path for ERC-1400",
        ],
        migration_timeline="2032-2038",
        recommendations=[
            "ERC-1400 v2 should mandate PQC-capable identity schemes",
            "Implement threshold signatures as interim protection",
            "Regulators should require PQC migration plans for security tokens",
        ],
    )


def audit_erc3643_platforms() -> PlatformAudit:
    """Audit ERC-3643 (Tokeny) platforms."""
    components = get_ethereum_components() + get_erc3643_components()

    return PlatformAudit(
        platform="ERC-3643 (Tokeny) Platforms",
        token_standard="ERC-3643",
        components=components,
        overall_risk_score=7.6,
        risk_factors=[
            "DID system vulnerable to quantum identity forgery",
            "Compliance attestations depend on ECDSA",
            "Cross-border operations increase regulatory exposure",
            "180+ jurisdictions affected",
        ],
        migration_timeline="2030-2035",
        recommendations=[
            "Tokeny should publish PQC migration guide for ERC-3643",
            "DID implementations should support ML-DSA-65",
            "Compliance engines should use hybrid signatures during transition",
        ],
    )


def run_full_audit() -> List[PlatformAudit]:
    """Run the complete PQC readiness audit."""
    print("=" * 60)
    print("QUANTUMWATCH - PQC READINESS AUDIT")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d')}")
    print("=" * 60)

    audits = [
        audit_ondo(),
        audit_securitize(),
        audit_erc1400_platforms(),
        audit_erc3643_platforms(),
    ]

    for audit in audits:
        print(f"\n{'─' * 50}")
        print(f"PLATFORM: {audit.platform}")
        print(f"Standard: {audit.token_standard}")
        print(f"Risk Score: {audit.overall_risk_score}/10")
        print(f"Components: {len(audit.components)}")
        print(f"Migration Timeline: {audit.migration_timeline}")
        print(f"\n  Risk Factors:")
        for f in audit.risk_factors:
            print(f"    - {f}")
        print(f"\n  Recommendations:")
        for r in audit.recommendations:
            print(f"    - {r}")

    return audits


def save_audit(audits: List[PlatformAudit]):
    """Save audit results to JSON and CSV."""
    # JSON (full detail)
    output = []
    for audit in audits:
        output.append({
            "platform": audit.platform,
            "token_standard": audit.token_standard,
            "risk_score": audit.overall_risk_score,
            "risk_factors": audit.risk_factors,
            "migration_timeline": audit.migration_timeline,
            "recommendations": audit.recommendations,
            "audit_date": audit.audit_date,
            "components": [
                {
                    "name": c.name,
                    "algorithm": c.algorithm,
                    "type": c.type,
                    "quantum_vulnerable": c.quantum_vulnerable,
                    "pqc_replacement": c.pqc_replacement,
                    "migration_difficulty": c.migration_difficulty,
                }
                for c in audit.components
            ],
        })

    path = PROCESSED_DIR / "pqc_audit.json"
    with open(path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nFull audit saved to {path}")

    # CSV (summary)
    df = pd.DataFrame([
        {
            "platform": a.platform,
            "standard": a.token_standard,
            "risk_score": a.overall_risk_score,
            "vulnerable_components": sum(1 for c in a.components if c.quantum_vulnerable),
            "total_components": len(a.components),
            "migration_timeline": a.migration_timeline,
        }
        for a in audits
    ])
    csv_path = PROCESSED_DIR / "pqc_audit_summary.csv"
    df.to_csv(csv_path, index=False)
    print(f"Summary saved to {csv_path}")
    print(df.to_string())


if __name__ == "__main__":
    audits = run_full_audit()
    save_audit(audits)   