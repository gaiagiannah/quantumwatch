"""
QuantumWatch - PQC Migration Playbook for RWA Platforms
Generates platform-specific migration recommendations.

Based on:
  - NIST FIPS 203/204/205 (PQC standards)
  - NSA CNSA 2.0 (ML-KEM-1024, ML-DSA-87, LMS/XMSS)
  - Ethereum PQC roadmap (Vitalik, Feb 2026)
  - OpenSSL 3.5 PQC support (Apr 2025)
  - XRP Ledger ML-DSA AlphaNet deployment (first live PQC on major chain)
"""

import json
import pandas as pd
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime

PROCESSED_DIR = Path("data/processed")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class MigrationStep:
    """A single step in the PQC migration plan."""
    phase: str
    action: str
    timeline: str
    effort: str  # "low", "medium", "high"
    dependencies: List[str]
    risk_if_skipped: str


@dataclass
class MigrationPlan:
    """Complete migration plan for a platform."""
    platform: str
    current_state: str
    target_state: str
    steps: List[MigrationStep]
    total_timeline: str
    key_risks: List[str]
    success_metrics: List[str]
    generated: str = field(default_factory=lambda: datetime.now().isoformat())


def generate_ondo_plan() -> MigrationPlan:
    """PQC migration plan for Ondo Finance."""
    steps = [
        MigrationStep(
            phase="Phase 0: Assessment (Now - Q1 2027)",
            action=(
                "Complete cryptographic inventory: all ECDSA usage points, "
                "key management infrastructure, oracle signing, "
                "admin key locations. Map all dependencies."
            ),
            timeline="Q1 2027",
            effort="medium",
            dependencies=["Access to all smart contract source code"],
            risk_if_skipped="Cannot plan migration without complete inventory",
        ),
        MigrationStep(
            phase="Phase 1: Hybrid Deployment (Q2 2027 - Q4 2028)",
            action=(
                "Deploy hybrid signatures (ECDSA + ML-DSA-65) for "
                "new operations. Existing ECDSA signatures remain valid. "
                "Update EIP-712 to support dual signatures. "
                "Deploy ML-KEM-768 for off-chain key exchange."
            ),
            timeline="Q2 2027 - Q4 2028",
            effort="high",
            dependencies=[
                "Ethereum PQC precompile or EIP for ML-DSA",
                "OpenSSL 3.5+ in all off-chain infrastructure",
                "Client wallet support for hybrid signatures",
            ],
            risk_if_skipped="No migration path when CRQC arrives",
        ),
        MigrationStep(
            phase="Phase 2: Admin Key Rotation (Q1 2029 - Q4 2030)",
            action=(
                "Rotate all admin keys to ML-DSA-87. "
                "Implement multi-sig with 3-of-5 PQC keys. "
                "Deploy HSM with PQC support for key storage. "
                "Update blocklist/allowlist management to PQC."
            ),
            timeline="Q1 2029 - Q4 2030",
            effort="high",
            dependencies=["Phase 1 complete", "HSM vendor with PQC support"],
            risk_if_skipped="Admin keys remain quantum-vulnerable",
        ),
        MigrationStep(
            phase="Phase 3: Oracle Upgrade (Q1 2030 - Q4 2031)",
            action=(
                "Migrate USDYOracleWrapper to PQC-signed updates. "
                "Deploy multi-oracle consensus (minimum 3 independent oracles). "
                "Implement timelocked oracle updates (24h delay). "
                "Add oracle anomaly detection (this project's detector)."
            ),
            timeline="Q1 2030 - Q4 2031",
            effort="medium",
            dependencies=["Phase 2 complete", "Additional oracle providers"],
            risk_if_skipped="Oracle remains single-point-of-failure",
        ),
        MigrationStep(
            phase="Phase 4: Full PQC Transition (2032 - 2035)",
            action=(
                "Deprecate ECDSA entirely. All new transactions "
                "require ML-DSA signatures. Old ECDSA transactions "
                "remain valid (backward compatibility). "
                "Update all multi-chain deployments (10+ chains). "
                "Coordinate with Ethereum mainnet PQC hard fork."
            ),
            timeline="2032 - 2035",
            effort="extreme",
            dependencies=[
                "Ethereum mainnet PQC upgrade",
                "All connected chains support PQC",
                "All wallet providers support ML-DSA",
            ],
            risk_if_skipped="Protocol remains vulnerable to quantum attacks",
        ),
    ]

    return MigrationPlan(
        platform="Ondo Finance (USDY, OUSG)",
        current_state="ECDSA secp256k1 for all signatures; single oracle; admin key in smart contract",
        target_state="ML-DSA-87 for all signatures; multi-oracle consensus; PQC HSM for admin keys",
        steps=steps,
        total_timeline="5-8 years (2027-2035)",
        key_risks=[
            "Ethereum PQC hard fork timeline is uncertain",
            "Multi-chain coordination (10+ chains) is complex",
            "Wallet ecosystem must support PQC before full migration",
            "Backward compatibility requirements increase complexity",
        ],
        success_metrics=[
            "100% of new transactions use PQC signatures",
            "Zero ECDSA-only admin operations",
            "Multi-oracle consensus deployed (3+ sources)",
            "HSM with PQC support in production",
            "All multi-chain deployments migrated",
        ],
    )


def generate_securitize_plan() -> MigrationPlan:
    """PQC migration plan for Securitize."""
    steps = [
        MigrationStep(
            phase="Phase 0: Assessment (Now - Q1 2027)",
            action="Cryptographic inventory of all Securitize contracts, admin keys, and off-chain systems.",
            timeline="Q1 2027",
            effort="medium",
            dependencies=[],
            risk_if_skipped="Incomplete migration planning",
        ),
        MigrationStep(
            phase="Phase 1: Admin Key PQC (Q2 2027 - Q4 2028)",
            action=(
                "Priority: migrate admin keys (mint/burn/approve) to ML-DSA-87. "
                "This is the highest-risk component. Deploy 3-of-5 multi-sig "
                "with PQC keys in HSM."
            ),
            timeline="Q2 2027 - Q4 2028",
            effort="high",
            dependencies=["HSM vendor", "Ethereum PQC precompile"],
            risk_if_skipped="Admin key compromise = total protocol compromise",
        ),
        MigrationStep(
            phase="Phase 2: Investor-Facing PQC (2029 - 2032)",
            action=(
                "Migrate investor-facing operations (transfers, approvals) "
                "to hybrid signatures. Coordinate with wallet providers. "
                "Update BUIDL and all other tokenized funds."
            ),
            timeline="2029 - 2032",
            effort="high",
            dependencies=["Phase 1", "Wallet ecosystem readiness"],
            risk_if_skipped="Investor transactions remain quantum-vulnerable",
        ),
        MigrationStep(
            phase="Phase 3: Full Transition (2033 - 2035)",
            action="Complete deprecation of ECDSA. All operations PQC-only.",
            timeline="2033 - 2035",
            effort="extreme",
            dependencies=["Ethereum mainnet PQC upgrade"],
            risk_if_skipped="Protocol remains vulnerable",
        ),
    ]

    return MigrationPlan(
        platform="Securitize (BUIDL, tokenized funds)",
        current_state="ECDSA for all operations; single admin entity controls mint/burn",
        target_state="ML-DSA-87 multi-sig admin; PQC for all investor operations",
        steps=steps,
        total_timeline="6-8 years (2027-2035)",
        key_risks=[
            "Single admin entity is highest-priority target",
            "Institutional investors may resist migration complexity",
            "Multiple tokenized funds increase migration surface",
        ],
        success_metrics=[
            "Admin keys in PQC HSM multi-sig",
            "100% new operations use PQC",
            "All tokenized funds migrated",
        ],
    )


def generate_generic_plan() -> MigrationPlan:
    """Generic PQC migration plan for any RWA platform."""
    steps = [
        MigrationStep(
            phase="Phase 0: Cryptographic Inventory",
            action="Catalog all cryptographic operations: signatures, hashes, key exchange, encryption. Map to components.",
            timeline="0-3 months",
            effort="medium",
            dependencies=[],
            risk_if_skipped="Cannot plan without complete inventory",
        ),
        MigrationStep(
            phase="Phase 1: Risk Prioritization",
            action="Score each component by: (a) quantum vulnerability, (b) data sensitivity duration, (c) blast radius. Prioritize admin keys and identity systems.",
            timeline="3-6 months",
            effort="low",
            dependencies=["Phase 0"],
            risk_if_skipped="Resources wasted on low-risk components",
        ),
        MigrationStep(
            phase="Phase 2: Hybrid Deployment",
            action="Deploy hybrid (classical + PQC) signatures for new operations. Use ML-KEM-768 for key exchange. Maintain backward compatibility.",
            timeline="6-24 months",
            effort="high",
            dependencies=["PQC library support (OpenSSL 3.5+, liboqs)"],
            risk_if_skipped="No migration path when CRQC arrives",
        ),
        MigrationStep(
            phase="Phase 3: Key Rotation",
            action="Rotate all keys to PQC. Implement key rotation schedule. Deploy HSM with PQC support.",
            timeline="24-48 months",
            effort="high",
            dependencies=["Phase 2", "HSM infrastructure"],
            risk_if_skipped="Old keys remain vulnerable",
        ),
        MigrationStep(
            phase="Phase 4: Full Transition",
            action="Deprecate classical crypto. All operations PQC-only. Update documentation and training.",
            timeline="48-72 months",
            effort="extreme",
            dependencies=["Ecosystem-wide PQC support"],
            risk_if_skipped="Protocol remains vulnerable",
        ),
    ]

    return MigrationPlan(
        platform="Generic RWA Platform",
        current_state="ECDSA/SHA-256 (typical)",
        target_state="ML-DSA/ML-KEM (NIST PQC standards)",
        steps=steps,
        total_timeline="4-8 years",
        key_risks=[
            "Ecosystem dependency (wallets, chains, exchanges must all support PQC)",
            "Backward compatibility requirements",
            "No committed timeline from Ethereum for PQC upgrade",
        ],
        success_metrics=[
            "100% new operations use PQC",
            "All admin keys in PQC HSM",
            "Zero classical-only cryptographic operations",
        ],
    )


def save_plans(plans: List[MigrationPlan]):
    """Save all migration plans."""
    for plan in plans:
        output = {
            "platform": plan.platform,
            "current_state": plan.current_state,
            "target_state": plan.target_state,
            "total_timeline": plan.total_timeline,
            "key_risks": plan.key_risks,
            "success_metrics": plan.success_metrics,
            "steps": [
                {
                    "phase": s.phase,
                    "action": s.action,
                    "timeline": s.timeline,
                    "effort": s.effort,
                    "dependencies": s.dependencies,
                    "risk_if_skipped": s.risk_if_skipped,
                }
                for s in plan.steps
            ],
            "generated": plan.generated,
        }

        safe_name = plan.platform.lower().replace(" ", "_").replace("(", "").replace(")", "").replace(",", "")
        path = PROCESSED_DIR / f"migration_{safe_name}.json"
        with open(path, "w") as f:
            json.dump(output, f, indent=2)
        print(f"Saved: {path}")


def main():
    print("Generating PQC Migration Playbooks...")

    plans = [
        generate_ondo_plan(),
        generate_securitize_plan(),
        generate_generic_plan(),
    ]

    for plan in plans:
        print(f"\n{'=' * 50}")
        print(f"PLATFORM: {plan.platform}")
        print(f"Timeline: {plan.total_timeline}")
        print(f"Steps: {len(plan.steps)}")
        for s in plan.steps:
            print(f"  {s.phase}: {s.effort.upper()} effort")

    save_plans(plans)


if __name__ == "__main__":
    main()   