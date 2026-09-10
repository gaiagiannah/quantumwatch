import argparse
import json
import sys
from src.quantum_risk import QuantumRiskEngine, AddressTarget
from src.report_generator import ForensicReportGenerator

def main():
    parser = argparse.ArgumentParser(
        description="QuantumWatch Automated CLI Forensic Audit Engine"
    )
    parser.add_argument("--address", type=str, required=True, help="Target EVM Address")
    parser.add_argument("--value-usd", type=float, default=0.0, help="Secured Capital Value (USD)")
    parser.add_argument("--pubkey-exposed", action="store_true", help="Set if public key is exposed on-chain")
    parser.add_argument("--gat-score", type=float, default=0.0, help="GAT anomaly score [0.0 - 1.0]")
    parser.add_argument("--trace-score", type=float, default=0.0, help="EVM trace anomaly score [0.0 - 1.0]")
    parser.add_argument("--out-report", type=str, default="", help="Path to write Markdown security report")

    args = parser.parse_args()

    # Initialize Engine & Evaluate
    engine = QuantumRiskEngine()
    target = AddressTarget(
        address=args.address,
        secp256k1_value_usd=args.value_usd,
        pubkey_exposed=args.pubkey_exposed,
        gat_anomaly_score=args.gat_score,
        trace_anomaly_score=args.trace_score
    )

    assessment = engine.evaluate_target(target)

    print("\n==========================================")
    print("      QUANTUMWATCH FORENSIC RESULTS       ")
    print("==========================================")
    print(json.dumps(assessment, indent=2))

    # Save Markdown report if path provided
    if args.out_report:
        md = ForensicReportGenerator.generate_markdown(assessment)
        with open(args.out_report, "w") as f:
            f.write(md)
        print(f"\n[+] Audit report saved to: {args.out_report}")

    # Fail CI/CD build if Threat Level is CRITICAL
    if assessment['composite_score'] >= 75.0:
        print("\n[!] CRITICAL THREAT DETECTED. CI/CD Pipeline Execution Failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()