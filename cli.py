import argparse
import json
import sys
from src.quantum_risk import QuantumRiskEngine, AddressTarget
from src.report_generator import ForensicReportGenerator
from src.chain_fetcher import ChainFetcher

def main():
    parser = argparse.ArgumentParser(description="QuantumWatch Automated CLI Forensic Audit Engine")
    parser.add_argument("--address", type=str, required=True, help="Target EVM Address")
    parser.add_argument("--live", action="store_true", help="Fetch balance and public key exposure live from RPC")
    parser.add_argument("--value-usd", type=float, default=0.0, help="Secured USD Value (if not using --live)")
    parser.add_argument("--pubkey-exposed", action="store_true", help="Set if public key is exposed (if not using --live)")
    parser.add_argument("--gat-score", type=float, default=0.1, help="GAT anomaly score [0.0 - 1.0]")
    parser.add_argument("--trace-score", type=float, default=0.1, help="EVM trace anomaly score [0.0 - 1.0]")
    parser.add_argument("--out-report", type=str, default="", help="Path to save Markdown report")

    args = parser.parse_args()

    # Build target from live RPC or manual flags
    if args.live:
        print(f"[*] Fetching live network data for `{args.address}`...")
        fetcher = ChainFetcher()
        target = fetcher.build_target(args.address, args.gat_score, args.trace_score)
    else:
        target = AddressTarget(
            address=args.address,
            secp256k1_value_usd=args.value_usd,
            pubkey_exposed=args.pubkey_exposed,
            gat_anomaly_score=args.gat_score,
            trace_anomaly_score=args.trace_score
        )

    # Evaluate
    engine = QuantumRiskEngine()
    assessment = engine.evaluate_target(target)

    print("\n==========================================")
    print("      QUANTUMWATCH FORENSIC RESULTS       ")
    print("==========================================")
    print(json.dumps(assessment, indent=2))

    if args.out_report:
        md = ForensicReportGenerator.generate_markdown(assessment)
        with open(args.out_report, "w") as f:
            f.write(md)
        print(f"\n[+] Audit report written to: {args.out_report}")

if __name__ == "__main__":
    main()