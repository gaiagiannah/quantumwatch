import argparse
import json
import sys
from src.quantum_risk import QuantumRiskEngine, AddressTarget
from src.report_generator import ForensicReportGenerator
from src.chain_fetcher import ChainFetcher
from src.alert_dispatcher import AlertDispatcher

def main():
    parser = argparse.ArgumentParser(description="QuantumWatch Automated CLI Forensic Audit Engine")
    parser.add_argument("--address", type=str, required=True, help="Target EVM Address")
    parser.add_argument("--chain", type=str, default="ethereum", choices=["ethereum", "base", "arbitrum"], help="Target EVM Network")
    parser.add_argument("--live", action="store_true", help="Fetch balance and sanctions live from RPC")
    parser.add_argument("--value-usd", type=float, default=0.0, help="Secured USD Value (if not using --live)")
    parser.add_argument("--pubkey-exposed", action="store_true", help="Set if public key is exposed (if not using --live)")
    parser.add_argument("--gat-score", type=float, default=0.1, help="GAT anomaly score [0.0 - 1.0]")
    parser.add_argument("--trace-score", type=float, default=0.1, help="EVM trace anomaly score [0.0 - 1.0]")
    parser.add_argument("--out-report", type=str, default="", help="Path to save Markdown report")
    parser.add_argument("--out-sar", type=str, default="", help="Path to save SAR/STR compliance filing")
    parser.add_argument("--webhook", type=str, default="", help="Webhook URL for immediate threat alerts")

    args = parser.parse_args()

    # Build target
    if args.live:
        print(f"[*] Fetching live network data on [{args.chain.upper()}] for `{args.address}`...")
        fetcher = ChainFetcher(chain=args.chain)
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
    print(f"   QUANTUMWATCH AUDIT RESULTS ({args.chain.upper()})")
    print("==========================================")
    print(json.dumps(assessment, indent=2))

    # Reports
    if args.out_report:
        md = ForensicReportGenerator.generate_markdown(assessment)
        with open(args.out_report, "w") as f:
            f.write(md)
        print(f"\n[+] Audit report written to: {args.out_report}")

    if args.out_sar:
        sar = ForensicReportGenerator.generate_sar_template(assessment)
        with open(args.out_sar, "w") as f:
            f.write(sar)
        print(f"[+] SAR filing written to: {args.out_sar}")

    # Dispatch Alert
    if args.webhook or assessment['composite_score'] >= 75.0:
        dispatcher = AlertDispatcher(webhook_url=args.webhook)
        dispatcher.send_alert(assessment)

if __name__ == "__main__":
    main()