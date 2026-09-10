import os
import requests
from typing import Tuple, Dict, Any
from src.quantum_risk import AddressTarget

class ChainFetcher:
    """
    Fetches real-time on-chain data for EVM targets using Web3 RPC endpoints & Etherscan API.
    """
    def __init__(self, rpc_url: str = "https://eth.llamarpc.com", etherscan_api_key: str = ""):
        self.rpc_url = rpc_url
        self.etherscan_key = etherscan_api_key or os.getenv("ETHERSCAN_API_KEY", "")

    def get_eth_price_usd(self) -> float:
        """Fetches current ETH/USD spot price from CoinGecko API."""
        try:
            url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"
            resp = requests.get(url, timeout=5).json()
            return float(resp["ethereum"]["usd"])
        except Exception:
            return 3000.0  # Fallback estimate if rate-limited

    def fetch_address_metrics(self, address: str) -> Tuple[float, bool]:
        """
        Queries Ethereum node via RPC:
        - Retrieves address ETH balance and converts to USD.
        - Checks transaction count (nonce). If nonce > 0, outbound signature exists,
          meaning the public key is exposed on-chain.
        """
        # 1. Fetch ETH Balance
        payload_bal = {
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [address, "latest"],
            "id": 1
        }
        res_bal = requests.post(self.rpc_url, json=payload_bal, timeout=10).json()
        wei_val = int(res_bal.get("result", "0x0"), 16)
        eth_val = wei_val / 1e18
        
        eth_price = self.get_eth_price_usd()
        value_usd = eth_val * eth_price

        # 2. Check Outbound Tx Nonce (Public Key Exposure Check)
        payload_nonce = {
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [address, "latest"],
            "id": 2
        }
        res_nonce = requests.post(self.rpc_url, json=payload_nonce, timeout=10).json()
        nonce = int(res_nonce.get("result", "0x0"), 16)

        # If nonce > 0, an outbound ECDSA transaction signature has been broadcasted
        pubkey_exposed = nonce > 0

        return value_usd, pubkey_exposed

    def build_target(
        self,
        address: str,
        gat_score: float = 0.1,
        trace_score: float = 0.1
    ) -> AddressTarget:
        """Constructs an AddressTarget object using live on-chain data."""
        value_usd, pubkey_exposed = self.fetch_address_metrics(address)
        return AddressTarget(
            address=address,
            secp256k1_value_usd=round(value_usd, 2),
            pubkey_exposed=pubkey_exposed,
            gat_anomaly_score=gat_score,
            trace_anomaly_score=trace_score
        )

if __name__ == "__main__":
    fetcher = ChainFetcher()
    # Test fetch on Vitalik Buterin's public ENS address
    test_address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    target = fetcher.build_target(test_address)
    print("Live Target Fetched:")
    print(f"Address: {target.address}")
    print(f"Secured Value (USD): ${target.secp256k1_value_usd:,.2f}")
    print(f"Public Key Exposed: {target.pubkey_exposed}")