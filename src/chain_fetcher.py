import os
import requests
from typing import Tuple, Dict, Any
from src.quantum_risk import AddressTarget

class ChainFetcher:
    """
    Fetches real-time on-chain data across Ethereum Mainnet, Base, and Arbitrum.
    """
    SUPPORTED_CHAINS = {
        "ethereum": {
            "rpc": "https://eth.llamarpc.com",
            "chain_id": 1,
            "sanctions_oracle": "0x40C57923924B5c5c5455c48D93317139ADDaC8fb"
        },
        "base": {
            "rpc": "https://mainnet.base.org",
            "chain_id": 8453,
            "sanctions_oracle": None
        },
        "arbitrum": {
            "rpc": "https://arb1.arbitrum.io/rpc",
            "chain_id": 42161,
            "sanctions_oracle": None
        }
    }

    def __init__(self, chain: str = "ethereum", custom_rpc: str = ""):
        self.chain = chain.lower()
        if self.chain not in self.SUPPORTED_CHAINS:
            raise ValueError(f"Unsupported chain '{chain}'. Supported: {list(self.SUPPORTED_CHAINS.keys())}")
        
        chain_config = self.SUPPORTED_CHAINS[self.chain]
        self.rpc_url = custom_rpc or chain_config["rpc"]
        self.sanctions_oracle = chain_config["sanctions_oracle"]

    def check_ofac_sanctions(self, address: str) -> bool:
        """Queries Chainalysis Sanctions Oracle if available on current chain."""
        if not self.sanctions_oracle:
            return False

        clean_addr = address.lower().replace("0x", "").zfill(64)
        calldata = f"0xdf592f7d{clean_addr}"

        payload = {
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{"to": self.sanctions_oracle, "data": calldata}, "latest"],
            "id": 1
        }
        try:
            res = requests.post(self.rpc_url, json=payload, timeout=5).json()
            result = res.get("result", "0x0")
            return int(result, 16) == 1
        except Exception:
            return False

    def get_eth_price_usd(self) -> float:
        """Fetches spot price for ETH / Native token."""
        try:
            url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd"
            resp = requests.get(url, timeout=5).json()
            return float(resp["ethereum"]["usd"])
        except Exception:
            return 3000.0

    def fetch_address_metrics(self, address: str) -> Tuple[float, bool, bool]:
        """Queries chain RPC for native balance, transaction count (nonce), and sanctions."""
        # 1. Fetch Balance
        payload_bal = {
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [address, "latest"],
            "id": 1
        }
        res_bal = requests.post(self.rpc_url, json=payload_bal, timeout=10).json()
        wei_val = int(res_bal.get("result", "0x0"), 16)
        value_usd = (wei_val / 1e18) * self.get_eth_price_usd()

        # 2. Check Outbound Tx Nonce
        payload_nonce = {
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [address, "latest"],
            "id": 2
        }
        res_nonce = requests.post(self.rpc_url, json=payload_nonce, timeout=10).json()
        nonce = int(res_nonce.get("result", "0x0"), 16)
        pubkey_exposed = nonce > 0

        # 3. Sanctions Check
        is_sanctioned = self.check_ofac_sanctions(address)

        return value_usd, pubkey_exposed, is_sanctioned

    def build_target(
        self,
        address: str,
        gat_score: float = 0.1,
        trace_score: float = 0.1
    ) -> AddressTarget:
        value_usd, pubkey_exposed, is_sanctioned = self.fetch_address_metrics(address)
        return AddressTarget(
            address=address,
            secp256k1_value_usd=round(value_usd, 2),
            pubkey_exposed=pubkey_exposed,
            is_sanctioned=is_sanctioned,
            gat_anomaly_score=gat_score,
            trace_anomaly_score=trace_score
        )