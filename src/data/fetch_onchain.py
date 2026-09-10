"""
QuantumWatch - On-Chain Data Pipeline
Pulls token transfer data from EVM chains for RWA protocols.

Data sources:
  - Etherscan API (free tier: 5 req/sec)
  - Alchemy RPC (free tier: 300 req/day)
  - Alchemy WebSocket (real-time block streaming)
  - DeFiLlama API (free, no key)
"""

import requests
import pandas as pd
import time
import os
import json
import asyncio
from pathlib import Path
from dotenv import load_dotenv
from tqdm import tqdm

load_dotenv()

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
ALCHEMY_API_KEY = os.getenv("ALCHEMY_API_KEY", "")
ETHERSCAN_API = "https://api.etherscan.io/v2/api"
ALCHEMY_RPC = f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}"

# RWA Protocol Token Contracts (Ethereum Mainnet)
RWA_TOKENS = {
    "ondo_usdy": {
        "address": "0x96F6eF951840721AdBF46Ac996b59E0235CB985C",
        "name": "Ondo USDY",
        "decimals": 6,
        "category": "tokenized_treasury",
    },
    "ondo_ousg": {
        "address": "0x1B19C19393e2d034D8Ff31ff34c81252FcBbee92",
        "name": "Ondo OUSG",
        "decimals": 2,
        "category": "tokenized_treasury",
    },
    # Add more protocols here as you expand
    # "centrifuge_pool1": {
    #     "address": "0x...",
    #     "name": "Centrifuge Pool 1",
    #     "decimals": 18,
    #     "category": "private_credit",
    # },
    # "maple_syrup": {
    #     "address": "0x...",
    #     "name": "Maple Syrup",
    #     "decimals": 18,
    #     "category": "institutional_credit",
    # },
}

DATA_DIR = Path("data/raw")
DATA_DIR.mkdir(parents=True, exist_ok=True)


def get_token_transfers(token_address: str, page: int = 1, offset: int = 100) -> pd.DataFrame:
    """Fetch ERC-20 token transfers from Etherscan API."""
    params = {
        "chainid": 1,
        "module": "account",
        "action": "tokentx",
        "contractaddress": token_address,
        "page": page,
        "offset": offset,
        "sort": "desc",
    }
    if ETHERSCAN_API_KEY:
        params["apikey"] = ETHERSCAN_API_KEY

    resp = requests.get(ETHERSCAN_API, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    if data.get("status") == "0" and "Max rate limit reached" in data.get("message", ""):
        time.sleep(3)
        return get_token_transfers(token_address, page, offset)

    results = data.get("result", [])
    if not isinstance(results, list):
        return pd.DataFrame()

    df = pd.DataFrame(results)
    if df.empty:
        return df

    # Parse and type columns
    df["value"] = pd.to_numeric(df["value"], errors="coerce")
    df["timeStamp"] = pd.to_numeric(df["timeStamp"], errors="coerce")
    df["blockNumber"] = pd.to_numeric(df["blockNumber"], errors="coerce")
    df["gasUsed"] = pd.to_numeric(df["gasUsed"], errors="coerce")
    df["status"] = pd.to_numeric(df["status"], errors="coerce")

    return df


def fetch_protocol(token_key: str, max_pages: int = 10) -> pd.DataFrame:
    """Fetch up to max_pages*100 transfers for a single token."""
    token = RWA_TOKENS[token_key]
    all_pages = []

    for page in tqdm(range(1, max_pages + 1), desc=f"  {token['name']}"):
        df = get_token_transfers(token["address"], page=page)
        if df.empty:
            break
        df["protocol"] = token_key
        df["token_name"] = token["name"]
        df["token_address"] = token["address"]
        df["decimals"] = token["decimals"]
        df["category"] = token["category"]
        all_pages.append(df)
        time.sleep(0.25)  # Respect rate limits

    if not all_pages:
        return pd.DataFrame()

    result = pd.concat(all_pages, ignore_index=True)
    # Convert to human-readable value
    result["value_human"] = result["value"] / (10 ** result["decimals"])
    return result


def fetch_all(max_pages_per_token: int = 10) -> pd.DataFrame:
    """Fetch data for all configured RWA tokens."""
    print(f"Fetching data for {len(RWA_TOKENS)} RWA tokens...")
    all_data = []

    for token_key in RWA_TOKENS:
        print(f"\nFetching: {RWA_TOKENS[token_key]['name']}")
        df = fetch_protocol(token_key, max_pages=max_pages_per_token)
        print(f"  Retrieved {len(df)} transactions")
        all_data.append(df)

    combined = pd.concat(all_data, ignore_index=True)
    combined.to_parquet(DATA_DIR / "rwa_all.parquet")
    print(f"\nTotal: {len(combined)} transactions, "
          f"{combined['from'].nunique()} unique senders, "
          f"{combined['to'].nunique()} unique receivers")
    print(f"Saved to {DATA_DIR / 'rwa_all.parquet'}")
    return combined


def fetch_protocol_tvl() -> pd.DataFrame:
    """Fetch TVL data from DeFiLlama (free, no API key)."""
    resp = requests.get("https://api.llama.fi/protocols", timeout=30)
    resp.raise_for_status()
    protocols = resp.json()

    # Filter for RWA-related protocols
    rwa_keywords = ["ondo", "securitize", "centrifuge", "maple", "frax",
                    "blackrock", "franklin", "van eck", "hashnote"]
    rwa_protocols = [
        p for p in protocols
        if any(kw in p.get("name", "").lower() for kw in rwa_keywords)
    ]

    df = pd.DataFrame(rwa_protocols)
    if not df.empty:
        df = df[["name", "symbol", "tvl", "chain", "category"]].dropna()
        df.to_csv(DATA_DIR / "rwa_tvl.csv", index=False)
        print(f"Saved TVL data for {len(df)} RWA protocols")

    return df


def stream_blocks_websocket(callback, max_blocks: int = 1000):
    """
    Real-time block streaming via Alchemy WebSocket.
    Replaces batch polling for live monitoring.

    Args:
        callback: Function called with each new block dict.
        max_blocks: Stop after this many blocks (0 = unlimited).

    Usage:
        def on_block(block):
            # Extract RWA token transfers from this block
            for tx in block["transactions"]:
                # Check for ERC-20 Transfer events to RWA token addresses
                ...

        stream_blocks_websocket(on_block, max_blocks=1000)
    """
    import websockets

    ws_url = f"wss://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}/ws"

    async def _stream():
        async with websockets.connect(ws_url) as ws:
            # Subscribe to new block headers
            await ws.send(json.dumps({
                "jsonrpc": "2.0",
                "method": "eth_subscribe",
                "params": ["newHeads"],
                "id": 1
            }))

            count = 0
            while max_blocks == 0 or count < max_blocks:
                msg = await ws.recv()
                data = json.loads(msg)

                if "params" in data:
                    block_hash = data["params"]["result"]["hash"]

                    # Fetch full block with transactions
                    resp = requests.post(
                        ALCHEMY_RPC,
                        json={
                            "jsonrpc": "2.0",
                            "method": "eth_getBlockByHash",
                            "params": [block_hash, True],
                            "id": 1
                        }
                    )
                    block = resp.json().get("result")
                    if block:
                        callback(block)
                        count += 1
                        if count % 100 == 0:
                            print(f"  Streamed {count} blocks...")

    asyncio.run(_stream())


def stream_rwa_transfers(callback, max_blocks: int = 500):
    """
    High-level: stream blocks and extract only RWA token transfers.
    Filters for ERC-20 Transfer events matching RWA_TOKENS addresses.

    Args:
        callback: Function called with (from_addr, to_addr, value, protocol, block_number)
        max_blocks: Stop after this many blocks
    """
    rwa_addresses = {v["address"].lower(): k for k, v in RWA_TOKENS.items()}

    def _on_block(block):
        block_num = int(block["number"], 16)
        for tx in block["transactions"]:
            # Check logs for Transfer events
            for log in tx.get("logs", []):
                # ERC-20 Transfer topic: 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
                if log.get("topics") and log["topics"][0] == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef":
                    contract = log["address"].lower()
                    if contract in rwa_addresses:
                        protocol = rwa_addresses[contract]
                        from_addr = "0x" + log["topics"][1][-40:]
                        to_addr = "0x" + log["topics"][2][-40:]
                        value = int(log["data"], 16)
                        decimals = RWA_TOKENS[protocol]["decimals"]
                        value_human = value / (10 ** decimals)
                        callback(from_addr, to_addr, value_human, protocol, block_num)

    stream_blocks_websocket(_on_block, max_blocks=max_blocks)


if __name__ == "__main__":
    fetch_all(max_pages_per_token=10)
    fetch_protocol_tvl()

    # Uncomment to test WebSocket streaming:
    # def print_rwa_transfer(from_addr, to_addr, value, protocol, block_num):
    #     print(f"  Block {block_num}: {from_addr[:10]}... -> {to_addr[:10]}... "
    #           f"| {value:,.2f} {protocol}")
    #
    # print("\nStreaming RWA transfers (10 blocks)...")
    # stream_rwa_transfers(print_rwa_transfer, max_blocks=10)   