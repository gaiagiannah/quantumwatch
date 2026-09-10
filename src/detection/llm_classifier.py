"""
QuantumWatch - LLM-Based Transaction Classification
Implements a simplified version of the BlockLens approach:
  - Tokenize EVM execution traces into semantic tokens
  - Use sliding window chunking for long sequences
  - Classify as malicious/benign using an LLM

Full BlockLens (Feng & Fan, ISC 2025) uses LLaMA 3.2-1B + LoRA fine-tuning.
This implementation provides:
  1. A zero-shot classifier using API-based LLM (for quick testing)
  2. A fine-tuning pipeline scaffold (for Colab/GPU training)

Reference: https://eprint.iacr.org/2025/1634
"""

import json
import requests
import pandas as pd
import numpy as np
from pathlib import Path
from typing import List, Dict
from dataclasses import dataclass

PROCESSED_DIR = Path("data/processed")
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


# --- EVM Trace Tokenization (BlockLens-inspired) ---

# Map EVM opcodes to semantic tokens
OPCODE_SEMANTICS = {
    # Arithmetic
    "ADD": "ADD", "MUL": "MUL", "SUB": "SUB", "DIV": "DIV",
    "MOD": "MOD", "EXP": "EXP", "SDIV": "SDIV", "SMOD": "SMOD",
    # Comparison
    "LT": "LT", "GT": "GT", "SLT": "SLT", "SGT": "SGT",
    "EQ": "EQ", "ISZERO": "ISZERO", "AND": "AND", "OR": "OR",
    "XOR": "XOR", "NOT": "NOT", "BYTE": "BYTE", "SHL": "SHL", "SHR": "SHR",
    # Context
    "ADDRESS": "CTX_ADDR", "BALANCE": "CTX_BAL", "ORIGIN": "CTX_ORIG",
    "CALLER": "CTX_CALLER", "CALLVALUE": "CTX_CALLVAL", "CALLDATALOAD": "CTX_CDL",
    "CALLDATASIZE": "CTX_CDS", "CALLDATACOPY": "CTX_CDC",
    "CODESIZE": "CTX_CDSZ", "CODECOPY": "CTX_CDCP",
    "GASPRICE": "CTX_GAS", "EXTCODESIZE": "CTX_ECS", "EXTCODECOPY": "CTX_ECC",
    "EXTCODEHASH": "CTX_ECH", "RETURNDATASIZE": "CTX_RDS", "RETURNDATACOPY": "CTX_RDC",
    # Block
    "BLOCKHASH": "BLK_HASH", "COINBASE": "BLK_CB", "TIMESTAMP": "BLK_TS",
    "NUMBER": "BLK_NUM", "DIFFICULTY": "BLK_DIFF", "GASLIMIT": "BLK_GL",
    "CHAINID": "BLK_CID", "SELFBALANCE": "BLK_SB", "BASEFEE": "BLK_BF",
    # Stack
    "POP": "POP", "MLOAD": "MLOAD", "MSTORE": "MSTORE",
    "SLOAD": "SLOAD", "SSTORE": "SSTORE",
    "JUMP": "JUMP", "JUMPI": "JUMPI", "PC": "PC",
    "MSIZE": "MSIZE", "GAS": "GAS", "JUMPDEST": "JUMPDEST",
    # Call
    "CREATE": "CREATE", "CALL": "CALL", "CALLCODE": "CALLCODE",
    "RETURN": "RETURN", "DELEGATECALL": "DELEGATECALL",
    "CREATE2": "CREATE2", "STATICCALL": "STATICCALL",
    "REVERT": "REVERT", "INVALID": "INVALID", "SELFDESTRUCT": "SELFDESTRUCT",
    # Memory/Storage
    "TLOAD": "TLOAD", "TSTORE": "TSTORE", "TSELFCOST": "TSELFCOST",
    "MCOPY": "MCOPY",
}


def tokenize_evm_trace(trace: List[Dict]) -> str:
    """
    Convert a raw EVM execution trace into a semantic token sequence.
    Follows BlockLens approach: map opcodes to semantic tokens,
    include gas costs, annotate call depth.
    """
    tokens = []
    depth = 1

    for step in trace:
        op = step.get("op", "UNKNOWN").upper()
        semantic = OPCODE_SEMANTICS.get(op, op)
        gas = step.get("gasCost", 0)

        # Annotate call depth
        if op in ("CALL", "STATICCALL", "DELEGATECALL", "CREATE", "CREATE2"):
            depth += 1
        if op in ("RETURN", "REVERT", "STOP", "SELFDESTRUCT"):
            depth = max(1, depth - 1)

        token_str = f"{semantic}@d{depth}"
        if gas > 0:
            token_str += f":g{gas}"

        # Include key values for storage operations
        if op in ("SSTORE", "SLOAD") and "store" in step:
            store_data = step["store"]
            key = store_data.get("key", "")[:8]
            val = store_data.get("value", "")[:8]
            token_str += f"({key},{val})"

        tokens.append(token_str)

    return " ".join(tokens)


def chunk_sequence(sequence: str, chunk_size: int = 512, overlap: int = 64) -> List[str]:
    """
    Sliding window chunking for long sequences (BlockLens approach).
    Allows the LLM to process long traces within context limits.
    """
    tokens = sequence.split()
    chunks = []
    for i in range(0, len(tokens), chunk_size - overlap):
        chunk = tokens[i:i + chunk_size]
        if chunk:
            chunks.append(" ".join(chunk))
    return chunks


# --- Zero-Shot LLM Classification (API-based) ---

CLASSIFICATION_PROMPT = """You are a blockchain security analyst. Analyze the following EVM transaction trace and classify it as MALICIOUS or BENIGN.

Transaction trace (semantic tokens):
{trace}

Context: This is a tokenized real-world asset (RWA) protocol transaction.
Common malicious patterns include:
- Unauthorized minting or burning
- Oracle price manipulation
- Flash loan attacks
- Reentrancy exploits
- Privilege escalation (admin key misuse)
- Front-running
- Sandwich attacks

Respond in JSON format:
{{"classification": "MALICIOUS" or "BENIGN", "confidence": 0.0-1.0, "reasoning": "brief explanation", "suspicious_chunks": [indices of suspicious chunks]}}
"""


def classify_with_llm(trace_tokens: str, api_key: str = None, model: str = "gpt-4o") -> Dict:
    """
    Zero-shot classification using an LLM API.
    For production, use the fine-tuned model below.
    """
    if not api_key:
        print("No API key provided. Using heuristic fallback.")
        return heuristic_classify(trace_tokens)

    # For very long traces, use the most suspicious chunk
    chunks = chunk_sequence(trace_tokens)
    # Heuristic: pick the chunk with the most CALL/REVERT operations
    def chunk_suspicion(chunk):
        return chunk.count("CALL") + chunk.count("REVERT") + chunk.count("SELFDESTRUCT") * 10
    target_chunk = max(chunks, key=chunk_suspicion) if chunks else trace_tokens[:2000]

    prompt = CLASSIFICATION_PROMPT.format(trace=target_chunk)

    # Call OpenAI API (or any compatible endpoint)
    try:
        import openai
        client = openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=500,
        )
        result_text = response.choices[0].message.content
        # Extract JSON
        start = result_text.find("{")
        end = result_text.rfind("}") + 1
        return json.loads(result_text[start:end])
    except Exception as e:
        print(f"LLM API error: {e}")
        return heuristic_classify(trace_tokens)


def heuristic_classify(trace_tokens: str) -> Dict:
    """Fallback heuristic classification when no LLM is available."""
    suspicious_ops = ["SELFDESTRUCT", "DELEGATECALL", "REVERT"]
    counts = {op: trace_tokens.count(op) for op in suspicious_ops}

    score = sum(counts.values())
    if score > 5:
        classification = "MALICIOUS"
        confidence = min(0.95, 0.5 + score * 0.05)
    elif score > 2:
        classification = "SUSPICIOUS"
        confidence = 0.5 + score * 0.05
    else:
        classification = "BENIGN"
        confidence = 0.9

    return {
        "classification": classification,
        "confidence": confidence,
        "reasoning": f"Heuristic: {counts}",
        "suspicious_chunks": [],
    }


# --- Fine-Tuning Pipeline (for Colab) ---

def prepare_finetuning_dataset(
    labeled_traces: List[Dict],
    output_path: Path
) -> Dict:
    """
    Prepare a dataset for LoRA fine-tuning (BlockLens approach).
    Each sample: {"trace": str, "label": 0/1}

    In production, collect:
    - Malicious: from DeFiHackLabs, Slowmist post-mortems, Immunefi reports
    - Benign: random DeFi transactions from Dune

    Run this on Google Colab with a T4/A100 GPU.
    """
    from datasets import Dataset

    examples = []
    for trace_data in labeled_traces:
        trace_str = tokenize_evm_trace(trace_data.get("trace", []))
        examples.append({
            "text": CLASSIFICATION_PROMPT.format(trace=trace_str[:4096]),
            "label": trace_data.get("label", 0),
        })

    dataset = Dataset.from_list(examples)
    dataset.save_to_disk(str(output_path))
    print(f"Dataset saved: {len(examples)} examples to {output_path}")
    return dataset


def finetune_llm(
    dataset_path: Path,
    base_model: str = "meta-llama/Llama-3.2-1B",
    output_dir: Path = Path("data/processed/llm_finetuned"),
    epochs: int = 3,
    batch_size: int = 4,
    learning_rate: float = 2e-5,
):
    """
    Fine-tune LLaMA 3.2-1B with LoRA (BlockLens approach).
    RUN THIS ON GOOGLE COLAB (T4 or better).
    """
    from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
    from peft import LoraConfig, get_peft_model, TaskType
    from datasets import load_from_disk
    from trl import SFTTrainer

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading base model: {base_model}")
    tokenizer = AutoTokenizer.from_pretrained(base_model)
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype="auto",
        device_map="auto",
    )

    # LoRA config (BlockLens uses LoRA)
    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=16,
        lora_alpha=32,
        lora_dropout=0.1,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # Load dataset
    dataset = load_from_disk(str(dataset_path))

    # Training
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        learning_rate=learning_rate,
        weight_decay=0.01,
        warmup_ratio=0.1,
        logging_steps=10,
        save_strategy="epoch",
        evaluation_strategy="epoch",
        fp16=True,
    )

    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        peft_config=lora_config,
    )

    print("Starting fine-tuning...")
    trainer.train()
    model.save_pretrained(output_dir / "final")
    tokenizer.save_pretrained(output_dir / "final")
    print(f"Model saved to {output_dir / 'final'}")


if __name__ == "__main__":
    # Demo: classify a sample trace
    sample_trace = [
        {"op": "PUSH1", "gasCost": 3},
        {"op": "CALLDATALOAD", "gasCost": 3},
        {"op": "PUSH1", "gasCost": 3},
        {"op": "SHR", "gasCost": 3},
        {"op": "PUSH4", "gasCost": 3},
        {"op": "EQ", "gasCost": 3},
        {"op": "PUSH2", "gasCost": 3},
        {"op": "JUMPI", "gasCost": 10},
        {"op": "JUMPDEST", "gasCost": 1},
        {"op": "CALL", "gasCost": 100},
        {"op": "ISZERO", "gasCost": 3},
        {"op": "PUSH1", "gasCost": 3},
        {"op": "MSTORE", "gasCost": 3},
        {"op": "PUSH1", "gasCost": 3},
        {"op": "REVERT", "gasCost": 0},
    ]

    tokens = tokenize_evm_trace(sample_trace)
    print(f"Tokenized trace: {tokens}")
    print(f"Length: {len(tokens.split())} tokens")

    result = heuristic_classify(tokens)
    print(f"\nClassification: {result}")   