#!/usr/bin/env python3
"""LoRA fine-tune of the Lares planner.

This is the one step that needs a GPU. Everything else in this directory runs on
a laptop. A 1.5B or 3B adapter trains on a free Colab T4 in roughly an hour, and
you need to do it once - the result is a file you copy back and quantise.

    pip install "torch" "transformers>=4.44" "peft>=0.12" "trl>=0.9" \
                "datasets" "accelerate" "bitsandbytes"

    python training/train_lora.py --base Qwen/Qwen2.5-Coder-3B-Instruct \
                                  --out training/out/lares-3b-lora

What the adapter is actually for
--------------------------------
Not knowledge. The security facts come from the catalogue through retrieval, and
a LoRA is a poor way to install facts anyway. It is for *format and restraint*:
emitting the exact JSON shape every time, copying discovered parameters through
instead of inventing plausible ones, and deferring a control rather than
inventing an id for a problem the catalogue does not cover. Those are the three
things a small model gets wrong, and they are all behaviour rather than recall,
which is what LoRA is good at.

Measure before and after with evaluate.py. If the numbers do not move, the
adapter is not earning its place and the base model plus retrieval is the better
answer - that is a real possible outcome and worth knowing.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: The modules a Qwen2.5 attention block exposes. Adapting all of them rather
#: than just the attention projections costs little at this size and is
#: noticeably better at holding an output format.
TARGET_MODULES = ["q_proj", "k_proj", "v_proj", "o_proj",
                  "gate_proj", "up_proj", "down_proj"]


def load_rows(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--base", default="Qwen/Qwen2.5-Coder-3B-Instruct")
    parser.add_argument("--data", default=str(ROOT / "training" / "data" / "train.jsonl"))
    parser.add_argument("--out", default=str(ROOT / "training" / "out" / "lares-lora"))
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument("--batch", type=int, default=1)
    parser.add_argument("--accum", type=int, default=8,
                        help="gradient accumulation; batch * accum is the effective batch")
    parser.add_argument("--lr", type=float, default=1e-4)
    parser.add_argument("--rank", type=int, default=16)
    parser.add_argument("--alpha", type=int, default=32)
    parser.add_argument("--max-seq", type=int, default=4096)
    parser.add_argument("--4bit", dest="four_bit", action="store_true",
                        help="QLoRA. Required to fit a 7B on a 16 GB T4.")
    args = parser.parse_args()

    try:
        import torch
        from datasets import Dataset
        from peft import LoraConfig
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from trl import SFTConfig, SFTTrainer
    except ImportError as exc:
        print(f"Missing a training dependency: {exc}\n")
        print('  pip install torch "transformers>=4.44" "peft>=0.12" "trl>=0.9" '
              'datasets accelerate bitsandbytes')
        return 1

    data_path = Path(args.data)
    if not data_path.exists():
        print(f"No training data at {data_path}.\nRun: python training/build_dataset.py")
        return 1

    rows = load_rows(data_path)
    print(f"{len(rows)} examples from {data_path.name}")
    kinds: dict[str, int] = {}
    for row in rows:
        kinds[row.get("kind", "?")] = kinds.get(row.get("kind", "?"), 0) + 1
    for kind, n in sorted(kinds.items(), key=lambda kv: -kv[1]):
        print(f"  {kind:<12} {n}")

    tokenizer = AutoTokenizer.from_pretrained(args.base, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    def render(row: dict) -> dict:
        # The tokenizer's own chat template, so the adapter learns the same
        # framing llama.cpp will apply at inference. Getting this wrong is the
        # usual reason a fine-tune appears to do nothing.
        return {"text": tokenizer.apply_chat_template(
            row["messages"], tokenize=False, add_generation_prompt=False)}

    dataset = Dataset.from_list(rows).map(render, remove_columns=["messages", "kind"])

    quantisation = None
    if args.four_bit:
        from transformers import BitsAndBytesConfig
        quantisation = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )

    model = AutoModelForCausalLM.from_pretrained(
        args.base,
        quantization_config=quantisation,
        torch_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
        device_map="auto" if torch.cuda.is_available() else None,
        trust_remote_code=True,
    )
    model.config.use_cache = False

    peft_config = LoraConfig(
        r=args.rank,
        lora_alpha=args.alpha,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=TARGET_MODULES,
    )

    config = SFTConfig(
        output_dir=args.out,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch,
        gradient_accumulation_steps=args.accum,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        logging_steps=10,
        save_strategy="epoch",
        bf16=torch.cuda.is_available(),
        max_seq_length=args.max_seq,
        dataset_text_field="text",
        gradient_checkpointing=True,
        report_to=[],
        # Packing would splice unrelated examples together, and the whole point
        # is that one prompt produces exactly one JSON object.
        packing=False,
    )

    trainer = SFTTrainer(
        model=model,
        args=config,
        train_dataset=dataset,
        peft_config=peft_config,
        processing_class=tokenizer,
    )

    print(f"\nTraining {args.base} on {len(dataset)} examples, "
          f"effective batch {args.batch * args.accum}")
    trainer.train()

    out = Path(args.out)
    trainer.save_model(str(out))
    tokenizer.save_pretrained(str(out))
    print(f"\nAdapter written to {out}")
    print("Next:")
    print(f"  python training/export_gguf.py --base {args.base} --adapter {out}")
    print("  python training/evaluate.py --model <the quantised gguf>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
