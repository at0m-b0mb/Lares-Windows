#!/usr/bin/env python3
"""Merge the adapter into the base model and quantise it to GGUF.

Three steps, and the last two belong to llama.cpp rather than to us:

    1. merge     the LoRA weights are folded into the base model, producing an
                 ordinary HuggingFace checkpoint with no adapter left over
    2. convert   llama.cpp's convert_hf_to_gguf.py turns that into F16 GGUF
    3. quantise  llama-quantize compresses it to Q4_K_M, which is the format
                 Lares actually loads

    git clone https://github.com/ggml-org/llama.cpp && cmake -B build llama.cpp \\
        && cmake --build build --config Release

    python training/export_gguf.py --base Qwen/Qwen2.5-Coder-3B-Instruct \\
        --adapter training/out/lares-3b-lora --llama-cpp ../llama.cpp

The merge needs enough RAM to hold the model in fp16 - about 6 GB for a 3B, 15
for a 7B. It does not need a GPU. If the machine cannot hold it, do this step in
the same Colab session that did the training, while the weights are already
there.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: Where llama.cpp puts its binaries, depending on how it was built.
QUANTIZE_NAMES = ["llama-quantize", "llama-quantize.exe", "quantize", "quantize.exe"]
BUILD_DIRS = ["build/bin", "build", "."]


def find_llama_cpp(hint: str | None) -> Path | None:
    candidates = []
    if hint:
        candidates.append(Path(hint).expanduser())
    candidates += [ROOT.parent / "llama.cpp", Path.home() / "llama.cpp"]
    for candidate in candidates:
        if (candidate / "convert_hf_to_gguf.py").exists():
            return candidate
    return None


def find_quantize(llama_cpp: Path) -> Path | None:
    for directory in BUILD_DIRS:
        for name in QUANTIZE_NAMES:
            candidate = llama_cpp / directory / name
            if candidate.exists():
                return candidate
    found = shutil.which("llama-quantize")
    return Path(found) if found else None


def merge(base: str, adapter: Path, out: Path) -> bool:
    try:
        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        print(f"Merging needs transformers and peft: {exc}")
        print('  pip install torch "transformers>=4.44" "peft>=0.12"')
        return False

    print(f"Loading {base} in fp16")
    model = AutoModelForCausalLM.from_pretrained(
        base, torch_dtype=torch.float16, device_map="cpu", trust_remote_code=True)

    print(f"Applying the adapter from {adapter}")
    model = PeftModel.from_pretrained(model, str(adapter))
    model = model.merge_and_unload()

    out.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(out), safe_serialization=True)
    AutoTokenizer.from_pretrained(base, trust_remote_code=True).save_pretrained(str(out))
    print(f"Merged model written to {out}")
    return True


def run(command: list[str]) -> bool:
    print("  " + " ".join(str(c) for c in command))
    result = subprocess.run([str(c) for c in command])
    return result.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--base", default="Qwen/Qwen2.5-Coder-3B-Instruct")
    parser.add_argument("--adapter", default=str(ROOT / "training" / "out" / "lares-lora"))
    parser.add_argument("--out", default=str(ROOT / "training" / "out"))
    parser.add_argument("--name", default="lares-planner")
    parser.add_argument("--quant", default="Q4_K_M",
                        help="Q4_K_M is what the ladder expects; Q5_K_M for more headroom")
    parser.add_argument("--llama-cpp", help="path to a built llama.cpp checkout")
    parser.add_argument("--skip-merge", action="store_true",
                        help="the merged model already exists")
    args = parser.parse_args()

    out_dir = Path(args.out)
    merged = out_dir / f"{args.name}-merged"

    if not args.skip_merge:
        adapter = Path(args.adapter)
        if not adapter.exists():
            print(f"No adapter at {adapter}.\nRun: python training/train_lora.py")
            return 1
        if not merge(args.base, adapter, merged):
            return 1
    elif not merged.exists():
        print(f"--skip-merge given but {merged} does not exist")
        return 1

    llama_cpp = find_llama_cpp(args.llama_cpp)
    if llama_cpp is None:
        print("\nCould not find a llama.cpp checkout. The merged model is ready at")
        print(f"  {merged}")
        print("\nTo finish, clone and build llama.cpp, then run this again with")
        print("  --skip-merge --llama-cpp /path/to/llama.cpp")
        return 1

    f16 = out_dir / f"{args.name}-f16.gguf"
    print(f"\nConverting to GGUF via {llama_cpp.name}")
    if not run([sys.executable, llama_cpp / "convert_hf_to_gguf.py", merged,
                "--outfile", f16, "--outtype", "f16"]):
        print("Conversion failed.")
        return 1

    quantize = find_quantize(llama_cpp)
    if quantize is None:
        print(f"\nF16 GGUF written to {f16}, but llama-quantize was not found.")
        print("Build llama.cpp (cmake --build build --config Release) and run:")
        print(f"  llama-quantize {f16} {out_dir / f'{args.name}-{args.quant.lower()}.gguf'} "
              f"{args.quant}")
        return 1

    quantised = out_dir / f"{args.name}-{args.quant.lower()}.gguf"
    print(f"\nQuantising to {args.quant}")
    if not run([quantize, f16, quantised, args.quant]):
        print("Quantisation failed.")
        return 1

    size = quantised.stat().st_size // 2**20
    print(f"\n{quantised} ({size} MB)")
    print("\nScore it before trusting it:")
    print(f"  python training/evaluate.py --model {quantised}")
    print("\nThen put it where Lares looks for models, or point at it with")
    print("  lares model --tier 3b")
    return 0


if __name__ == "__main__":
    sys.exit(main())
