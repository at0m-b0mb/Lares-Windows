# Training

Lares ships with no trained weights of its own. It runs a stock **Qwen2.5-Coder**
in GGUF and gets its security knowledge from the catalogue through retrieval,
which is more reliable than anything a 3B model remembers.

This directory is for going further: fine-tuning that stock model on the exact
job Lares asks it to do. Whether it is worth doing is an empirical question, and
`evaluate.py` is here so you can answer it rather than assume it.

## Be clear about what this can and cannot do

**It cannot teach the model security.** A LoRA adapter is a small, low-rank
nudge to an existing model's behaviour. It is a poor mechanism for installing
facts, and trying to use it that way mostly produces a model that states wrong
things more confidently. The facts live in `lares/catalog/controls/*.yaml` and
reach the model through BM25 retrieval at inference time. If a control is wrong,
fix the YAML — do not try to train around it.

**It can teach the model restraint and format.** Those are behaviours, which is
what LoRA is actually good at, and they are the three things a small model gets
wrong here:

1. emitting the required JSON shape every time, without prose around it;
2. copying a parameter the probe *discovered* instead of writing a plausible
   value of its own;
3. deferring a problem the catalogue has no control for, rather than inventing a
   control id that looks real.

**Nobody has pretrained a model on Windows hardening**, and this does not change
that. If the numbers from `evaluate.py` do not move, the honest conclusion is
that the stock model plus retrieval was already good enough and the adapter
should be dropped. That is a real possible outcome.

## The four steps

```bash
# 1. Build the dataset. Runs on a laptop in seconds.
python training/build_dataset.py --count 4000

# 2. See what a perfect score looks like, and that the judge is not broken.
python training/evaluate.py --baseline

# 3. Score the stock model, so there is a number to beat.
python training/evaluate.py --tier 3b

# 4. Train. This is the only step that wants a GPU.
python training/train_lora.py --base Qwen/Qwen2.5-Coder-3B-Instruct --4bit

# 5. Merge, convert, quantise.
python training/export_gguf.py --llama-cpp ../llama.cpp

# 6. Score the result against the number from step 3.
python training/evaluate.py --model training/out/lares-planner-q4_k_m.gguf
```

Step 4 on a free Colab T4: roughly an hour for a 3B with `--4bit`, under half
that for a 1.5B. A 7B needs `--4bit` and will be tight on 16 GB.

## Where the data comes from

Every example is generated from the control catalogue — the same YAML the
executor runs. Nothing is scraped and nothing is invented, so the targets are
correct by construction, and adding a control grows the training set rather than
leaving it stale.

| Kind | What it teaches |
|---|---|
| `plan` | a synthetic scan and the plan a correct planner produces |
| `parameters` | copy the discovered value; do not write a plausible one |
| `defer` | report-only, irreversible and above-ceiling controls are never planned |
| `unknown` | a problem with no control gets a reason, not an invented id |
| `explain` | the control's own rationale, in plain English |
| `script` | the catalogue's own vetted PowerShell, for the Expert lane |

The synthetic machines vary by Windows edition, memory, domain membership and
network profile, and the constraints vary by ceiling, elevation and budget. That
variation is what teaches the model that a control can be *inapplicable* rather
than merely unfixed.

## How the scoring works

`evaluate.py` does not ask whether the answer reads well. It puts every proposed
action through the real guard — `validate_params` and `check_policy`, the same
functions the executor calls on a live machine — and scores what the executor
would have accepted.

| Measure | Question |
|---|---|
| parseable | did it return JSON at all |
| real | does every `control_id` exist in the catalogue |
| accepted | would the guard let every action run |
| faithful | do the parameters match what the probe discovered |
| restraint | did it plan anything that should have been deferred |
| coverage | of the findings it could have fixed, how many did it plan |

`--baseline` scores the reference answers themselves. It should come back at
100% on everything; if it does not, the judge is broken and no model score from
it means anything.

## A note on what "good" looks like

Coverage is not the measure to maximise. A model that plans every fixable
finding and gets one parameter wrong is worse than one that plans eight and gets
all eight right, because the guard refuses the wrong one anyway and the built-in
planner picks up whatever the model left behind. **Restraint at zero and
faithful near 100 matter more than coverage**, and a model that scores well on
those while leaving findings for the fallback planner is doing its job.
