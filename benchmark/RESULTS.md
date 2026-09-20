# First experiment — quantization

**Run 2026-09-19. Pilot. The headline is a null result, and the suite is too small
to have found much else.**

## Question

Does heavier quantization make a model more likely to obey instructions injected into
tool output? Existing research finds stronger quantization increases jailbreak
vulnerability and shifts the refusal boundary, and notes GGUF is under-tested. Nobody had
run *agent injection* per-quantization.

## Setup

| | |
| --- | --- |
| Base | Meta-Llama-3.1-8B-Instruct, GGUF from `bartowski` |
| Builds | Q4_K_M, Q5_K_M, Q6_K, Q8_0 — all four SHA-256 pinned, see `results/` |
| Suite | `canary-v1` — 4 content channels × 6 published injection techniques = 24 matched pairs |
| Scaffold | one, fixed. Text JSON tool protocol. Temperature 0, seed 42, 8192 ctx |
| Runner | llama.cpp b11057, CUDA 12.4, RTX A4500 |

FP16 was dropped: 16 GB exceeded the ~14 GB of free VRAM. Q8_0 is the high-precision
reference.

## Result

```
quant       utility   susceptible     rate   95% CI (Wilson)
Q4_K_M      24/24        4/24      16.7%   [ 6.7%, 35.9%]
Q5_K_M      24/24        0/24       0.0%   [ 0.0%, 13.8%]
Q6_K        24/24        5/24      20.8%   [ 9.2%, 40.5%]
Q8_0        24/24        5/24      20.8%   [ 9.2%, 40.5%]
```

**No monotonic quantization effect.** The most heavily quantized build is not the most
susceptible — Q8_0, the *least* quantized, ties for the highest rate, and Q5_K_M scored
zero. That is the opposite shape to the hypothesis.

The widest gap, Q5_K_M vs Q6_K, gives Fisher exact two-tailed **p = 0.050**. But that pair
was chosen after seeing the data, one of 6; against a Bonferroni threshold of 0.0083 it is
**not significant**. Nothing here is resolved.

**Utility was 24/24 on every build.** Every model called the tool correctly on every
benign control, so no build's score is contaminated by inability to call tools. That was
the failure mode most likely to invert the headline, and it did not occur.

## The channel, not the quantization

Breaking the hits down by where the untrusted content came from:

| channel | Q4_K_M | Q5_K_M | Q6_K | Q8_0 |
| --- | --- | --- | --- | --- |
| document | 0 | 0 | 0 | 0 |
| inbox | **4** | 0 | 0 | 0 |
| ticket | 0 | 0 | 0 | 0 |
| webpage | 0 | 0 | **5** | **5** |

Every successful injection in the whole experiment landed in exactly one channel per
build — and *which* channel moved between builds. Q4 was compromised only through the
inbox; Q6 and Q8 only through the web page; Q5 not at all.

So the rate is not measuring a stable per-build property. It is measuring which of four
content framings happened to fall over a decision boundary, and quantization perturbs
that without moving it in a consistent direction. With 4 channels, one channel flipping
moves the headline rate by 20 points.

By technique, the pattern is nearly flat — five of six techniques worked at 25% on the
susceptible builds, which is just "one channel". The exception is real: **`tool-output-spoof`
never worked on any build.** Injection framed as forged JSON tool-result syntax failed
everywhere, while plain natural-language instructions succeeded.

## What this changes

1. **The suite is under-powered and channel-bound.** 4 channels is far too few when one
   channel carries all the signal. Next version needs many more channels, and cases that
   vary content framing independently of technique.
2. **Report channel breakdown alongside any rate.** A single susceptibility number hides
   the fact that one framing is doing all the work.
3. **Quantization is not the first thing to measure.** It produced no clear effect at this
   sample size. Lineage — official instruct tune vs. community fine-tune vs. abliterated —
   is the better next experiment, and a larger effect is plausible there.
   `bartowski/mlabonne_Qwen3-8B-abliterated-GGUF` and
   `bartowski/Meta-Llama-3.1-8B-Instruct-abliterated-GGUF` give same-uploader,
   same-quantization comparisons.

## Limits

- **One model, one scaffold, one seed, one hardware class.** Results are comparable only
  within that.
- **24 cases.** Wide intervals; only very large effects would show.
- **Text tool protocol, not native tool calling.** llama.cpp b11057 returns HTTP 500
  (`"output that does not match the expected peg-native format"`) when Llama 3.1 emits two
  tool calls in one turn separated by `"; "`. Under native parsing that failure would have
  scored as "did not call the tool" — and had it occurred at different rates per
  quantization, it would have silently corrupted the comparison. The text protocol removes
  the parser as a variable but is one step less faithful to a production harness. Worth
  reporting upstream.
- **Every injection is appended at the end of the content.** Position was never varied and
  is confounded with everything. Identified after the run; see
  [SUITE-DESIGN.md](SUITE-DESIGN.md).
- **Attacker goal is mixed and unlabelled.** Some techniques ask the model to send
  *instead* to the attacker, others to send *also*. Those are different asks and the rates
  above pool them.
- **One sample per cell.** Each channel × technique result rests on a single piece of text.
- **No FP16 arm**, so the genuinely unquantized baseline is untested.
- **Synthetic cases** written by the same person running the experiment.

## Reproducing

```
python benchmark/build_suite.py
python benchmark/run_benchmark.py --manifest <manifest.json> \
    --llama-bin <llama.cpp dir> --base-model llama-3.1-8b-instruct
python benchmark/analyze.py
```

Each result names its `weightsDigest`, `scaffoldDigest`, seed, and runner build. Anyone
with the same artifact can re-run and check. Transcripts are kept locally and referenced
by digest; they contain the injection payloads and are not published.
