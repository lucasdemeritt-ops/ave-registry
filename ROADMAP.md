# Roadmap

**This is a list of conditions, not dates.** Each stage names what must be true before the
next one starts. Nothing here is scheduled; work begins on a stage when its gate is met.

The project is deliberately low-traffic for now. The repo may be public, but it is not
being promoted — the point is that the idea and this roadmap are sound and inspectable, so
that when conditions are met the work can start rather than be designed.

## Where things stand

| | |
| --- | --- |
| Premise tested | Yes — 21 findings written as advisories, [PHASE0-FINDINGS.md](PHASE0-FINDINGS.md) |
| Registry format | v0.1, 20 advisories, matcher + specificity tests in CI |
| Benchmark harness | Works end to end, [benchmark/RESULTS.md](benchmark/RESULTS.md) |
| Benchmark **instrument** | **Not calibrated.** This is the blocker for everything downstream |
| Contributors | One |
| Machines | One RTX A4500 (~14 GB usable) |

Two datasets are known to be missing and are the real substance of the project: a
tool→capability catalogue, and model susceptibility measurements. Both are reference data
that advisories point at.

---

## Stage 1 — Calibrate the suite

**Why:** the first experiment produced a rate that moved 20 points depending on whether a
single content channel flipped. Every cell in `canary-v1` is one channel × one technique ×
**one sample**, so each cell is effectively a coin toss on one exact piece of text. The
instrument is not yet known to measure anything.

**Work:** authoring, not engineering. The harness does not change.

- Multiple samples per cell — several differently-worded items per channel, so a cell's
  score averages over phrasing rather than resting on one sentence.
- More channels, roughly 4 → 20, so a result can be said to generalize past four framings.
- Per-condition reporting: channel breakdown alongside any headline rate, never a bare
  number.

**Gate — all three must hold:**

1. **Positive control fires.** A deliberately susceptible configuration scores high. If the
   suite cannot catch a config built to be caught, it catches nothing.
2. **Negative control stays clean.** A hardened configuration scores at or near zero.
3. **Per-condition precision is usable.** Each channel's 95% Wilson interval is narrow
   enough to distinguish it from its neighbours — as a starting target, width under ~20
   points, which needs order-100 samples per channel rather than 6.

Until all three hold, no susceptibility number from this project should be published or
cited, including internally.

**Cost:** ~1.3 h of compute for 400 pairs × 4 builds on the existing card. The expensive
part is writing the content.

---

## Stage 2 — One-command runs

**Gate to start:** Stage 1 passed.

Today a run needs llama.cpp installed by hand, a GGUF fetched by hand, and a manifest
written by hand. That is fine for one person and impossible to hand to anyone else.

**Work:** a single entry point that takes a HuggingFace id and a quantization, then
fetches, hashes, runs, and writes a valid result. No hand-built manifests.

**Gate to pass:** a person who has not seen the code can produce a schema-valid result
from the README alone, without asking a question.

---

## Stage 3 — Cross-machine variance baseline

**Gate to start:** Stage 2 passed. Needs **2–3 machines of different hardware**, not
powerful ones.

**The question it answers:** how much do two *honest* runs of the same pinned artifact
disagree across different hardware and runner builds? Temperature 0 and a fixed seed do
not make llama.cpp deterministic across GPUs.

This is the prerequisite for the verification model in
[benchmark/SPEC.md](benchmark/SPEC.md). "Results are re-run, not trusted" is meaningless
until it is known how far apart two good-faith runs normally sit — otherwise ordinary
variance looks like fabrication and vice versa.

**Gate to pass:** a published tolerance. A re-run within it corroborates; outside it, the
result is flagged.

**Machines available:** the A4500, a laptop, and possibly a rented cloud GPU. The laptop is
sufficient — this stage needs *different*, not *fast*.

---

## Stage 4 — Invited cohort

**Gate to start:** Stages 1–3 passed, and the policy items below answered.

A handful of people who are asked directly. Not a public call.

**Why invited rather than open:** there is one chance to ask people to download several GB
and spend an hour of GPU time. If the first dataset turns out to be noise, that goodwill is
spent and the second ask is much harder.

**Needs:** a submission path — PR template, CI validation of submitted results (the schema
validation already in CI is the foundation), and deduplication on weights digest, scaffold
digest and seed.

**Gate to pass:** results arriving from people other than the maintainer, reproducing
within the Stage 3 tolerance.

---

## Stage 5 — Open contribution

**Gate to start:** Stage 4 passed, plus both policy questions answered in writing:

1. **Naming community models.** Publishing susceptibility scores for named community
   fine-tunes means naming hobbyist authors. Needs a policy before any lineage comparison
   is published.
2. **Targeting risk.** A public ranking of the most easily compromised models is useful to
   an attacker as well as a defender. The techniques are already published; the *scores*
   are the new information. Needs a decision on what is published and at what granularity.

---

## What each additional machine unlocks

| Machine | Unlocks | Stage |
| --- | --- | --- |
| A4500 (have) | Everything up to 8B across quantizations; ~1.3 h per 400-pair × 4-build sweep | 1 |
| Laptop | The variance baseline — needs *different* hardware, not fast | 3 |
| Rented cloud GPU | The FP16 arm dropped from experiment 1 (needed >14 GB), and models above 13B | 1 extension |

Compute is not currently the constraint. The first experiment used about 5 minutes of GPU
time. The constraint is that the measuring instrument is not yet marked.

---

## Registry track, in parallel

Independent of the benchmark, and not gated on it:

1. **Capability catalogue.** Tool capabilities cannot be read from a manifest; they are a
   judgement and need a maintained tool→capability mapping. The registry's configuration-
   native advisories depend on it. Largest open piece of work.
2. **Mirror rather than hand-write component advisories.** 8 of 21 phase-0 findings were
   ordinary component bugs already covered by CVE/OSV. Source those automatically; spend
   human review on configuration-native records.
3. **Lockfile emitter.** Deferred until the capability catalogue exists, since a lock
   without capabilities cannot match the advisories that matter.

## Housekeeping before wider visibility

- Schema `$id` fields still read `ave-registry.example`; point them at the repo.
- Enable GitHub private vulnerability reporting, which [DISCLOSURE.md](DISCLOSURE.md)
  already directs people to.
- Credit and notify @lizthedeveloper, whose idea this is and who asked to be told if
  someone used it. Better sent with findings than with intentions.
