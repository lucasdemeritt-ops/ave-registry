#!/usr/bin/env python3
"""
Summarize susceptibility results with uncertainty.

    python benchmark/analyze.py

A rate from 24 cases carries a very wide interval, and reporting bare
percentages invites reading noise as signal. This prints Wilson score intervals
and a two-tailed Fisher exact test for the widest observed pair, so the
write-up can say whether anything was actually resolved.

Standard library only.
"""

from __future__ import annotations

import json
import math
from itertools import combinations
from pathlib import Path

RESULTS = Path(__file__).resolve().parent / "results"
Z = 1.959963985  # 95%

# Ordered least to most faithful to the original weights.
ORDER = ["Q4_K_M", "Q5_K_M", "Q6_K", "Q8_0", "FP16"]


def wilson(k: int, n: int) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + Z * Z / n
    centre = (p + Z * Z / (2 * n)) / d
    half = Z / d * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n))
    return (max(0.0, centre - half), min(1.0, centre + half))


def _hyper(a: int, b: int, c: int, d: int) -> float:
    n = a + b + c + d
    return (math.comb(a + b, a) * math.comb(c + d, c)) / math.comb(n, a + c)


def fisher_two_tailed(a: int, b: int, c: int, d: int) -> float:
    """P of tables at most as probable as the observed one, margins fixed."""
    observed = _hyper(a, b, c, d)
    row1, col1, n = a + b, a + c, a + b + c + d
    total = 0.0
    for x in range(max(0, col1 - (n - row1)), min(row1, col1) + 1):
        p = _hyper(x, row1 - x, col1 - x, (n - row1) - (col1 - x))
        if p <= observed * (1 + 1e-9):
            total += p
    return min(1.0, total)


def main() -> int:
    rows = []
    for path in sorted(RESULTS.glob("*.json")):
        r = json.loads(path.read_text(encoding="utf-8-sig"))
        s, u = r["susceptibility"], r["utility"]
        rows.append({
            "quant": r["model"]["quantization"],
            "base": r["model"]["baseModel"],
            "complied": s["complied"], "eligible": s["eligible"], "rate": s["rate"],
            "benign": u["benignPassed"], "benignTotal": u["benignTotal"],
            "byTechnique": s.get("byTechnique", {}),
        })
    rows.sort(key=lambda r: ORDER.index(r["quant"]) if r["quant"] in ORDER else 99)
    if not rows:
        print("no results")
        return 1

    print(f"{rows[0]['base']}  -  canary-v1, 24 cases per build\n")
    print(f"{'quant':<9} {'utility':>9}  {'susceptible':>12}  {'rate':>7}   95% CI (Wilson)")
    print("-" * 66)
    for r in rows:
        lo, hi = wilson(r["complied"], r["eligible"])
        print(f"{r['quant']:<9} {r['benign']:>4}/{r['benignTotal']:<4} "
              f"{r['complied']:>6}/{r['eligible']:<5} {r['rate']*100:>6.1f}%   "
              f"[{lo*100:4.1f}%, {hi*100:4.1f}%]")

    # The widest pair is chosen AFTER seeing the data, so its nominal p is
    # optimistic: with k builds there are k(k-1)/2 pairs and we report the
    # extreme one. Compare against a Bonferroni-corrected threshold.
    pairs = list(combinations(rows, 2))
    x, y = max(pairs, key=lambda pr: abs(pr[0]["rate"] - pr[1]["rate"]))
    p = fisher_two_tailed(x["complied"], x["eligible"] - x["complied"],
                          y["complied"], y["eligible"] - y["complied"])
    thresh = 0.05 / len(pairs)
    print(f"\nWidest gap: {x['quant']} ({x['rate']*100:.1f}%) vs {y['quant']} ({y['rate']*100:.1f}%)"
          f"   Fisher exact two-tailed p = {p:.3f}")
    print(f"Selected post hoc from {len(pairs)} pairs, so the threshold is "
          f"0.05/{len(pairs)} = {thresh:.4f}.")
    print("  -> significant after correction" if p < thresh else
          "  -> NOT significant after correction; this suite cannot resolve a gap this size")

    techs = sorted({t for r in rows for t in r["byTechnique"]})
    if techs:
        print(f"\n{'technique':<22}" + "".join(f"{r['quant']:>9}" for r in rows))
        print("-" * (22 + 9 * len(rows)))
        for t in techs:
            print(f"{t:<22}" + "".join(f"{r['byTechnique'].get(t, 0)*100:>8.0f}%" for r in rows))

    # Which content channel carried the successful injections? A uniform rate
    # across techniques usually means one channel is doing all the work.
    tdir = Path(__file__).resolve().parent / "transcripts"
    by_channel: dict[str, dict[str, int]] = {}
    for r in rows:
        path = tdir / f"{r['base']}-{r['quant']}-canary-v1.json"
        if not path.exists():
            continue
        for rec in json.loads(path.read_text(encoding="utf-8-sig")):
            ch = rec["case"].split("--", 1)[0]
            by_channel.setdefault(ch, {})[r["quant"]] = (
                by_channel.setdefault(ch, {}).get(r["quant"], 0) + int(rec["attackComplied"]))
    if by_channel:
        print(f"\n{'channel (of 6 techniques)':<26}" + "".join(f"{r['quant']:>9}" for r in rows))
        print("-" * (26 + 9 * len(rows)))
        for ch in sorted(by_channel):
            print(f"{ch:<26}" + "".join(f"{by_channel[ch].get(r['quant'], 0):>9}" for r in rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
