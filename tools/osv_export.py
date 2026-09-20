#!/usr/bin/env python3
"""
Translate every AVE advisory into an OSV record and measure what is lost.

    python tools/osv_export.py            # report only
    python tools/osv_export.py --write    # also write interop/osv/*.json

This is the standing test of the project's main alternative: "don't build a
registry, extend OSV." OSV is package-centric and its matchers ignore
database_specific, so each advisory lands in one of three classes, decided
mechanically:

  LOSSLESS         one package in an OSV ecosystem, a version range, and no
                   other condition. OSV says everything AVE says.
  LOSSY            the package can be named, but conditions that decide real
                   exposure (settings, grants, capabilities, co-present tools,
                   exemptions) can only ride along in database_specific, which
                   OSV consumers do not act on. The record over-matches.
  UNREPRESENTABLE  nothing to name: a desktop app or hosted service outside
                   every OSV ecosystem, or no single component at all.

If LOSSLESS ever dominates the registry, the alternative wins and this project
should become an OSV contribution. See ALTERNATIVES.md.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Registry harness name -> (OSV ecosystem, package name). Absent = not a package
# in any OSV ecosystem (desktop applications, hosted services, server products).
HARNESS_PACKAGES = {
    "claude-code": ("npm", "@anthropic-ai/claude-code"),
    "gemini-cli": ("npm", "@google/gemini-cli"),
    "langflow": ("PyPI", "langflow"),
    "semantic-kernel-python": ("PyPI", "semantic-kernel"),
    "semantic-kernel-dotnet": ("NuGet", "Microsoft.SemanticKernel"),
    "amazon-q-vscode": ("VSCode", "amazonwebservices.amazon-q-vscode"),
    "github-copilot-chat": ("VSCode", "GitHub.copilot-chat"),
}
PURL_ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI", "nuget": "NuGet", "cargo": "crates.io", "gem": "RubyGems"}

_CMP = re.compile(r"^(>=|<=|>|<|=)(.+)$")


def purl_to_package(purl: str):
    m = re.match(r"^pkg:([^/]+)/(.+)$", purl)
    if not m or m.group(1) not in PURL_ECOSYSTEMS:
        return None
    return PURL_ECOSYSTEMS[m.group(1)], m.group(2)


def first(value):
    return value[0] if isinstance(value, list) else value


def primary_component(advisory):
    """The first clause that names something OSV could call a package.
    Returns (clause_index, package | None, versions | None)."""
    for i, clause in enumerate(advisory["affected"]["all"]):
        (kind, spec), = clause.items()
        if kind == "harness" and "name" in spec:
            return i, HARNESS_PACKAGES.get(first(spec["name"])), spec.get("versions")
        if kind == "tool" and "source" in spec:
            return i, purl_to_package(first(spec["source"])), spec.get("versions")
    return None, None, None


def extra_conditions(advisory, primary_index):
    """Everything that is not the primary component's identity and versions."""
    dropped = []
    for i, clause in enumerate(advisory["affected"]["all"]):
        (kind, spec), = clause.items()
        if kind == "model" and spec.get("any"):
            continue  # says nothing; nothing to lose
        if i == primary_index:
            rest = {k: v for k, v in spec.items() if k not in ("name", "source", "versions")}
            if rest:
                dropped.append({kind: rest})
        else:
            dropped.append(clause)
    dropped += [{"notAffectedIf": c} for c in advisory.get("notAffectedIf", [])]
    return dropped


def to_osv_ranges(versions):
    events, exact = [], []
    for rng in versions:
        ev = {}
        for part in rng.split():
            op, v = _CMP.match(part).groups()
            if op == "=":
                exact.append(v)
            elif op == ">=":
                ev["introduced"] = v
            elif op == "<":
                ev["fixed"] = v
            elif op == "<=":
                ev["last_affected"] = v
        if ev:
            events.append({"introduced": ev.pop("introduced", "0")})
            events += [{k: v} for k, v in ev.items()]
    return events, exact


def classify(advisory):
    idx, package, versions = primary_component(advisory)
    if package is None:
        return "UNREPRESENTABLE", None, None, []
    dropped = extra_conditions(advisory, idx)
    if versions and not dropped:
        return "LOSSLESS", package, versions, []
    return "LOSSY", package, versions, dropped


def to_osv(advisory, package, versions, dropped):
    affected = {"package": {"ecosystem": package[0], "name": package[1]}}
    if versions:
        events, exact = to_osv_ranges(versions)
        if events:
            affected["ranges"] = [{"type": "ECOSYSTEM", "events": events}]
        if exact:
            affected["versions"] = exact
    else:
        # No version condition exists, so OSV can only say "every version".
        affected["ranges"] = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
    if dropped:
        affected["database_specific"] = {
            "ave_conditions_not_expressible_in_osv": dropped,
            "warning": "OSV matchers ignore this field; this record over-matches without it.",
        }
    record = {
        "schema_version": "1.6.0",
        # OSV only accepts ids from registered databases; "x_" marks an
        # unregistered one. Registering a prefix is a step on the OSV path.
        "id": "x_" + advisory["id"],
        "published": advisory["published"] + "T00:00:00Z",
        "modified": advisory.get("modified", advisory["published"]) + "T00:00:00Z",
        "summary": advisory["title"],
        "details": advisory["summary"],
        "affected": [affected],
        "references": [{"type": "ARTICLE", "url": u} for u in advisory["references"]],
    }
    if advisory.get("aliases"):
        record["aliases"] = advisory["aliases"]
    if advisory.get("credit"):
        record["credits"] = [{"name": c} for c in advisory["credit"]]
    return record


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="write interop/osv/*.json")
    args = ap.parse_args()

    out = ROOT / "interop" / "osv"
    tally = {"LOSSLESS": [], "LOSSY": [], "UNREPRESENTABLE": []}
    for path in sorted((ROOT / "advisories").rglob("AVE-*.json")):
        adv = json.loads(path.read_text(encoding="utf-8"))
        cls, package, versions, dropped = classify(adv)
        tally[cls].append(adv["id"])
        note = ""
        if cls == "LOSSY":
            note = f"drops {len(dropped)} condition(s)" + ("" if versions else "; NO version range - flags every version")
        elif cls == "UNREPRESENTABLE":
            note = "no package in any OSV ecosystem"
        print(f"{adv['id']}  {cls:<16} {note}")
        if args.write and package:
            out.mkdir(parents=True, exist_ok=True)
            (out / f"{adv['id']}.json").write_text(
                json.dumps(to_osv(adv, package, versions, dropped), indent=2) + "\n", encoding="utf-8")

    total = sum(len(v) for v in tally.values())
    print()
    for cls, ids in tally.items():
        print(f"{cls:<16} {len(ids):>2} / {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
