#!/usr/bin/env python3
"""
agent-audit — match agent.lock files against the AVE registry.

Runs entirely locally. Standard library only. Nothing about your
configuration leaves the machine.

    python tools/audit.py examples/locks/
    python tools/audit.py my-agent.lock --explain AVE-2026-0001
    python tools/audit.py runs/ --fail-on high        # CI gate

Matching is three-valued. A clause is TRUE, FALSE, or UNKNOWN — unknown when
the lock does not record the field the clause tests. A lock is:

    AFFECTED   every clause TRUE and no exemption applies
    POSSIBLE   no clause FALSE, but at least one UNKNOWN
    (clear)    any clause FALSE, or an exemption is TRUE

A lockfile that omits a field must never read as safe, so missing data
degrades to POSSIBLE rather than to clear.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

TRUE, FALSE, UNKNOWN = "true", "false", "unknown"
SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


# ── three-valued logic ───────────────────────────────────────────────────────

def all_of(values):
    values = list(values)
    if FALSE in values:
        return FALSE
    return UNKNOWN if UNKNOWN in values else TRUE


def any_of(values):
    values = list(values)
    if TRUE in values:
        return TRUE
    return UNKNOWN if UNKNOWN in values else FALSE


def negate(value):
    return {TRUE: FALSE, FALSE: TRUE}.get(value, UNKNOWN)


def tv(condition: bool) -> str:
    return TRUE if condition else FALSE


# ── versions ─────────────────────────────────────────────────────────────────

_COMPARATOR = re.compile(r"^(>=|<=|>|<|=)(.+)$")


def parse_version(text: str) -> tuple:
    """Numeric release segments only: '1.0.111' and calver '2025.12.18' both
    work; pre-release/build suffixes are ignored."""
    release = re.split(r"[-+]", text.strip().lstrip("v"), maxsplit=1)[0]
    return tuple(int(p) for p in release.split(".") if p.isdigit())


def _cmp(a: tuple, b: tuple) -> int:
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def version_in_ranges(version, ranges) -> str:
    if version is None:
        return UNKNOWN
    have = parse_version(str(version))
    if not have:
        return UNKNOWN
    for rng in ranges:
        ok = True
        for part in rng.split():
            op, want = _COMPARATOR.match(part).groups()
            c = _cmp(have, parse_version(want))
            ok = ok and {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0, "=": c == 0}[op]
        if ok:
            return TRUE
    return FALSE


# ── field matchers ───────────────────────────────────────────────────────────

def match_name(actual, expected) -> str:
    if actual is None:
        return UNKNOWN
    names = [expected] if isinstance(expected, str) else expected
    return tv(str(actual).lower() in {n.lower() for n in names})


def match_value(actual, matcher, present: bool) -> str:
    if isinstance(matcher, dict):
        (op, arg), = matcher.items()
        if op == "exists":
            return tv(present == arg)
        if not present:
            return UNKNOWN
        if op == "in":
            return tv(actual in arg)
        if op == "not":
            return tv(actual != arg)
        if op == "minCount":
            return tv(isinstance(actual, (list, dict)) and len(actual) >= arg)
        raise ValueError(f"unknown matcher op: {op}")
    if not present:
        return UNKNOWN
    return tv(actual == matcher)


def match_fields(obj: dict, spec: dict) -> str:
    return all_of(match_value(obj.get(k), m, k in obj) for k, m in spec.items())


def match_set(actual, spec: dict) -> str:
    if actual is None:
        return UNKNOWN
    have = set(actual)
    results = []
    if "includesAll" in spec:
        results.append(tv(set(spec["includesAll"]) <= have))
    if "includesAny" in spec:
        results.append(tv(bool(set(spec["includesAny"]) & have)))
    return all_of(results)


# ── clauses ──────────────────────────────────────────────────────────────────

def eval_harness(spec, lock):
    h = lock.get("harness", {})
    out = []
    if "name" in spec:
        out.append(match_name(h.get("name"), spec["name"]))
    if "versions" in spec:
        # A hosted agent has no operator-visible version; that is UNKNOWN, not clear.
        out.append(version_in_ranges(h.get("version"), spec["versions"]))
    if "hosted" in spec:
        out.append(match_value(h.get("hosted"), spec["hosted"], "hosted" in h))
    if "settings" in spec:
        out.append(match_fields(h.get("settings", {}), spec["settings"]))
    return all_of(out)


def eval_model(spec, lock):
    if spec.get("any"):
        return TRUE
    m = lock.get("model", {})
    return all_of(match_name(m.get(k), v) for k, v in spec.items())


def match_source(tool, expected) -> str:
    """Identity is not a property. An emitter may not know a tool's grants, but
    it always knows what the tool is, so a missing `source` is a non-match, not
    an unknown - otherwise every unlabelled tool 'might be' every package. The
    one exception: no source recorded, but the name equals the package name."""
    if tool.get("source") is not None:
        return match_name(tool["source"], expected)
    purls = [expected] if isinstance(expected, str) else expected
    tails = {p.rsplit("/", 1)[-1].lower() for p in purls}
    return UNKNOWN if str(tool.get("name", "")).lower() in tails else FALSE


def eval_one_tool(spec, tool):
    out = []
    if "name" in spec:
        out.append(match_name(tool.get("name"), spec["name"]))
    if "source" in spec:
        out.append(match_source(tool, spec["source"]))
    if "versions" in spec:
        out.append(version_in_ranges(tool.get("version"), spec["versions"]))
    if "transport" in spec:
        out.append(match_value(tool.get("transport"), spec["transport"], "transport" in tool))
    if "pinned" in spec:
        out.append(match_value(tool.get("pinned"), spec["pinned"], "pinned" in tool))
    if "capabilities" in spec:
        out.append(match_set(tool.get("capabilities"), spec["capabilities"]))
    if "grants" in spec:
        out.append(match_fields(tool.get("grants", {}), spec["grants"]))
    return all_of(out)


def eval_tool(spec, lock):
    tools = lock.get("tools", [])
    return any_of(eval_one_tool(spec, t) for t in tools) if tools else FALSE


def eval_toolset(spec, lock):
    tools = lock.get("tools", [])
    union = set()
    for t in tools:
        union |= set(t.get("capabilities", []))
    result = match_set(union, spec["capabilities"])
    if result == FALSE and any("capabilities" not in t for t in tools):
        return UNKNOWN  # an unclassified tool might supply the missing capability
    return result


def eval_runtime(spec, lock):
    return match_fields(lock.get("runtime", {}), spec)


def eval_goal(spec, lock):
    return match_set(lock.get("goal", {}).get("properties"), spec["properties"])


def eval_clause(clause, lock):
    (kind, spec), = clause.items()
    if kind == "any":
        return any_of(eval_clause(c, lock) for c in spec)
    if kind == "not":
        return negate(eval_clause(spec, lock))
    return {
        "harness": eval_harness, "model": eval_model, "tool": eval_tool,
        "toolset": eval_toolset, "runtime": eval_runtime, "goal": eval_goal,
    }[kind](spec, lock)


# ── advisories ───────────────────────────────────────────────────────────────

def remediated_before(advisory, lock):
    """Hosted agents have no version to match, so a vendor-side fix is matched
    on time instead: a lock generated after the remediation date is clear.
    Dates may be partial ('2025-08'); an undated lock is UNKNOWN."""
    dates = [f["remediatedServerSide"] for f in advisory["fixedBy"] if "remediatedServerSide" in f]
    if not dates:
        return None
    fixed = max(dates)
    generated = lock.get("generated")
    if not generated:
        return fixed, UNKNOWN
    prefix = generated[:len(fixed)]
    if prefix > fixed:
        return fixed, TRUE
    return fixed, (UNKNOWN if prefix == fixed else FALSE)


def evaluate(advisory, lock):
    """Returns (status, clause_results, exemption_results); status is
    'affected', 'possible', or None."""
    clauses = [(c, eval_clause(c, lock)) for c in advisory["affected"]["all"]]
    exempt = [(c, eval_clause(c, lock)) for c in advisory.get("notAffectedIf", [])]
    hit = all_of(r for _, r in clauses)
    out = any_of(r for _, r in exempt) if exempt else FALSE
    remediated = remediated_before(advisory, lock)
    if remediated is not None:
        exempt.append(({"remediatedServerSide": remediated[0]}, remediated[1]))
        out = any_of([out, remediated[1]])
    if hit == FALSE or out == TRUE:
        status = None
    elif hit == TRUE and out == FALSE:
        status = "affected"
    else:
        status = "possible"
    return status, clauses, exempt


def load_registry(path: Path):
    advisories = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(path.rglob("AVE-*.json"))]
    return sorted(advisories, key=lambda a: a["id"])


def load_locks(paths):
    for raw in paths:
        p = Path(raw)
        files = sorted(p.rglob("*.json")) + sorted(p.rglob("*.lock")) if p.is_dir() else [p]
        for f in files:
            yield f, json.loads(f.read_text(encoding="utf-8"))


def describe_fix(fix) -> str:
    if "upgrade" in fix:
        u = fix["upgrade"]
        return f"upgrade {u['name']} to {u['version']}"
    if "mitigation" in fix:
        return fix["mitigation"]
    return f"fixed server-side {fix['remediatedServerSide']}; no operator action"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Match agent.lock files against the AVE registry.")
    ap.add_argument("locks", nargs="+", help="lockfiles or directories of them")
    ap.add_argument("--registry", default=str(Path(__file__).resolve().parent.parent / "advisories"))
    ap.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if an AFFECTED match is at or above this severity")
    ap.add_argument("--explain", metavar="AVE-ID", help="show clause-by-clause reasoning for one advisory")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    registry = load_registry(Path(args.registry))
    locks = list(load_locks(args.locks))
    report, worst = [], -1

    for path, lock in locks:
        label = lock.get("label") or path.stem
        for adv in registry:
            if args.explain and adv["id"] != args.explain:
                continue
            status, clauses, exempt = evaluate(adv, lock)
            if args.explain:
                print(f"{adv['id']} against {label}: {status or 'clear'}")
                for c, r in clauses:
                    print(f"  [{r:>7}] {json.dumps(c)}")
                for c, r in exempt:
                    print(f"  [{r:>7}] exempt-if {json.dumps(c)}")
                print()
                continue
            if status:
                report.append({"lock": label, "id": adv["id"], "status": status,
                               "severity": adv["severity"], "title": adv["title"],
                               "fix": [describe_fix(f) for f in adv["fixedBy"]]})
                if status == "affected":
                    worst = max(worst, SEVERITY_ORDER[adv["severity"]])

    if args.explain:
        return 0

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Scanned {len(locks)} lockfile(s) against {len(registry)} advisories.\n")
        for path, lock in locks:
            label = lock.get("label") or path.stem
            rows = [r for r in report if r["lock"] == label]
            print(f"{label}: {'clear' if not rows else f'{len(rows)} match(es)'}")
            for r in sorted(rows, key=lambda r: (r["status"] != "affected", -SEVERITY_ORDER[r["severity"]])):
                tag = r["severity"].upper() if r["status"] == "affected" else "MAYBE"
                print(f"  {tag:<6} {r['id']}  {r['title']}")
                for i, fix in enumerate(r["fix"]):
                    print(f"         {'Fix:' if i == 0 else 'Or: '} {fix}")
            print()

    if args.fail_on and worst >= SEVERITY_ORDER[args.fail_on]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
