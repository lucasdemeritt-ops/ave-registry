#!/usr/bin/env python3
"""
Validate every advisory and example lockfile against the schemas, and enforce
the registry rules a JSON Schema cannot express.

    pip install jsonschema
    python tools/validate.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def check(validator, path: Path, doc) -> list[str]:
    return [f"{path.relative_to(ROOT)}: {'/'.join(map(str, e.path)) or '<root>'}: {e.message}"
            for e in validator.iter_errors(doc)]


def main() -> int:
    adv_validator = Draft202012Validator(load(ROOT / "schema" / "advisory.schema.json"), format_checker=FormatChecker())
    lock_validator = Draft202012Validator(load(ROOT / "schema" / "agent-lock.schema.json"), format_checker=FormatChecker())

    errors, seen = [], {}
    advisories = sorted((ROOT / "advisories").rglob("*.json"))
    for path in advisories:
        doc = load(path)
        errors += check(adv_validator, path, doc)
        # Identifiers are permanent: filename, id, and directory year must agree, and never repeat.
        if path.stem != doc.get("id"):
            errors.append(f"{path.relative_to(ROOT)}: filename does not match id {doc.get('id')}")
        if doc.get("id", "")[4:8] != path.parent.name:
            errors.append(f"{path.relative_to(ROOT)}: id year does not match directory {path.parent.name}")
        if doc.get("id") in seen:
            errors.append(f"{path.relative_to(ROOT)}: duplicate id, also in {seen[doc['id']]}")
        seen[doc.get("id")] = path.name

    locks = sorted((ROOT / "examples" / "locks").glob("*.json"))
    for path in locks:
        errors += check(lock_validator, path, load(path))

    # Benchmark results, once any exist. The schema itself is checked either way.
    res_schema = load(ROOT / "schema" / "susceptibility-result.schema.json")
    Draft202012Validator.check_schema(res_schema)
    res_validator = Draft202012Validator(res_schema, format_checker=FormatChecker())
    results = sorted((ROOT / "benchmark" / "results").glob("*.json"))
    for path in results:
        doc = load(path)
        errors += check(res_validator, path, doc)
        # A rate over the wrong denominator is the failure mode that silently
        # inverts the headline finding, so check it rather than trusting it.
        s, u = doc.get("susceptibility", {}), doc.get("utility", {})
        if s.get("eligible", 0) > u.get("benignPassed", 0):
            errors.append(f"{path.relative_to(ROOT)}: eligible exceeds benignPassed")
        # rate is stored rounded to 4dp, so tolerate half of that last place.
        if s.get("eligible") and abs(s["complied"] / s["eligible"] - s["rate"]) > 5e-5:
            errors.append(f"{path.relative_to(ROOT)}: susceptibility.rate is not complied/eligible")

    # OSV mirror: the parallel track must stay in sync with the advisories.
    # Regenerate in-memory and compare to what is committed, so a changed
    # advisory whose OSV form was not re-exported fails CI.
    import osv_export
    osv_dir = ROOT / "interop" / "osv"
    expected = {}
    for adv_path in sorted((ROOT / "advisories").rglob("AVE-*.json")):
        adv = load(adv_path)
        cls, package, versions, dropped = osv_export.classify(adv)
        if package is not None:
            expected[f"x_{adv['id']}.json"] = osv_export.to_osv(adv, package, versions, dropped)
    committed = {p.name: load(p) for p in osv_dir.glob("x_*.json")} if osv_dir.exists() else {}
    if committed.keys() != expected.keys():
        errors.append(f"interop/osv out of sync: run tools/osv_export.py --write "
                      f"(committed {len(committed)}, expected {len(expected)})")
    else:
        for name, doc in expected.items():
            if committed[name] != doc:
                errors.append(f"interop/osv/{name} stale: run tools/osv_export.py --write")

    for e in errors:
        print(f"ERROR  {e}")
    print(f"{len(advisories)} advisories, {len(locks)} example locks, "
          f"{len(results)} results, {len(expected)} OSV records, {len(errors)} error(s).")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
