"""
The OSV translation is a standing check on the project's premise (see
ALTERNATIVES.md), so its classification is pinned here. A new advisory must be
added to the expected class deliberately; a record silently changing class is
either a bug in the exporter or news about the premise.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import osv_export  # noqa: E402

EXPECTED = {
    "LOSSLESS": {"0010", "0012", "0013", "0014", "0016", "0017"},
    "LOSSY": {"0002", "0005", "0006", "0007", "0008", "0009"},
    "UNREPRESENTABLE": {"0001", "0003", "0004", "0011", "0015", "0018", "0019", "0020"},
}


def advisories():
    for path in sorted((ROOT / "advisories").rglob("AVE-*.json")):
        yield json.loads(path.read_text(encoding="utf-8"))


class Classification(unittest.TestCase):
    def test_every_record_is_in_its_expected_class(self):
        got = {k: set() for k in EXPECTED}
        for adv in advisories():
            got[osv_export.classify(adv)[0]].add(adv["id"][-4:])
        self.assertEqual(got, EXPECTED)

    def test_lossless_means_nothing_was_dropped(self):
        for adv in advisories():
            cls, package, versions, dropped = osv_export.classify(adv)
            if cls == "LOSSLESS":
                record = osv_export.to_osv(adv, package, versions, dropped)
                self.assertNotIn("database_specific", record["affected"][0], adv["id"])

    def test_lossy_records_carry_their_dropped_conditions(self):
        for adv in advisories():
            cls, package, versions, dropped = osv_export.classify(adv)
            if cls == "LOSSY":
                record = osv_export.to_osv(adv, package, versions, dropped)
                self.assertTrue(record["affected"][0]["database_specific"]
                                ["ave_conditions_not_expressible_in_osv"], adv["id"])


class Ranges(unittest.TestCase):
    def test_range_translation(self):
        events, exact = osv_export.to_osv_ranges([">=0.0.5 <0.1.16"])
        self.assertEqual(events, [{"introduced": "0.0.5"}, {"fixed": "0.1.16"}])
        events, exact = osv_export.to_osv_ranges(["<1.3.0"])
        self.assertEqual(events, [{"introduced": "0"}, {"fixed": "1.3.0"}])
        events, exact = osv_export.to_osv_ranges(["=1.84.0"])
        self.assertEqual((events, exact), ([], ["1.84.0"]))
        events, exact = osv_export.to_osv_ranges([">=1.0.16"])
        self.assertEqual(events, [{"introduced": "1.0.16"}])


if __name__ == "__main__":
    unittest.main()
