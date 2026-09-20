# Alternatives considered

A new registry is the expensive answer. This document records the cheaper ones, what was
done to test them, and what evidence would make this project switch to one of them.

## The alternatives

| | Idea | Status |
| --- | --- | --- |
| **A** | **Extend OSV.** Don't build a registry; express agent findings as OSV records and propose whatever fields are missing. | **Tested — see below. Runs in parallel as a standing check.** |
| **B** | **Use CVE as-is.** CVE can name anything, including desktop apps and hosted services, and to our understanding its CPE applicability statements can express "product A together with product B". | Untested. Expected to cover component co-presence but not settings, grants, capabilities or approval policy. A translation experiment like A's is the next one to run. |
| **C** | **Detection only.** [Agent Threat Rules](https://agentthreatrule.org) already detects attacks in content at runtime. Maybe exposure data is unnecessary. | Complementary rather than competing: detection says an attack is happening, exposure says you are configured to be hurt by it. Advisories link ATR rules under `detection`. |
| **D** | **Extend SBOM / CycloneDX.** The lockfile half resembles an SBOM. | Not yet examined in detail. An SBOM inventories components; it has no place for grants, approval policy or tool capabilities, and nothing matches it against advisories. Worth a proper look before the lockfile format is frozen. |
| **E** | **Do nothing.** Findings stay as blog posts. | The status quo this project exists to test against. |

## Alternative A, tested

Phase 0 ended on a caveat: if findings keep collapsing to "this package at this version is
broken", the right move is contributing to OSV rather than standing up a registry. That is
testable, so it was tested.

**Method.** `tools/osv_export.py` translates every advisory into an OSV record and sorts it
into one of three classes by fixed rules — no judgement per record:

- **LOSSLESS** — one package in an OSV ecosystem, a version range, no other condition.
- **LOSSY** — the package can be named, but conditions that decide real exposure can only
  ride along in `database_specific`, which the OSV schema documents as informational and
  which OSV matchers do not act on. The record over-matches.
- **UNREPRESENTABLE** — nothing to name: a desktop app or hosted service outside every OSV
  ecosystem, or no single component at all.

All generated records validate against the official OSV JSON schema.

**Result, 20 advisories:**

| Class | Count | Records |
| --- | --- | --- |
| LOSSLESS | 6 | 0010, 0012, 0013, 0014, 0016, 0017 |
| LOSSY | 6 | 0002, 0005, 0006, 0007, 0008, 0009 |
| UNREPRESENTABLE | 8 | 0001, 0003, 0004, 0011, 0015, 0018, 0019, 0020 |

**What it shows.** OSV carries 30% of the corpus completely. For another 30% it can name
the package but must drop the conditions — and the dropped conditions are exactly the
point. Record 0002 becomes "every version of the Supabase MCP server is vulnerable", which
is false: the exposure is a `service_role` credential with writes enabled. Two of the six
lossy records have no version range at all, so the OSV form flags every version forever.
The remaining 40% cannot be written down, including all three configuration-native
findings that motivated the project.

So on current evidence, extending OSV is **not sufficient** — and the gap is not a few
missing fields. It is that OSV's unit is a package and the unit here is a combination,
and that OSV's extension point is ignored by the tools that consume it.

**Limits of this test.**

- 20 records, one author, selected for being well documented. The shares are not
  population estimates.
- The harness-to-package mapping table is ours. A different table moves records between
  classes at the margin.
- OSV accepts new ecosystems by pull request, and a git-range record can name a repository
  without an ecosystem. Both would move some UNREPRESENTABLE records to LOSSY. Neither
  moves anything to LOSSLESS, because the blocker for those records is conditions, not
  naming.
- "Matchers ignore `database_specific`" is how the schema documents the field. A consumer
  could choose to act on it; none we know of does.

## Why it runs in parallel anyway

Building the OSV bridge was cheap, and it pays in both worlds:

- **If this project is right,** the six lossless records still belong in OSV-compatible
  form, so existing scanners can use them today without knowing AVE exists. The roadmap
  already planned to mirror component bugs *from* OSV; this is the same bridge in the other
  direction.
- **If this project is wrong,** the exporter is the migration path, and the lossy records'
  `database_specific` payloads are the concrete field proposal to take to OSV.
- **Either way,** the class shares are a standing measurement. Every new advisory changes
  them, and they say whether the registry is earning its existence.

Publishing under a real OSV id would need a registered database prefix; records currently
carry the `x_` prefix the schema reserves for unregistered sources.

## What would make this project switch

Decided now, before there is anything invested in the answer:

- **Switch to A** if LOSSLESS becomes the clear majority as the corpus grows past its
  current sampling bias — meaning real-world findings are mostly package bugs after all —
  or if OSV consumers begin acting on condition fields, which removes the over-matching
  problem.
- **Switch to B** if the CVE translation experiment shows CPE applicability can carry the
  conditions that matter. We expect it cannot express settings or grants, but that is an
  expectation, not a result.
- **Stay the course** while configuration-native and condition-dependent findings remain a
  substantial share and no existing format can express them without over-matching.

The honest summary today: the alternative was tried rather than dismissed, it covers less
than a third of the evidence, and it stays wired in as a check on us.
