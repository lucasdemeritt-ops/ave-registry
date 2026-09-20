# Disclosure policy

A precise, machine-readable map of exploitable configurations is also a targeting list.
Unlike a conventional CVE, many records here have no patched version to move to — the
fix is a settings change each operator makes by hand. This policy exists so that
difference is handled deliberately.

*Written while nothing is at stake, on purpose. It will be wrong in places; change it by
pull request, not under pressure.*

## What the registry publishes

**Already-public findings** are filed at once. The seed corpus is entirely this.

**New findings** — ones with no public write-up — are not filed by pull request. Report
them privately through GitHub's private vulnerability reporting on this repository
(Security tab, "Report a vulnerability"). They are held under embargo:

- **Component fix possible:** until the vendor ships it, or 90 days, whichever is first.
- **Configuration-native, no fix possible:** 30 days after the affected vendor and any
  identifiable operators are notified, so they can change settings before the conditions
  are published.

## What a record contains

Conditions and impact. Never a working payload, injection text, or reproduction steps
beyond what a cited public source already contains. If a record cannot be made useful
without exploit detail, it is not ready.

## When a vendor disagrees

A vendor may contest any advisory by opening an issue. The outcome is published either
way:

- If the record is wrong, it is corrected or withdrawn, keeping its id and a note.
- If the record is accurate, it stays, and the vendor's position is linked from it.

An advisory that names a vendor's **default** configuration is the case most likely to
be contested. The test is only whether the stated conditions produce the stated impact.
Whether the vendor considers the behaviour intended is recorded, and does not decide
inclusion.

## What this registry is not

Not a bug bounty, not a CNA, and not run by an organisation. At present it is one person
merging pull requests. That is stated here so nobody infers otherwise from an
official-looking identifier.
