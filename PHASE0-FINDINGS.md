# Phase 0 findings

**Question.** Can published agent-security findings be written as predicates over a
configuration lockfile — and does doing so gain anything over a conventional CVE?

**Method.** 21 published findings, 2025–2026, each attempted as an `AVE` record against
the schema. Every record cites the write-up it was derived from. The kill criterion was
fixed before starting: *stop if fewer than half express without inventing new clause
types, or if most collapse to a single component and gain nothing over a CVE.*

**Result.** The gate passes, but the premise survives in a narrower form than the
original pitch. Two of the four proposed axes did no work at all.

## The tally

| Class | Count | Records | What AVE adds over a CVE |
| --- | --- | --- | --- |
| **A. Configuration-native** — no patched version exists; exposure is decided by grants, approval policy, and tool combination | 3 | 0001, 0002, 0003 | Everything. None of the three has a CVE, because there is no component to file against. |
| **B. Component plus condition** — a fix exists, but a second axis decides whether a deployment is actually exposed | 6 | 0004–0009 | Precision. Cursor <1.3 with no untrusted-content tool is not reachable by CurXecute; Semantic Kernel without the affected plugin is not affected. A CVE flags both. |
| **C. Pure component** — one package, one version range | 8 | 0010–0017 | Nothing but matchability against a lock. These should be mirrored from CVE/OSV, not hand-written. |
| **D. Hosted** — vendor-run agent, no operator-visible version | 3 | 0018–0020 | Little. Nothing to scan and nothing to do; the vendor fixed it server-side. Kept as a record of the pattern. |
| **E. Out of model** — not part of an agent configuration | 1 | none filed | MCP Inspector (CVE-2025-49596) is a developer tool. It never appears in a lock. |

Against the criterion: 8 of 21 collapse to a pure component (38%, not most). 10 of 21
needed nothing beyond the schema as first specified; the other 11 needed five additions
(below), all general — no advisory needed a bespoke clause.

## What the corpus says about the four axes

The original pitch named four axes: harness, model, goal, tools.

| Axis | Records that condition on it |
| --- | --- |
| Harness (name, version) | 14 |
| Tools (identity, version, or capabilities) | 12 |
| — of which tool capabilities | 7 |
| Harness approval settings | 4 |
| Tool grants | 2 |
| Runtime | 1 |
| **Model** | **0** |
| **Goal / prompt** | **0** |

Counted from the records by script, not by hand. Not one of 21 findings is conditioned
on a model or a prompt. Models plainly differ in how readily they follow injected instructions,
but no published finding says "affected on snapshot X, not on Y" — researchers
demonstrate on whatever model is to hand and the vulnerability is in the wiring.

**Consequence for v0.1:** model and goal stay in the lockfile for forensics and leave
the matching language unused. The open question in the spec — *does the prompt belong in
scope at all?* — is answered by the evidence: not for matching.

> ### Correction, same day
>
> The conclusion above is right about the goal axis and **wrong about the model axis**,
> for a reason stated in the Limits section below and then not acted on.
>
> All 21 findings concern frontier, mostly hosted products. The model axis read zero
> because a hosted model **cannot be pinned** — no stable identity, changed underneath
> you, fixed server-side. That is a fact about hosted deployment, not about models.
>
> Open weights invert it. A GGUF build has a SHA-256, never changes, and is reproducible
> indefinitely. The identity problem that killed the axis does not exist there.
>
> So the axis is not dead, it is **unmeasured** — over quantized builds and community
> fine-tunes deployed with tool access, a population the literature does not cover. The
> corpus could not have found this, because a finding about it would have to be measured
> rather than published, and nobody is measuring.
>
> Revised: **drop goal from the matching language, keep model for pinnable artifacts.**
> The data that would make a `model` clause meaningful does not exist yet, so the clause
> stays unused in practice until it does. See [benchmark/SPEC.md](benchmark/SPEC.md).

What does the work instead is a thing the pitch did not name: **what the tools can do
and whether a human confirms it.** The recurring shape across classes A, B and D is a
toolset that can read untrusted content, read private data, and send data out, with no
confirmation between them.

## Five additions the corpus forced

1. **Tool capability classes and a `toolset` clause.** Needed by 7 records. "GitHub MCP
   plus auto-approve" can name a tool; ShadowLeak cannot — the researchers note any data
   connector gives the same shape. The combination has to be expressed over what tools
   *can do*, unioned across the toolset. Six capabilities cover the corpus.
2. **A normalized settings vocabulary.** Needed by 4. Every harness names its approval
   setting differently. An advisory written against native keys is a per-harness
   advisory; `toolApproval`, `configWriteApproval`, `toolDefinitionPinning`,
   `projectConfigTrust`, `remoteContentRendering` are harness-independent.
3. **Multiple version ranges.** GitLab ships fixes on three release lines at once.
4. **Time-based matching for hosted agents.** No version to compare, so a lock is
   cleared by being generated after the vendor's remediation date.
5. **Identity is not a property.** Found by running the matcher, not by writing records.
   With naive three-valued logic, a built-in terminal tool with no `source` field read
   as "possibly mcp-remote" and every lock lit up with 3–8 false maybes. A missing
   *property* is unknown; a missing *identity* is a non-match.

## The dependency this uncovered

**Capabilities cannot be emitted; they have to be catalogued.** A lockfile emitter can
read a version from a manifest. It cannot introspect whether a tool "ingests untrusted
content." That is a judgement about what the tool does, and classes A and B — where AVE
earns its keep — depend on it entirely.

So the registry needs a second dataset: a catalogue mapping tool identities (purls) to
capabilities, maintained the same way as advisories. This was not in the roadmap and it
is now the largest open piece of work. It is also the most reusable output — a
capability catalogue for MCP servers is useful to people who never touch the registry.

## Does it match narrowly?

Seven example lockfiles, 140 advisory–lock pairs, asserted in `tests/test_audit.py`:

| Lock | Affected | Possible |
| --- | --- | --- |
| cursor-dev-workstation | 0002, 0003, 0004, 0011 | — |
| claude-desktop-github | 0001 | — |
| gemini-cli-unsandboxed | 0010 | — |
| hardened-support-agent | — | — |
| ci-coding-agent-patched | — | — |
| hosted-deep-research-today | — | — |
| partial-lock-minimal-emitter | — | 0003, 0004, 0011 |

Hardened and patched deployments are clear; an under-specified lock degrades to
*possible* rather than reading as safe. The broadest record is 0003 (unpinned MCP server),
and it is the one to watch.

**This is weak evidence and should be read as such.** The locks were written by the same
person who wrote the advisories, with the advisories in view. It shows the matcher is
correct, not that the advisories are narrow in the wild. That test is phase 2: a real
deployment, emitted by a tool, scanned cold.

## Limits

- **Sampling bias.** Findings were chosen for being well documented, which over-selects
  CVE-bearing component bugs. Configuration-native findings are under-reported *because*
  they have no identifier to be indexed under. 3 of 21 is not a population estimate, in
  either direction.
- **One author.** Every record was written and reviewed by one person in one sitting.
  The phase 1 gate — can a stranger write a valid advisory from the schema alone — is
  untested.
- **Unverified details,** flagged in the records themselves: 0006 has no exact fixed
  version in the sources reviewed and matches on a setting instead; 0015's fix is
  described per release line rather than as a version; 0016 assumes every release from
  1.0.16 is malicious.
- **No generic "lethal trifecta" advisory was filed,** deliberately. A record matching
  any toolset with all three capabilities would hit most real deployments and train
  people to ignore the tool. The pattern is a weakness class, like a CWE; instances get
  advisories.

## What changes in the roadmap

1. Drop **goal** from the v0.1 matching language. Keep **model**, scoped to pinnable
   artifacts — see the correction above and [benchmark/SPEC.md](benchmark/SPEC.md).
2. Add the capability catalogue as a first-class dataset, ahead of the emitter.
3. Source class C by mirroring OSV/CVE; spend human review on classes A and B.
4. Deprioritize hosted agents.
5. Link out to [Agent Threat Rules](https://agentthreatrule.org) for detection. ATR asks
   *is an attack happening in this content?* AVE asks *is this deployment configured in a
   known-exploitable way?* — Sigma to our CVE. Record 0004 already cites an ATR rule.
