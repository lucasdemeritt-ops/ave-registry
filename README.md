# AVE — Agent Vulnerability and Exposure registry

**Status: phase 0 experiment. One maintainer, twenty records, no users. Read
[PHASE0-FINDINGS.md](PHASE0-FINDINGS.md) before trusting any of it.**

When an AI agent gets exploited, the flaw is often not in any one component. A token
scoped too widely, a tool that reads public content, and an approval prompt someone
clicked "always allow" on — each is fine alone, and together they leak your private
repositories. There is no patched version to move to, so there is no CVE, so there is
nothing for an operator to check against.

AVE is an attempt at the missing piece:

- **`agent.lock`** — a generated record of exactly what an agent deployment is made of:
  harness and version, tools with their versions, grants and capabilities, approval
  settings, runtime. It pins values, never ranges, and contains no prompt text.
- **Advisories** — each one a predicate over lockfiles, so whether you are affected is
  decided mechanically rather than by reading a blog post.
- **`audit.py`** — joins the two, locally. Nothing about your configuration leaves your
  machine.

```
$ python tools/audit.py examples/locks/

cursor-dev-workstation: 4 match(es)
  HIGH   AVE-2026-0002  Supabase MCP with service_role key exfiltrates database via injected row content
         Fix: Run the server in read-only mode
         Or:  Do not give an agent a service_role credential; use a role subject to row-level security
  HIGH   AVE-2026-0004  Cursor before 1.3 rewrites its MCP configuration from injected content (CurXecute)
         Fix: upgrade cursor to 1.3
  ...

hardened-support-agent: clear
```

## Where the idea came from

[@lizthedeveloper](https://www.instagram.com/reel/Dde4lvCCBl4/) proposed it in a
66-second reel on 19 September 2026 — a CVE for agent configurations, with a lockfile
rather than a manifest so you know the exact thing you ran — and gave it away to anyone
in AI safety who would build it. This is that. The idea is hers; the schema, the corpus,
and the mistakes are this project's.

## What phase 0 found

Twenty-one published findings were written up as advisories to test whether the idea
holds. Short version:

- **It holds, more narrowly than pitched.** 3 of 21 are configuration-native — no fix
  exists, no CVE was ever assigned, and AVE is the only way to express them. 6 more gain
  real precision from a second axis. 8 are ordinary component bugs that a CVE already
  covers.
- **Two of the four proposed axes did nothing.** No finding was conditioned on the model
  or the prompt. What matters is what the tools can do and whether a human confirms it.
  *(Corrected same day: this holds for the prompt, but the model axis read zero because
  every finding concerned hosted products, which cannot be pinned. Open-weight builds
  can. See the correction in the findings.)*
- **It uncovered two missing datasets.** Tool capabilities cannot be read off a manifest;
  they have to be catalogued. Neither that catalogue nor any model-susceptibility data
  exists. The registry is thin — the reference data under it is the substance.

## How this relates to other work

| Project | Asks | Relationship |
| --- | --- | --- |
| CVE / [OSV](https://osv.dev) | Is this package version vulnerable? | Pure-component records here should mirror these, not duplicate them. |
| [Agent Threat Rules](https://agentthreatrule.org) | Is an attack happening in this content? | Complementary — Sigma to our CVE. Advisories link to ATR rules under `detection`. |
| [Vulnerable MCP Project](https://vulnerablemcp.info) | What MCP vulnerabilities are known? | A catalogue for people to read. AVE is a format for machines to match. |
| SBOM / CycloneDX | What components are in this build? | Closest to the lockfile; does not record grants, approval policy, or tool capabilities. |

## Use it

```
python tools/audit.py <lockfile-or-directory>
python tools/audit.py my.lock --explain AVE-2026-0001     # why did this match?
python tools/audit.py locks/ --fail-on high               # CI gate, exit 1
python tools/audit.py locks/ --json

pip install jsonschema && python tools/validate.py        # schema + registry rules
python -m unittest discover tests
```

`audit.py` needs only the Python standard library. Matching is three-valued: a lockfile
that does not record a field reads as **MAYBE**, never as safe.

There is no lockfile emitter yet. Until there is, locks are written by hand against
[`schema/agent-lock.schema.json`](schema/agent-lock.schema.json); the files in
`examples/locks/` are illustrative, not real deployments.

## Layout

```
schema/        JSON Schema for agent.lock, advisories, and benchmark results
advisories/    the registry, one file per AVE id
examples/      sample lockfiles: vulnerable, hardened, patched, hosted, under-specified
tools/         audit.py (matcher), validate.py (schema + registry rules)
tests/         the expected-match matrix; doubles as the specificity test
benchmark/     model susceptibility track — SPEC.md only, nothing run yet
SCHEMA.md      matching semantics, vocabularies, conventions
```

## Second track: model susceptibility

[`benchmark/SPEC.md`](benchmark/SPEC.md) specifies a reproducible measurement of how
readily a **pinned** model artifact obeys injected instructions — aimed at quantized
builds and community fine-tunes, which nobody measures and everybody runs locally. It
reuses existing task suites rather than inventing a benchmark, and uses canary tool calls
so the verdict is a string match rather than a judgement.

Specification only. No results exist yet.

## Contributing, and reporting

See [CONTRIBUTING.md](CONTRIBUTING.md) for the review bar — in one line, *an advisory
that matches most deployments is worse than no advisory* — and
[DISCLOSURE.md](DISCLOSURE.md) before filing anything about a live deployment.

Identifiers become permanent at the first tagged release. Until then, expect renumbering.

## Licence

Code under MIT. Advisories and schemas under CC-BY-4.0. See [LICENSE](LICENSE).
