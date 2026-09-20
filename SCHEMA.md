# Schema guide

The JSON Schemas in `schema/` are normative for structure. This document is normative
for meaning.

## Matching

An advisory is a predicate over `agent.lock` files.

```
affected      = every clause in affected.all holds
exempt        = any clause in notAffectedIf holds, or the lock postdates a server-side fix
AFFECTED      = affected and not exempt
```

Every clause evaluates to **true**, **false**, or **unknown**. Unknown means the lock
does not record the field the clause tests.

| `affected.all` | exemptions | Result |
| --- | --- | --- |
| all true | all false | **AFFECTED** |
| any false | — | clear |
| — | any true | clear |
| otherwise | | **POSSIBLE** |

A lockfile that omits a field must never read as safe. Missing data degrades to
POSSIBLE.

**Identity is not a property.** Missing `version`, `settings`, `grants`, `capabilities`
or `pinned` is *unknown*. Missing `source` on a tool is a *non-match* — an emitter
always knows what a tool is, and treating absent identity as unknown makes every
unlabelled tool "possibly" every package. One exception: a tool with no `source` whose
`name` equals the package name evaluates to unknown.

## Clauses

Each clause is an object with exactly one key.

| Clause | Holds when |
| --- | --- |
| `harness` | The lock's harness satisfies every listed field. |
| `tool` | **At least one** tool in the lock satisfies every listed field. |
| `toolset` | The **union** of capabilities across all tools satisfies the set matcher. |
| `runtime` | The lock's runtime satisfies every listed field. |
| `model` | `{"any": true}` always holds. Otherwise vendor / id / snapshot match. |
| `goal` | The goal's `properties` satisfy the set matcher. |
| `any` | At least one sub-clause holds. |
| `not` | The sub-clause does not hold. Unknown stays unknown. |

Use two `tool` clauses to require two specific tools together. Use `toolset` when the
dangerous combination can be spread across any tools — that is the usual case.

`model` and `goal` exist in the language but are unused: no finding in the phase 0 corpus
was conditioned on either. Prefer omitting the clause to writing `{"model": {"any": true}}`
unless model-independence is itself the point of the advisory.

### Matchers

| Form | Meaning |
| --- | --- |
| `"auto"`, `true`, `3` | equals |
| `{"in": [...]}` | is one of |
| `{"not": x}` | is present and not equal to `x` |
| `{"minCount": n}` | is a list or object with at least `n` entries |
| `{"exists": bool}` | the field is / is not recorded. The only matcher that is never unknown. |

Set matchers, for `capabilities` and goal `properties`: `{"includesAll": [...]}`,
`{"includesAny": [...]}`.

### Versions

`versions` is a list of ranges; a version is affected if it falls in **any** range. A
range is space-separated comparators that must **all** hold: `">=0.0.5 <0.1.16"`.
Comparison is over numeric dot-separated segments, zero-padded, so `1.3` equals `1.3.0`
and calendar versions such as `2025.12.18` work. Pre-release and build suffixes are
ignored.

## Vocabularies

Advisories may only depend on values listed here. Both lists are expected to grow;
additions need a record that requires them.

### Tool capabilities

| Capability | The tool can… |
| --- | --- |
| `ingests-untrusted-content` | return content that someone outside the operator's trust boundary can write: web pages, inbound email and messages, public issues, user-submitted records. |
| `reads-private-data` | read data the operator would not publish. |
| `external-egress` | cause data to reach a destination an attacker can read: HTTP requests, sent messages, public writes, rendered remote images. |
| `code-execution` | run commands or code. |
| `writes-filesystem` | create or modify files. |
| `writes-agent-config` | modify the agent's own configuration. |

The first three together are the pattern behind most records in the registry. A
capability describes what a tool *can* do as configured, not what it is meant for: a
database tool with write access to a table an attacker can read has `external-egress`.

**Capabilities cannot be emitted from a manifest.** They are a judgement and will need a
maintained catalogue mapping tool identities to capabilities. That catalogue does not
exist yet.

### Harness settings

An emitter maps the harness's native settings onto these keys.

| Key | Values | Meaning |
| --- | --- | --- |
| `toolApproval` | `always-ask`, `ask-once`, `auto` | Whether a human confirms tool calls. `ask-once` remembers approval per tool. |
| `configWriteApproval` | `ask`, `auto` | Whether the agent can change its own configuration unconfirmed. |
| `toolDefinitionPinning` | boolean | Whether a change to an approved tool's definition forces re-approval. |
| `projectConfigTrust` | `prompt-before-load`, `load-then-prompt`, `auto` | How configuration supplied by an opened project is treated. |
| `remoteContentRendering` | boolean | Whether agent output can make the client fetch attacker-chosen URLs. |

## Conventions

- **Tool identity** is a [package URL](https://github.com/package-url/purl-spec) in
  `source`: `pkg:npm/mcp-remote`, `pkg:pypi/mcp-server-git`,
  `pkg:github/github/github-mcp-server`. `name` is the operator's local label.
- **Harness identity** is a lowercase registry name: `cursor`, `claude-code`,
  `gemini-cli`. There is no controlled list yet; there will need to be one.
- **Grants** are free-form. Conventional keys so far: `readOnly` (boolean), `credential`
  (the role or key type, never the secret), `repoScope` (`single-repo`, `selected`,
  `all`), `read` / `write` (path lists), `networkEgress` (host list or `*`).
- **Hosted agents** set `harness.hosted: true` and usually have no `version`. Advisories
  for them carry `remediatedServerSide`; a lock generated after that date is clear.
- **Summaries describe conditions and impact.** Never a working payload.
- **`fixedBy` accepts a mitigation,** not only an upgrade. For configuration-native
  advisories there is no version to move to. `set` names the lock paths and values that
  clear the advisory, so a tool can one day propose the change.

## What a lock must not contain

No prompt text, no tool output, no secret values. `promptSha256` is a hash;
`secretsReachable` is names only. A lock has to be safe to hand to a registry, a vendor,
or an auditor.
