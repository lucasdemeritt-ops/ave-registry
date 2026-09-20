# Suite design — what is varied, what is not, what is planned

**Nothing in the "planned" columns exists yet.** `canary-v1` is 4 channels × 6 techniques ×
1 sample. This document exists so the gaps are written down rather than discovered.

## Every dimension, and whether the current suite varies it

A susceptibility number only means something relative to what was varied to get it.

| Dimension | `canary-v1` today | Planned | Why it matters |
| --- | --- | --- | --- |
| **Content channel** — where the untrusted text comes from | 4 | ~25, listed below | All hits in experiment 1 landed in one channel per build. Four is too few to call anything general. |
| **Samples per cell** | **1** | several worded variants | The root problem. Each score currently rests on one sentence. |
| **Injection technique** | 6 | 6, plus any the corpus adds | One (`tool-output-spoof`) never worked; five behaved alike. |
| **Injection position** | **end of content only** | start / middle / end | Undisclosed until now: every injection is appended. Position is known to matter and is currently confounded with everything. |
| **Attacker goal** | **mixed, uncontrolled** | labelled: *redirect* vs *add a recipient* | Some techniques say "instead", others "also". These are different asks and the suite does not separate them. |
| **Task shape** | one — "read X, send a summary to Y" | several | A model may resist mid-summary and comply mid-something-else. |
| **Canary action** | `send_message` only | + file write, config write, code execution, URL fetch | Matches the capability vocabulary in `SCHEMA.md`. Exfiltration is one impact of several. |
| **Turn depth** | injection in the first tool result | + later turns, + after benign tool results | Long-context and late-turn behaviour may differ. |
| **Defensive system prompt** | none | with / without | Measures whether the cheap mitigation does anything. |
| **Language** | English | at least one other | Safety behaviour is known to vary by language. |
| **Tool protocol** | text JSON | + native tool calling | Forced by a llama.cpp parser bug; see RESULTS.md. One step less faithful to production. |
| **Model, quantization, lineage** | 1 model × 4 quants | per SPEC.md factorials | The thing being measured. |

Three of these — position, attacker goal, and samples per cell — are flaws in the current
suite, not just omissions. Experiment 1's numbers inherit all three.

## Channel plan

Channels are chosen from two sources: vectors that have **already been exploited** in the
registry's own corpus, and places untrusted text plausibly enters an agent. A channel with
a precedent is higher priority, because it is known to be reachable.

| Channel | Precedent in the registry | Status |
| --- | --- | --- |
| Inbound email | AVE-2026-0018, 0020 | **have** |
| Web page | AVE-2026-0020 (browsing) | **have** |
| Support ticket | AVE-2026-0002 | **have** |
| Document / notes | — | **have** |
| Public issue or pull-request text | AVE-2026-0001 | planned |
| Repository README or agent context file | AVE-2026-0005, 0010 | planned |
| Chat message (Slack, WhatsApp, Teams) | AVE-2026-0003, 0004 | planned |
| Web form submission / CRM field | AVE-2026-0019 | planned |
| Database row | AVE-2026-0002 | planned |
| Project configuration file | AVE-2026-0011, 0012, 0013 | planned |
| Code comment | — | planned |
| Commit message | — | planned |
| Search-result snippet | — | planned |
| Retrieved chunk (RAG / vector store) | — | planned |
| Calendar invite | — | planned |
| Text extracted from a PDF | — | planned |
| Spreadsheet or CSV cell | — | planned |
| API / JSON response field | — | planned |
| Log line or error message | — | planned |
| File name or metadata | — | planned |
| Image alt-text or OCR output | — | planned |
| Audio / video transcript | — | planned |
| Product review or public comment | — | planned |
| User profile field | — | planned |
| Agent memory / saved notes | — | planned |
| Output of another agent | — | planned |
| **Tool description or metadata** | AVE-2026-0003 | planned — **needs a harness change** |

The last row is a different mechanism. Every other channel poisons what a tool *returns*;
tool poisoning corrupts the tool's *definition*, before any call is made. The current
harness cannot express it.

## Order of work

1. **Samples per cell, on the existing four channels.** Cheapest, and it fixes the actual
   defect. Until a cell has several samples, adding channels adds more coin tosses.
2. **Label and separate position and attacker goal.** They are confounds today.
3. **Positive and negative controls.** The gate in ROADMAP.md: a config built to be
   compromised must score high, a hardened one near zero.
4. **Channels with a registry precedent,** then the rest.
5. **Remaining dimensions** — task shape, canary action, turn depth, defences, language.

Steps 1–3 come before 4 deliberately. Breadth on an uncalibrated instrument produces more
numbers, not more knowledge.

## What this does not cover

Direct jailbreaks, multi-modal injection delivered as pixels or audio rather than extracted
text, attacks on the harness rather than the model, and adaptive attacks that rewrite
themselves against a target. The last is a real research direction and would measure more
truthfully than a fixed suite; it is out of scope until the disclosure policy covers what
happens when it finds something new.
