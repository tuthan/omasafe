# Corpus expectation ledger

Dispositions for pinned corpus results, keyed by
`{plugin_id, commit, rule_id}`. The ledger is both triage record and
regression fixture: a disposition attached to a pinned commit keeps that exact
finding classified across runs, and any detector change that alters a
disposition-covered result surfaces as an untriaged delta instead of silently
shifting counts.

## Format

One JSON object per line (`fixtures/corpus/expectations/dispositions.jsonl`):

```json
{"plugin_id":"…","commit":"40-or-64-hex","rule_id":"oma.qml.process-execution","disposition":"true-positive","note":"launcher pattern reviewed 2026-08-26"}
```

- `disposition` is `true-positive` or `false-positive`.
- `note` is required human context (who/why), never parsed by tooling.
- Records are append-only; superseding a disposition appends a new line with
  the same key — the last line for a key wins.

## Semantics in the runner

- A finding whose key has no record is **untriaged**.
- A repository that cannot be cloned at its pinned commit is **incomplete**
  for every rule; incomplete is never counted clean.
- Release gate (`run-corpus.py --gate-high`): fails on any known
  high-severity false positive or any untriaged high-severity finding.
  Genuine high findings are expected and fine.

The checked-in ledger contains only dispositions from the pinned sample that
were reviewed against the corresponding source commit. New records must still
come from real triage; do not pre-seed unknown findings or infer dispositions
from severity alone.

## H7 measurement outputs

`scripts/run-corpus.py` adds `triaged`, `precision`, and `blockingEligible`
fields to its report. Precision is `true_positive / (true_positive +
false_positive)` only when at least one emitted result has a disposition;
otherwise it is `null`. A family is eligible only when it has at least one
triaged result, zero false positives, and zero untriaged results. An empty
ledger therefore admits no blocking family.

The independent fixture suite is described by
`ground-truth.json` and measured with:

```text
python3 scripts/measure-ground-truth.py \
  --output docs/reports/h7-ground-truth.json
```

Its detection-rate report is separate from corpus precision: fixture labels
provide independently declared positives and negatives, but do not establish
ecosystem recall.
