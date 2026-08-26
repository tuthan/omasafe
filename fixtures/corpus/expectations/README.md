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

The ledger intentionally starts empty: dispositions accrue from real triage,
never pre-seeded.
