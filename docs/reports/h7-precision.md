# H7 precision and ground-truth report

Status: **measurement tooling complete; pinned-sample triage recorded**

H7 keeps two measurements separate:

- `scripts/run-corpus.py` reports precision only for emitted findings with a
  human disposition in `fixtures/corpus/expectations/dispositions.jsonl`.
  The checked-in ledger contains 8 reviewed observations from the pinned
  sample. None is a High-severity finding, so every High family still has
  `N/A` precision and no family is eligible for hardened blocking. This is an
  absence of High-family evidence, not a zero-precision result.
- `scripts/measure-ground-truth.py` runs the independently labelled local
  adversarial and negative fixture suite. Its machine-readable output is
  [h7-ground-truth.json](h7-ground-truth.json).

## Corpus precision

The table covers every High-severity catalog family. Counts are populated by
the corpus runner when pinned community findings receive append-only reviewed
dispositions; the current sample contains no emitted High family.

| Rule family | True positive | False positive | Untriaged | Precision | Blocking eligible |
| --- | ---: | ---: | ---: | ---: | --- |
| `oma.qml.remote-component-load` | 0 | 0 | 0 | N/A | no evidence |
| `oma.qml.polkit-agent-ui` | 0 | 0 | 0 | N/A | no evidence |
| `oma.qml.session-lock` | 0 | 0 | 0 | N/A | no evidence |
| `oma.qml.pam-authentication` | 0 | 0 | 0 | N/A | no evidence |
| `oma.qml.sensitive-data-egress` | 0 | 0 | 0 | N/A | no evidence |
| `oma.script.sensitive-data-egress` | 0 | 0 | 0 | N/A | no evidence |
| `oma.script.download-execute` | 0 | 0 | 0 | N/A | no evidence |
| `oma.script.privilege-escalation` | 0 | 0 | 0 | N/A | no evidence |
| `oma.python.download-execute` | 0 | 0 | 0 | N/A | no evidence |
| `oma.python.privilege-escalation` | 0 | 0 | 0 | N/A | no evidence |
| `oma.script.reverse-shell` | 0 | 0 | 0 | N/A | no evidence |
| `oma.python.reverse-shell` | 0 | 0 | 0 | N/A | no evidence |
| `oma.script.decode-execute` | 0 | 0 | 0 | N/A | no evidence |
| `oma.script.privileged-shared-temp-controlled` | 0 | 0 | 0 | N/A | no evidence |

## Ground-truth fixture detection

The checked-in suite currently contains 11 labelled cases covering the H2–H6
reference, execution, dataflow, and user-data families. The generated report
records per-case missing/forbidden rules and per-family detection rates. The
current run passes all cases: 11/11 fixtures pass and every declared positive
rule is detected (100% for each covered family); this is fixture detection
rate, not ecosystem recall.

Run locally:

```text
python3 scripts/measure-ground-truth.py \
  --output docs/reports/h7-ground-truth.json
```

The release gate runs this suite without network access. Complete reviewed
dispositions for a High family remain required before that family can enter the
H8b blocking set.
