# H8b blocking-family admission report

Status: **complete — no family admitted; hardened blocking remains
precision-independent for this release**

H8b consumes the two H7 measurements without changing analyzer rules:

- corpus precision must be measured from at least one reviewed disposition, with
  no false-positive or untriaged results;
- independently labelled fixture detection must be measured at 100%.

The thresholds are fixed at `1.0`. The checked-in disposition ledger contains
8 reviewed records, but none is a High-severity finding, so every High-severity
family has `N/A` precision. The ground-truth suite passes 11/11 cases, with
100% detection for each covered family, but fixture detection cannot substitute
for High-family real-plugin precision.

| High-severity family | Corpus precision | Fixture detection rate | H8b admission |
| --- | ---: | ---: | --- |
| `oma.qml.remote-component-load` | N/A | 1.0 | no evidence |
| `oma.qml.polkit-agent-ui` | N/A | N/A | no evidence |
| `oma.qml.session-lock` | N/A | N/A | no evidence |
| `oma.qml.pam-authentication` | N/A | N/A | no evidence |
| `oma.qml.sensitive-data-egress` | N/A | 1.0 | no evidence |
| `oma.script.sensitive-data-egress` | N/A | N/A | no evidence |
| `oma.script.download-execute` | N/A | 1.0 | no evidence |
| `oma.script.privilege-escalation` | N/A | N/A | no evidence |
| `oma.python.download-execute` | N/A | N/A | no evidence |
| `oma.python.privilege-escalation` | N/A | N/A | no evidence |
| `oma.script.reverse-shell` | N/A | 1.0 | no evidence |
| `oma.python.reverse-shell` | N/A | N/A | no evidence |
| `oma.script.decode-execute` | N/A | 1.0 | no evidence |
| `oma.script.privileged-shared-temp-controlled` | N/A | 1.0 | no evidence |

The resulting enforcement-policy blocking set is `[]`. The policy still
blocks hardened operations on incomplete coverage, stale identities,
unapproved executable payloads, and failed installed-tree postconditions.
When maintainers append additional real-plugin dispositions and rerun H7, only families
with both complete measurements at the thresholds may be copied into the
typed H8b admission input; their precision and fixture rate stay alongside the
family and therefore change the enforcement-policy identity, not analyzer
identity.

Sources: [`h7-precision.md`](h7-precision.md),
[`h7-ground-truth.json`](h7-ground-truth.json), and
[`fixtures/corpus/expectations/dispositions.jsonl`](../../fixtures/corpus/expectations/dispositions.jsonl).
