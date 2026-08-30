# `detect.rs` maintenance and decomposition plan

Status: **proposal**

`crates/omasafe-analyzer/src/detect.rs` is currently approximately 10,586
lines and 400 KB. It contains the public analyzer entry points, inventory
orchestration, QML/JavaScript lexical and AST detection, shell source
assembly and tokenization, command/redirect/control-flow models, Python
heuristics, result normalization helpers, and more than 4,000 lines of tests.

The immediate problem is not merely file length. Shell behavior is represented
across many independent helpers that repeatedly tokenize and summarize the
same text. Adding one grammar feature now requires reviewers to verify egress,
producer provenance, stdin flow, consumed substitutions, nested bodies,
budgets, and conditional execution in several places.

## Goals

- Keep `detect`'s public API unchanged:
  `analyze_inventory`, `parser_metadata`, and `AnalysisArtifacts`.
- Separate language frontends and shell-analysis layers behind private module
  boundaries.
- Make each shell construct parse once and carry typed semantics through all
  detectors.
- Preserve deterministic ordering, fingerprints, coverage limitations, and
  both QML feature configurations.
- Make behavioral changes independently reviewable from file movement.

## Non-goals

- Do not change rule ids, severities, capability contracts, or policy
  fingerprints merely to reorganize code.
- Do not introduce a general-purpose POSIX/Bash parser in the extraction
  phase.
- Do not move tests and production logic simultaneously in one large commit.
- Do not make private modules public API without a concrete external consumer.

## Recommended target layout

Keep `detect.rs` as a small facade initially; Rust permits it to own private
modules under `src/detect/`.

```text
src/
  detect.rs                       # public facade and inventory orchestration
  detect/
    model.rs                      # FileOutcome, ResultParts, shared helpers
    references.rs                 # literal references and invocation edges
    qml/
      mod.rs                      # QML entry point and shared contracts
      lexical.rs                  # fallback QML/JS scanner
      ast.rs                      # qml-parser feature implementation
      strings.rs                  # JS/QML string and escape handling
    script/
      mod.rs                      # shell/Python dispatch and result anchoring
      python.rs                   # Python-only H3 lexical detectors
      shell/
        mod.rs                    # shell analyzer facade
        source.rs                 # logical units, comments, heredocs
        lexer.rs                  # ShellToken and substitutions
        syntax.rs                 # statements, pipelines, groups, outcomes
        command.rs                # ScriptCommand, wrappers, argv/redirections
        interpreter.rs            # interpreter and eval invocation parsing
        effects.rs                # stdin/stdout/code-execution effects
        egress.rs                 # fetch attribution
        consumption.rs            # download/decode execution pairing
        indicators.rs             # reverse shell, chmod/temp families
        budget.rs                 # ShellBudget and limitation propagation
    tests/
      inventory.rs
      qml_lexical.rs
      qml_ast.rs
      shell_h3.rs
      shell_regressions.rs
```

Exact filenames matter less than dependency direction. `lexer` must not depend
on findings; `syntax` may depend on tokens; `command` may depend on syntax;
effects and detectors may depend on all three. The facade should be the only
layer that constructs final `AnalysisArtifacts`.

## Stage 0 — close the known-defect baseline

Resolve and pin the eight open P1 cases in
`docs/h3-review-round-12.md` before taking characterization snapshots or
starting mechanical extraction. Otherwise the golden tests in A1 would turn
known false positives and false negatives into the refactor's definition of
correct behavior, and those defects would remain open through the longest
part of the sequence.

Stage 0 may add temporary private helpers to `detect.rs`, but it should not
begin the module move or typed-IR work. Its completion gate is:

- every round-12 reproduction has a focused regression test;
- at least one false-positive and one false-negative case are pinned through
  the end-to-end artifact path;
- both feature configurations and the full verification gate pass; and
- `docs/h3-review-round-12.md` is marked complete.

## Stage A — behavior-preserving extraction

This stage should be mechanical. Do not fix H3 findings while moving code.

### A1. Establish characterization gates

Before extraction:

- Run and record both workspace feature configurations.
- Add a compact golden test that serializes normalized artifacts for the
  existing benign and malicious script fixtures.
- Confirm rule ordering, capability ordering, limitations, and analysis
  fingerprints are identical across repeated runs.

### A2. Extract leaf helpers first

Start with modules having few dependencies:

1. `shell/budget.rs`
2. `shell/lexer.rs`
3. `shell/source.rs`
4. QML/JS string decoding helpers
5. Python-only lexical helpers

Use `pub(super)` or `pub(in crate::detect)` rather than broad `pub` exports.
Avoid renaming functions during extraction so diffs remain reviewable.

### A3. Extract shell syntax and command modeling

Move statement/pipeline/group splitting, `Outcomes`, command-position parsing,
wrapper unwrapping, interpreter parsing, and redirect semantics. Keep existing
tests running after each module move.

### A4. Extract detector families

Move egress, download/decode consumption, reverse-shell indicators, and shared
temporary-path rules only after their dependencies have stable homes.

### A5. Move tests last

Keep the current unit tests in `detect.rs` until production extraction is
complete. Then split them by behavior. Child test modules can still access
private parent items, so production visibility need not be widened solely for
tests.

### Stage A acceptance criteria

- `detect.rs` is primarily a facade and orchestration file, preferably below
  1,500 lines.
- No extracted production module exceeds roughly 1,500 lines without an
  explicit reason.
- Normalized fixture output and determinism fingerprints are byte-identical.
- No new `allow(dead_code)` or lint suppression is introduced to facilitate
  the move.

## Stage B — replace repeated shell walks with a typed IR

File splitting alone will not remove the semantic duplication responsible for
the recent regressions. After Stage A is stable, introduce one bounded shell
representation:

```rust
struct ShellProgram {
    units: Vec<LogicalUnit>,
}

struct LogicalUnit {
    start_line: u32,
    statements: Vec<Statement>,
    heredocs: Vec<Heredoc>,
}

struct Statement {
    guard: Guard,
    pipelines: Vec<Pipeline>,
}

struct Pipeline {
    negated: bool,
    commands: Vec<CommandNode>,
}

struct Command {
    head: CommandHead,
    args: Vec<Word>,
    redirects: Vec<Redirect>,
    body: Option<ExecutedBody>,
}

enum CommandNode {
    Simple(Command),
    Subshell(Vec<Statement>),
    BraceGroup(Vec<Statement>),
    If(IfCommand),
    While(LoopCommand),
    Until(LoopCommand),
    For(ForCommand),
    Case(CaseCommand),
}
```

`Guard` represents list operators such as unconditional sequencing, `&&`,
`||`, and backgrounding; it must not absorb reserved-word control structures.
`if`/`while`/`until`/`for`/`case` should be explicit compound command variants
so branch execution and skipped bodies remain representable. Stage B may
initially preserve today's limited detection scope for those variants, but the
IR must not flatten them into ordinary argv words.

Words should retain both their best-known runtime value and provenance:

```rust
enum WordProvenance {
    Static,
    ParameterExpansion,
    CommandSubstitution,
    ProcessSubstitution,
    ArithmeticExpansion,
    Mixed,
}
```

This is more maintainable than a single `dynamic: bool`: detectors can reject
unknown executable text while still descending into known command
substitutions and distinguishing literal positional-parameter references.
Initially, tilde expansion, brace expansion, globbing, and IFS-driven field
splitting belong to `Mixed`; give them dedicated variants only when a detector
models their semantics. If words can carry several causes simultaneously,
implement provenance as flags/a small set rather than forcing a lossy single
enum value.

## Centralize command effects

Every detector currently asks a slightly different version of whether a
command reads stdin, forwards stdout, executes input, or fetches data. Replace
those parallel predicates with one typed effect summary:

```rust
struct CommandEffects {
    stdin: StdinEffect,
    stdout: StdoutEffect,
    execution: ExecutionEffect,
    egress: EgressEffect,
}

enum StdinEffect {
    Unread,
    Consumed,
    ForwardedExecutableText,
    ForwardedDerivedData,
}

enum ExecutionEffect {
    None,
    ExecutesStdin,
    ExecutesStaticBody,
    ExecutesTaintedArgument,
}
```

Interpreter modes, transformers, `eval`, `source`, and `xargs` should each
produce `CommandEffects`. Pipeline reachability and compound sequencing then
consume those effects rather than reclassifying command heads independently.
This directly prevents cases where `ParseOnly` is safe in one predicate but
incorrectly `Untouched` in another.

## Parse once, summarize once

Static `-c` and eval bodies currently re-enter several independent walks.
Cache a bounded `ShellSummary` for each parsed `ExecutedBody` during one
analysis traversal:

```rust
struct ShellSummary {
    fetch_egress: bool,
    live_fetch_stdout: bool,
    stdin_effect: StdinEffect,
    executes_stdin: bool,
    findings: SmallVec<[FindingTag; 4]>,
    exhausted: bool,
}
```

The cache key should be local to one file analysis and bounded by the existing
node budget; it must not become an unbounded global cache. A summary should be
computed with the correct language frontend—never send Python `-c` text to the
shell frontend.

## Testing strategy after decomposition

### Layer tests

- `source`: logical newlines, comments, heredocs, escaped operators.
- `lexer`: quoting, concatenation, substitutions, redirects, malformed input.
- `syntax`: statement guards, pipeline groups, arithmetic/non-arithmetic
  hierarchy.
- `command`: wrappers, argv boundaries, option arity, redirects.
- `effects`: table-driven command modes and stdin/stdout behavior.
- `consumption`: producer-to-consumer reachability over typed effects.

### Property and differential tests

Add bounded property tests for invariants that have repeatedly regressed:

- Quoting or escaping a control operator cannot create a new statement or
  pipeline edge.
- Adding a stdout-away redirect cannot make a producer more reachable.
- Adding a stdin-away redirect cannot make a consumer more reachable.
- A skipped conditional branch cannot add egress or findings.
- Encoding mode cannot be equivalent to decoding mode.
- Parse-only execution cannot become code execution.
- Tokenization and logical-unit assembly never panic on arbitrary UTF-8.

For the supported Bash subset, use small differential fixtures executed in an
isolated process to verify exit/flow semantics (`-c`, `-s`, `-n`, `+n`, option
clusters, compounds). Do not execute untrusted plugin input in analyzer tests;
only execute fixed repository-owned test strings.

### Fixture ownership

Keep end-to-end fixtures for public behavior and small unit tables for grammar
details. Each H3 review finding should normally add:

- one exact positive or negative at the lowest responsible layer;
- one companion case at the end-to-end artifact layer;
- both feature configurations when QML argv paths are involved.

## Review and merge sequence

Recommended pull-request sequence:

1. Fix and pin the round-12 P1 findings on the current structure (Stage 0).
2. Add characterization/golden tests over the corrected baseline.
3. Extract shell budget, tokens, and logical source.
4. Extract syntax and command modeling.
5. Extract shell detector families.
6. Extract QML/JS and Python frontends.
7. Move and group tests.
8. Introduce the typed shell IR without changing findings.
9. Introduce centralized command effects.
10. Expand supported shell semantics only through separately reviewed,
    regression-pinned changes.

Each step should pass:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace
cargo test --workspace --no-default-features
./scripts/generate-cli-assets.sh --check
scripts/determinism-canary.sh
git diff --check
```

## Maintenance rules going forward

- New shell syntax belongs in the source/lexer/syntax layers, not directly in
  a finding predicate.
- A new command mode must define stdin, stdout, execution, and egress effects
  together.
- A detector must consume the typed representation; it should not scan raw
  token arrays for its own approximation of argv or redirects.
- Every recursion entry must charge exactly one shared budget owner and expose
  exhaustion to the facade.
- Cross-language executed bodies must dispatch by language family.
- Comments should document semantic invariants and supported scope, not the
  history of individual review rounds; review history belongs in `docs/`.

Following this sequence turns `detect.rs` into a stable API facade while also
addressing the deeper cause of its growth: duplicated parsing and flow logic,
not merely the number of lines in one file.
