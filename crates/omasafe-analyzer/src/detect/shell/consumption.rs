//! Download/decode execution pairing for shell script text.
//!
//! Extracted from `detect.rs` (plan A4): the statement-scoped finding
//! families — fetch-to-interpreter and decoder-to-interpreter pipelines,
//! consumed substitution spans, reverse-shell spellings, and the shared
//! temporary-path rules — with per-line finding deduplication.
use super::budget::ShellBudget;
use super::command::{segment_commands, skip_command_prefixes, statement_outcomes};
use super::effects::{
    command_decodes, command_fetches, pipeline_has_live_producer, segment_has_live_producer,
    segment_stdin_reaches_interpreter, stdout_reaches, tokens_live_fetch_stdout,
};
use super::indicators::{
    chmod_relaxes_shared_temp, reverse_shell_spelling, segment_has_shared_temp_path,
};
use super::interpreter::{INTERPRETER_BASENAMES, static_command_body};
use super::lexer::{ShellToken, SubstKind, tokenize};
use super::syntax::{
    GroupKind, Outcomes, conditional_statements, grouped_token_ranges, pipeline_segments,
};
use crate::detect::{
    ResultParts, SCRIPT_DECODE_EXECUTE_RULE, SCRIPT_REVERSE_SHELL_RULE,
    SHARED_TEMP_CONTROLLED_RULE, SHARED_TEMP_INDICATOR_RULE, parts,
};
use crate::fingerprint::Confidence;

/// The shell consumption families over one token stream, collected without
/// duplicate (rule, semantic tag) pairs: a group's interior re-detects what
/// the outer segment already bound through its opening `(`, and repeated
/// statements on the line add no information.
pub(in crate::detect) fn shell_consumption_findings(
    tokens: &[ShellToken],
    number: u32,
    download_rule: &'static str,
    found: &mut Vec<ResultParts>,
    budget: &mut ShellBudget,
) {
    if !budget.spend(tokens.len()) {
        return;
    }
    let mut outcomes = Outcomes::ANY;
    for (statement, guard) in conditional_statements(tokens) {
        if statement.is_empty() {
            continue;
        }
        if !outcomes.executes(guard) {
            continue; // no path reaches it; the outcome set is unchanged
        }

        // Runtime text of every substitution this statement's live heads
        // execute — `eval`'s command substitutions and an interpreter's
        // process substitutions — re-parsed with the same command-position
        // rules.
        let consumed = consumed_substitutions(statement);

        // Download-execute: a fetch-tool command feeding an interpreter
        // through the pipeline, or heading a consumed span.
        if pipeline_fetches_to_interpreter(statement, budget)
            || consumed
                .iter()
                .any(|span| span_has_fetch_command(span, budget))
        {
            push_finding(
                found,
                parts(
                    download_rule,
                    number,
                    "download-execute",
                    Confidence::LexicalFallback,
                ),
            );
        }

        // Decode-execute: a decoder command feeding an interpreter through
        // the pipeline, or heading a consumed span.
        if pipeline_decodes_to_interpreter(statement, budget)
            || consumed
                .iter()
                .any(|span| span_executes_decoder(span, budget))
        {
            push_finding(
                found,
                parts(
                    SCRIPT_DECODE_EXECUTE_RULE,
                    number,
                    "decode-execute",
                    Confidence::LexicalFallback,
                ),
            );
        }

        for segment in pipeline_segments(statement) {
            if segment.is_empty() {
                continue;
            }
            if reverse_shell_spelling(segment) {
                push_finding(
                    found,
                    parts(
                        SCRIPT_REVERSE_SHELL_RULE,
                        number,
                        "reverse-shell",
                        Confidence::LexicalFallback,
                    ),
                );
            }
            // Shared temporary storage: the wrapper and the /tmp or
            // /dev/shm path share one command's segment (indicator),
            // or the chmod's own mode release targets one
            // (controlled). A pathname alone never proves attacker
            // control, and the indicator id is never repurposed. The
            // path is read from each command's real arguments, so a
            // quoted operand (`chmod 777 "/tmp/x"`) still binds while a
            // redirect target (`sudo true > /tmp/sudo.log`) never does.
            let shared_temp_path = segment_has_shared_temp_path(segment);
            if shared_temp_path
                && segment_commands(segment)
                    .iter()
                    .any(|command| matches!(command.head, "sudo" | "pkexec" | "doas"))
            {
                push_finding(
                    found,
                    parts(
                        SHARED_TEMP_INDICATOR_RULE,
                        number,
                        "privileged-shared-temp",
                        Confidence::LexicalFallback,
                    ),
                );
            }
            if shared_temp_path && chmod_relaxes_shared_temp(segment) {
                push_finding(
                    found,
                    parts(
                        SHARED_TEMP_CONTROLLED_RULE,
                        number,
                        "shared-temp-mode-release",
                        Confidence::LexicalFallback,
                    ),
                );
            }
        }

        // Static bodies execute with the statement: an interpreter's `-c`
        // body or an `eval` argument is real shell text, so every family
        // applies inside it too (`eval 'curl URL | sh'` and
        // `sh -c 'curl URL | sh'` run the pipeline now). Runtime-derived
        // bodies are outside the static slice.
        for segment in pipeline_segments(statement) {
            for command in segment_commands(segment) {
                let Some(body) = static_command_body(&command) else {
                    continue;
                };
                if !budget.enter() {
                    return;
                }
                shell_consumption_findings(&tokenize(&body), number, download_rule, found, budget);
                budget.leave();
            }
        }

        // A subshell or brace group executes its interior as its own
        // statement list, so the same families apply inside it instead of
        // the group's separators merely being hidden from this pass. An
        // arithmetic command evaluates its interior as an expression whose
        // words are never commands — but genuine command substitutions
        // nested in it DO execute (`(( $(curl URL | sh) + 1 ))`).
        for (kind, group) in grouped_token_ranges(statement) {
            match kind {
                GroupKind::List => {
                    if budget.enter() {
                        shell_consumption_findings(group, number, download_rule, found, budget);
                        budget.leave();
                    }
                }
                GroupKind::Arithmetic => {
                    if budget.enter() {
                        tokens_arithmetic_consumption(group, number, download_rule, found, budget);
                        budget.leave();
                    }
                }
            }
        }

        // A command or process substitution ALWAYS executes its interior —
        // only whether its resulting OUTPUT is further consumed depends on
        // the outer head (consumed_substitutions). The families therefore
        // also apply inside it directly: `payload=$(curl URL | sh)` runs
        // the pipeline now. Words inside groups are reached by the group
        // recursion above; only the statement's own depth is walked here.
        let mut depth = 0i32;
        for token in statement {
            match token {
                ShellToken::Operator(op) => match op.as_str() {
                    "(" | "{" | "((" => depth += 1,
                    ")" | "}" | "))" => depth = (depth - 1).max(0),
                    _ => {}
                },
                ShellToken::Word { substitutions, .. } if depth == 0 => {
                    for substitution in substitutions {
                        match substitution.kind {
                            SubstKind::Command | SubstKind::Process => {
                                if !budget.enter() {
                                    break;
                                }
                                shell_consumption_findings(
                                    &tokenize(&substitution.inner),
                                    number,
                                    download_rule,
                                    found,
                                    budget,
                                );
                                budget.leave();
                            }
                            SubstKind::Arithmetic => arithmetic_consumption_findings(
                                &substitution.inner,
                                number,
                                download_rule,
                                found,
                                budget,
                            ),
                        }
                    }
                }
                _ => {}
            }
        }

        outcomes = outcomes.advance(guard, statement_outcomes(statement));
    }
}

/// Consumption families inside an arithmetic expansion: the expression's
/// own words (and grouping parens) are never commands, but a genuine
/// command substitution nested in it executes during evaluation
/// (`x=$(( 1 + $(curl URL | sh | wc -c) ))`).
fn arithmetic_consumption_findings(
    expression: &str,
    number: u32,
    download_rule: &'static str,
    found: &mut Vec<ResultParts>,
    budget: &mut ShellBudget,
) {
    if !budget.spend(expression.len()) || !budget.enter() {
        return;
    }
    tokens_arithmetic_consumption(&tokenize(expression), number, download_rule, found, budget);
    budget.leave();
}

/// Consumption families for the words of an arithmetic context — an
/// expansion's interior OR an arithmetic command group's interior: the
/// words are expression operands, but a genuine command or process
/// substitution nested in them executes during evaluation. Each recursive
/// helper owns its single depth charge: command/process substitution
/// interiors enter here, nested arithmetic enters in
/// `arithmetic_consumption_findings`.
fn tokens_arithmetic_consumption(
    tokens: &[ShellToken],
    number: u32,
    download_rule: &'static str,
    found: &mut Vec<ResultParts>,
    budget: &mut ShellBudget,
) {
    for token in tokens {
        if let ShellToken::Word { substitutions, .. } = token {
            for substitution in substitutions {
                match substitution.kind {
                    SubstKind::Command | SubstKind::Process => {
                        if budget.enter() {
                            shell_consumption_findings(
                                &tokenize(&substitution.inner),
                                number,
                                download_rule,
                                found,
                                budget,
                            );
                            budget.leave();
                        }
                    }
                    SubstKind::Arithmetic => arithmetic_consumption_findings(
                        &substitution.inner,
                        number,
                        download_rule,
                        found,
                        budget,
                    ),
                }
            }
        }
    }
}

/// Push one finding unless the same rule already fired with the same
/// semantic tag on this line.
fn push_finding(found: &mut Vec<ResultParts>, finding: ResultParts) {
    if !found.iter().any(|existing| {
        existing.rule_id == finding.rule_id && existing.semantic_value == finding.semantic_value
    }) {
        found.push(finding);
    }
}

/// A fetch-tool command whose output reaches an interpreter down the same
/// pipeline: `curl … | sh`, `curl x | gzip -d | sh`, including from inside a
/// producing compound group (`(echo x; curl URL) | sh`). The fetch site's
/// own stdout must land on the pipe and the body must survive every
/// intermediate segment.
fn pipeline_fetches_to_interpreter(statement: &[ShellToken], budget: &mut ShellBudget) -> bool {
    let segments = pipeline_segments(statement);
    for consumer in 1..segments.len() {
        if !segment_stdin_reaches_interpreter(segments[consumer], budget) {
            continue;
        }
        for producer in 0..consumer {
            if segment_has_live_producer(segments[producer], budget, &command_fetches)
                && stdout_reaches(&segments, producer, consumer, budget)
            {
                return true;
            }
        }
    }
    false
}

/// A decoder command feeding an interpreter through the pipe: `… | base64 -d
/// | sh`, `curl x | xxd -r | zsh`, including across intermediate segments,
/// with the decoder's own stdout tracked per command site.
fn pipeline_decodes_to_interpreter(statement: &[ShellToken], budget: &mut ShellBudget) -> bool {
    let segments = pipeline_segments(statement);
    for consumer in 1..segments.len() {
        if !segment_stdin_reaches_interpreter(segments[consumer], budget) {
            continue;
        }
        for producer in 0..consumer {
            if segment_has_live_producer(segments[producer], budget, &command_decodes)
                && stdout_reaches(&segments, producer, consumer, budget)
            {
                return true;
            }
        }
    }
    false
}

/// Runtime interiors of the substitutions this statement's live heads
/// execute: an `eval` in command position runs its command substitutions'
/// text, and an interpreter/`source`/`.` head runs its process substitutions
/// as script input. `diff <(curl a)` compares and `echo eval "$(curl …)"`
/// never executes, so neither yields a consumed span.
fn consumed_substitutions(statement: &[ShellToken]) -> Vec<String> {
    let mut spans = Vec::new();
    for segment in pipeline_segments(statement) {
        let commands = segment_commands(segment);
        let head_eval = commands.iter().any(|command| command.head == "eval");
        let head_consumes = commands.iter().any(|command| {
            INTERPRETER_BASENAMES.contains(&command.head) || command.head == "source"
        }) || segment_head_word(segment) == Some(".");
        for token in segment {
            if let ShellToken::Word { substitutions, .. } = token {
                for substitution in substitutions {
                    let executed = match substitution.kind {
                        SubstKind::Command => head_eval,
                        SubstKind::Process => head_consumes,
                        // Arithmetic evaluates to a number; `eval 0` runs no
                        // fetched text.
                        SubstKind::Arithmetic => false,
                    };
                    if executed {
                        spans.push(substitution.inner.clone());
                    }
                }
            }
        }
    }
    spans
}

/// The head word value of a segment before basename reduction, so a bare `.`
/// source is recognisable (`command_basename(".")` is empty).
fn segment_head_word(segment: &[ShellToken]) -> Option<&str> {
    let mut index = 0usize;
    skip_command_prefixes(segment, &mut index);
    segment.get(index).and_then(ShellToken::word)
}

/// A fetch-tool command inside an executed substitution span: a LIVE
/// producer site in command position whose output survives the rest of its
/// own pipeline to become the span's collected output (including compound
/// groups), its own stdout tracked per command. `eval "$(curl x > f)"`
/// writes the response to a file and executes nothing, and
/// `eval "$(curl x | cat >/dev/null)"` collects only what `cat` leaves —
/// nothing; `eval "$(false && curl x)"` never runs the fetch.
fn span_has_fetch_command(span: &str, budget: &mut ShellBudget) -> bool {
    tokens_live_fetch_stdout(&tokenize(span), budget)
}

/// A decoder command inside an executed substitution span: feeding an
/// interpreter within the span, or a live decoder site heading it.
fn span_executes_decoder(span: &str, budget: &mut ShellBudget) -> bool {
    let tokens = tokenize(span);
    let mut outcomes = Outcomes::ANY;
    for (statement, guard) in conditional_statements(&tokens) {
        if statement.is_empty() {
            continue;
        }
        if !outcomes.executes(guard) {
            continue;
        }
        if pipeline_decodes_to_interpreter(statement, budget)
            || pipeline_has_live_producer(&pipeline_segments(statement), budget, &command_decodes)
        {
            return true;
        }
        outcomes = outcomes.advance(guard, statement_outcomes(statement));
    }
    false
}
