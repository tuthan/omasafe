//! Shell lexer: words, operators, and substitutions over one shell text.
//!
//! The lexer never depends on findings or `FileOutcome`: it resolves
//! quoting, escapes, and substitution syntax into tokens carrying runtime
//! values plus provenance, so every later layer reads the same token
//! stream instead of re-scanning raw text.

use crate::detect::model::balanced_bracket_span;

const PARAMETER_BIT: u16 = 1 << 0;
const COMMAND_SUBST_BIT: u16 = 1 << 1;
const PROCESS_SUBST_BIT: u16 = 1 << 2;
const ARITHMETIC_BIT: u16 = 1 << 3;
const GLOB_BIT: u16 = 1 << 4;
const TILDE_BIT: u16 = 1 << 5;
const BRACE_BIT: u16 = 1 << 6;
const FIELD_SPLIT_BIT: u16 = 1 << 7;

/// Additive causes that make a shell word runtime-dependent. The lexer owns
/// this set because only it still knows whether an expansion or pattern was
/// quoted when it was encountered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::detect) struct WordProvenance(u16);

impl WordProvenance {
    pub(in crate::detect) const EMPTY: Self = Self(0);
    pub(in crate::detect) const PARAMETER: Self = Self(PARAMETER_BIT);
    pub(in crate::detect) const COMMAND_SUBST: Self = Self(COMMAND_SUBST_BIT);
    pub(in crate::detect) const PROCESS_SUBST: Self = Self(PROCESS_SUBST_BIT);
    pub(in crate::detect) const ARITHMETIC: Self = Self(ARITHMETIC_BIT);
    pub(in crate::detect) const GLOB: Self = Self(GLOB_BIT);
    pub(in crate::detect) const TILDE: Self = Self(TILDE_BIT);
    pub(in crate::detect) const BRACE: Self = Self(BRACE_BIT);
    pub(in crate::detect) const FIELD_SPLIT: Self = Self(FIELD_SPLIT_BIT);

    pub(in crate::detect) const fn is_static(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for WordProvenance {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for WordProvenance {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// A substitution's kind: command substitution (`$( … )`, backticks) expands
/// to text a command consumes, process substitution (`<( … )`, `>( … )`)
/// presents its output as a filename operand, and arithmetic expansion
/// (`$(( … ))`) evaluates variables into a number — only genuine command
/// substitutions nested inside it run anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::detect) enum SubstKind {
    Command,
    Process,
    Arithmetic,
}

/// One active (non-single-quoted) substitution embedded in a word, keeping
/// the raw interior text so its command can be re-tokenised for egress and
/// consumption attribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) struct Substitution {
    pub(in crate::detect) kind: SubstKind,
    pub(in crate::detect) inner: String,
}

/// A shell token: a WORD carries its expanded runtime value (quotes removed,
/// adjacent fragments concatenated, escapes applied — so `c"ur"l` is `curl`)
/// plus any active substitutions it contains; an OPERATOR carries its literal
/// unquoted control/redirection text. Operators are recognised only when
/// unquoted, so a quoted or escaped `;`/`|`/`>` is part of a word and never
/// splits a statement or reads as a redirect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) enum ShellToken {
    Word {
        value: String,
        substitutions: Vec<Substitution>,
        provenance: WordProvenance,
        /// Some fragment of the word resolves only at runtime — an unquoted
        /// or double-quoted `$`/backtick expansion, or a captured
        /// substitution — so the value is not statically known text.
        dynamic: bool,
        /// Byte span of the word's raw spelling in the tokenized text
        /// (quotes and escapes included), so a rewrite can anchor at the
        /// exact source position the word occupies.
        span: (usize, usize),
    },
    Operator(String),
}

impl ShellToken {
    pub(in crate::detect) fn word(&self) -> Option<&str> {
        match self {
            ShellToken::Word { value, .. } => Some(value),
            ShellToken::Operator(_) => None,
        }
    }

    pub(in crate::detect) fn operator(&self) -> Option<&str> {
        match self {
            ShellToken::Operator(op) => Some(op),
            ShellToken::Word { .. } => None,
        }
    }

    /// The word's raw byte span in the tokenized text; `None` for operators.
    pub(in crate::detect) fn span(&self) -> Option<(usize, usize)> {
        match self {
            ShellToken::Word { span, .. } => Some(*span),
            ShellToken::Operator(_) => None,
        }
    }
}

/// Tokenise one line (or substitution interior) into words and unquoted
/// operators. Quotes, backslash escapes, and `$(`/`$((`/backtick/`<(`
/// substitutions are resolved here, keeping each token's runtime value
/// separate from its source syntax. `|&` is one pipeline operator, adjacent
/// `((`/`))` delimit an arithmetic command, and a lone `{`/`}` word is the
/// brace-group reserved word.
pub(in crate::detect) fn tokenize(input: &str) -> Vec<ShellToken> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    // Close positions of arithmetic commands opened so far, innermost last:
    // `))` is only a closer while a `((` group is open.
    let mut arithmetic_closes: Vec<usize> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b'\r' => i += 1,
            // A raw newline separates statements exactly like `;`. It reaches
            // the lexer unquoted inside reparsed bodies (eval/`-c` text,
            // substitution interiors), where the physical line structure is
            // gone but the newline's meaning survives.
            b'\n' => {
                tokens.push(ShellToken::Operator(";".to_owned()));
                i += 1;
            }
            b';' => {
                tokens.push(ShellToken::Operator(";".to_owned()));
                i += 1;
            }
            b'(' => {
                // Adjacent `((` with a matching `))` is an arithmetic
                // command: bash evaluates the contents as an expression and
                // an invalid expression is an error that runs nothing,
                // while a group with no `))` closes as two subshell parens
                // (`((a) && echo b)` runs `a && echo b`).
                if bytes.get(i + 1) == Some(&b'(')
                    && let Some(close) = arithmetic_command_close(bytes, i)
                {
                    arithmetic_closes.push(close);
                    tokens.push(ShellToken::Operator("((".to_owned()));
                    i += 2;
                } else {
                    tokens.push(ShellToken::Operator("(".to_owned()));
                    i += 1;
                }
            }
            b')' => {
                if arithmetic_closes.last() == Some(&i) {
                    arithmetic_closes.pop();
                    tokens.push(ShellToken::Operator("))".to_owned()));
                    i += 2;
                } else {
                    tokens.push(ShellToken::Operator(")".to_owned()));
                    i += 1;
                }
            }
            b'|' => {
                if bytes.get(i + 1) == Some(&b'|') {
                    tokens.push(ShellToken::Operator("||".to_owned()));
                    i += 2;
                } else if bytes.get(i + 1) == Some(&b'&') {
                    // Bash pipes stdout AND stderr to the next segment.
                    tokens.push(ShellToken::Operator("|&".to_owned()));
                    i += 2;
                } else {
                    tokens.push(ShellToken::Operator("|".to_owned()));
                    i += 1;
                }
            }
            b'&' => {
                if bytes.get(i + 1) == Some(&b'&') {
                    tokens.push(ShellToken::Operator("&&".to_owned()));
                    i += 2;
                } else if bytes.get(i + 1) == Some(&b'>') {
                    if bytes.get(i + 2) == Some(&b'>') {
                        tokens.push(ShellToken::Operator("&>>".to_owned()));
                        i += 3;
                    } else {
                        tokens.push(ShellToken::Operator("&>".to_owned()));
                        i += 2;
                    }
                } else {
                    tokens.push(ShellToken::Operator("&".to_owned()));
                    i += 1;
                }
            }
            _ => {
                if let Some((op, next)) = redirect_operator_at(bytes, i) {
                    tokens.push(ShellToken::Operator(op));
                    i = next;
                } else {
                    let (word, next) = read_word(input, i);
                    // A lone brace word is Bash's compound-group reserved
                    // word (`{ … ; }`); glued braces stay ordinary words
                    // (`{curl`, `${x}`, `-exec {} \;`).
                    match word {
                        ShellToken::Word { value, .. } if value == "{" || value == "}" => {
                            tokens.push(ShellToken::Operator(value));
                        }
                        other => tokens.push(other),
                    }
                    i = next;
                }
            }
        }
    }
    tokens
}

/// Close of an arithmetic command opened by the `((` at `start`: the `))`
/// pair that returns paren depth to the opening pair, honouring nesting and
/// quotes (`(( (1+2)*3 ))` closes at the end, while `((a) && echo b)` never
/// finds one and reads as two subshell parens). Returns the index of the
/// first `)` of the closing pair.
fn arithmetic_command_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 2u32;
    let mut index = start + 2;
    let mut in_string: Option<u8> = None;
    while index < bytes.len() {
        let byte = bytes[index];
        match in_string {
            Some(quote) => {
                if byte == b'\\' {
                    index += 2;
                    continue;
                }
                if byte == quote {
                    in_string = None;
                }
            }
            None => {
                if byte == b'"' || byte == b'\'' {
                    in_string = Some(byte);
                } else if byte == b'(' {
                    depth += 1;
                } else if byte == b')' {
                    if depth == 2 && bytes.get(index + 1) == Some(&b')') {
                        return Some(index);
                    }
                    if depth == 2 {
                        // A close at the opening pair's own depth unbalances
                        // the `((` — no `))` can follow (`(( 1 ) ) )`). Bash
                        // rejects the input; read it back as plain parens.
                        return None;
                    }
                    depth -= 1;
                }
            }
        }
        index += 1;
    }
    None
}

/// A redirection operator starting at `start`: optional leading fd digits,
/// then `<`/`>` with the `>>`, `<>`, `<<`, and `&` (duplication) variants. A
/// bare `<(`/`>(` (no fd digits) is a process substitution, not a redirect,
/// and is left to `read_word`.
pub(in crate::detect) fn redirect_operator_at(
    bytes: &[u8],
    start: usize,
) -> Option<(String, usize)> {
    let mut i = start;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    let had_digits = i > start;
    let first = *bytes.get(i)?;
    if first != b'<' && first != b'>' {
        return None;
    }
    if !had_digits && bytes.get(i + 1) == Some(&b'(') {
        return None; // process substitution: part of a word
    }
    i += 1;
    if (first == b'>' && bytes.get(i) == Some(&b'>'))
        || (first == b'<' && matches!(bytes.get(i), Some(b'>' | b'<')))
    {
        i += 1; // `>>`, `<>`, `<<`
        if first == b'<' && bytes.get(i - 1) == Some(&b'<') && bytes.get(i) == Some(&b'-') {
            i += 1; // `<<-` strips leading tabs from heredoc body lines
        }
    }
    if bytes.get(i) == Some(&b'&') {
        i += 1; // `>&` / `<&` duplication
    }
    Some((String::from_utf8_lossy(&bytes[start..i]).into_owned(), i))
}

/// Open a `$` substitution whose `(` sits at `open`: adjacent `((` is an
/// arithmetic expansion, anything else a command substitution. Returns the
/// kind, the interior text, and the index just past the closing `)`.
/// `$(( … ))` is arithmetic because bash expands the interior as an
/// expression first — a spaced `$( (cmd) )` keeps its subshell reading as a
/// command substitution.
fn dollar_substitution(input: &str, open: usize) -> Option<(SubstKind, String, usize)> {
    let (start, close) = balanced_bracket_span(input, open)?;
    let kind = if input.as_bytes().get(open + 1) == Some(&b'(') {
        SubstKind::Arithmetic
    } else {
        SubstKind::Command
    };
    Some((kind, input[start..close].to_owned(), close + 1))
}

/// Read one WORD starting at `start`, resolving quotes, backslash escapes,
/// and substitutions into a runtime value; returns the byte index just past
/// the word. A word is marked dynamic when any fragment resolves only at
/// runtime — an unquoted or double-quoted `$`/backtick expansion, or a
/// captured substitution — while single-quoted text stays literal.
fn read_word(input: &str, start: usize) -> (ShellToken, usize) {
    let bytes = input.as_bytes();
    let mut i = start;
    let mut value: Vec<u8> = Vec::new();
    let mut substitutions: Vec<Substitution> = Vec::new();
    let mut provenance = WordProvenance::EMPTY;
    let mut parameter_brace_depth = 0u32;
    let mut brace_expansion_stack = Vec::new();
    let mut glob_bracket_open = false;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b'\n' | b'\r' | b';' | b'|' | b'&' | b'(' | b')' => break,
            b'<' | b'>' => {
                if bytes.get(i + 1) == Some(&b'(')
                    && let Some((open, close)) = balanced_bracket_span(input, i + 1)
                {
                    substitutions.push(Substitution {
                        kind: SubstKind::Process,
                        inner: input[open..close].to_owned(),
                    });
                    value.extend_from_slice(&bytes[i..=close]);
                    provenance |= WordProvenance::PROCESS_SUBST;
                    i = close + 1;
                    continue;
                }
                break; // a redirection operator terminates the word
            }
            b'\\' => {
                if let Some(&next) = bytes.get(i + 1) {
                    value.push(next);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b'\'' => {
                if let Some(rel) = input[i + 1..].find('\'') {
                    value.extend_from_slice(&bytes[i + 1..i + 1 + rel]);
                    i = i + 1 + rel + 1;
                } else {
                    value.extend_from_slice(&bytes[i + 1..]);
                    i = bytes.len();
                }
            }
            b'"' => {
                i = read_double_quoted(
                    input,
                    i + 1,
                    &mut value,
                    &mut substitutions,
                    &mut provenance,
                )
            }
            b'$' if bytes.get(i + 1) == Some(&b'(') => {
                match dollar_substitution(input, i + 1) {
                    Some((kind, inner, end)) => {
                        substitutions.push(Substitution { kind, inner });
                        add_substitution_provenance(&mut provenance, kind, false);
                        match kind {
                            // The expansion's runtime value is a number, so
                            // it never reads back as a command word.
                            SubstKind::Arithmetic => value.push(b'0'),
                            _ => value.extend_from_slice(&bytes[i..end]),
                        }
                        i = end;
                    }
                    None => {
                        value.push(bytes[i]);
                        provenance |= WordProvenance::COMMAND_SUBST | WordProvenance::FIELD_SPLIT;
                        i += 1;
                    }
                }
            }
            b'$' => {
                // A braced or bare parameter expansion resolves at runtime.
                provenance |= WordProvenance::PARAMETER | WordProvenance::FIELD_SPLIT;
                value.push(bytes[i]);
                if bytes.get(i + 1) == Some(&b'{') {
                    value.push(b'{');
                    parameter_brace_depth = parameter_brace_depth.saturating_add(1);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b'`' => {
                if let Some(rel) = input[i + 1..].find('`') {
                    let inner_start = i + 1;
                    let inner_end = i + 1 + rel;
                    substitutions.push(Substitution {
                        kind: SubstKind::Command,
                        inner: input[inner_start..inner_end].to_owned(),
                    });
                    value.extend_from_slice(&bytes[i..=inner_end]);
                    provenance |= WordProvenance::COMMAND_SUBST | WordProvenance::FIELD_SPLIT;
                    i = inner_end + 1;
                } else {
                    value.push(bytes[i]);
                    provenance |= WordProvenance::COMMAND_SUBST | WordProvenance::FIELD_SPLIT;
                    i += 1;
                }
            }
            b'~' if i == start || value.last() == Some(&b'=') => {
                provenance |= WordProvenance::TILDE;
                value.push(bytes[i]);
                i += 1;
            }
            b'*' | b'?' => {
                provenance |= WordProvenance::GLOB;
                value.push(bytes[i]);
                i += 1;
            }
            b'[' => {
                glob_bracket_open = true;
                value.push(bytes[i]);
                i += 1;
            }
            b']' if glob_bracket_open => {
                provenance |= WordProvenance::GLOB;
                glob_bracket_open = false;
                value.push(bytes[i]);
                i += 1;
            }
            b'{' if parameter_brace_depth == 0 => {
                brace_expansion_stack.push(false);
                value.push(bytes[i]);
                i += 1;
            }
            b',' if parameter_brace_depth == 0 => {
                if let Some(has_comma) = brace_expansion_stack.last_mut() {
                    *has_comma = true;
                }
                value.push(bytes[i]);
                i += 1;
            }
            b'}' if parameter_brace_depth > 0 => {
                parameter_brace_depth -= 1;
                value.push(bytes[i]);
                i += 1;
            }
            b'}' if parameter_brace_depth == 0 => {
                if brace_expansion_stack.pop().unwrap_or(false) {
                    provenance |= WordProvenance::BRACE;
                }
                value.push(bytes[i]);
                i += 1;
            }
            other => {
                value.push(other);
                i += 1;
            }
        }
    }
    (
        ShellToken::Word {
            value: String::from_utf8_lossy(&value).into_owned(),
            substitutions,
            dynamic: !provenance.is_static(),
            provenance,
            span: (start, i),
        },
        i,
    )
}

/// Continue reading inside a double-quoted region opened just before `start`:
/// backslash escapes only ``"$`\``, `$( … )`/`$(( … ))` and backticks stay
/// active substitutions, everything else is literal. Returns the index past
/// the closing quote (or end of input); any runtime-resolved fragment marks
/// the word dynamic.
fn read_double_quoted(
    input: &str,
    start: usize,
    value: &mut Vec<u8>,
    substitutions: &mut Vec<Substitution>,
    provenance: &mut WordProvenance,
) -> usize {
    let bytes = input.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return i + 1,
            b'\\' => {
                if let Some(&next) = bytes.get(i + 1) {
                    if matches!(next, b'"' | b'$' | b'`' | b'\\') {
                        value.push(next);
                    } else {
                        value.push(b'\\');
                        value.push(next);
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b'$' if bytes.get(i + 1) == Some(&b'(') => {
                match dollar_substitution(input, i + 1) {
                    Some((kind, inner, end)) => {
                        substitutions.push(Substitution { kind, inner });
                        add_substitution_provenance(provenance, kind, true);
                        match kind {
                            // The expansion's runtime value is a number, so
                            // it never reads back as a command word.
                            SubstKind::Arithmetic => value.push(b'0'),
                            _ => value.extend_from_slice(&bytes[i..end]),
                        }
                        i = end;
                    }
                    None => {
                        value.push(bytes[i]);
                        *provenance |= WordProvenance::COMMAND_SUBST;
                        i += 1;
                    }
                }
            }
            b'$' => {
                value.push(bytes[i]);
                *provenance |= WordProvenance::PARAMETER;
                i += 1;
            }
            b'`' => {
                if let Some(rel) = input[i + 1..].find('`') {
                    let inner_start = i + 1;
                    let inner_end = i + 1 + rel;
                    substitutions.push(Substitution {
                        kind: SubstKind::Command,
                        inner: input[inner_start..inner_end].to_owned(),
                    });
                    value.extend_from_slice(&bytes[i..=inner_end]);
                    *provenance |= WordProvenance::COMMAND_SUBST;
                    i = inner_end + 1;
                } else {
                    value.push(bytes[i]);
                    *provenance |= WordProvenance::COMMAND_SUBST;
                    i += 1;
                }
            }
            other => {
                value.push(other);
                i += 1;
            }
        }
    }
    i
}

fn add_substitution_provenance(provenance: &mut WordProvenance, kind: SubstKind, quoted: bool) {
    *provenance |= match kind {
        SubstKind::Command => WordProvenance::COMMAND_SUBST,
        SubstKind::Process => WordProvenance::PROCESS_SUBST,
        SubstKind::Arithmetic => WordProvenance::ARITHMETIC,
    };
    if !quoted && matches!(kind, SubstKind::Command) {
        *provenance |= WordProvenance::FIELD_SPLIT;
    }
}
