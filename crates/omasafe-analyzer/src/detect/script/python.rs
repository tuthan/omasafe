//! Python-only lexical detectors (H3 slice): socket-to-process wiring
//! that only means something in Python syntax, kept apart from the
//! shell engine.

use crate::detect::model::balanced_bracket_span;

/// Python reverse shell (H3 review): a connected socket whose descriptor
/// reaches a process — a `dup2(` or `Popen(` call whose own argument span
/// passes that socket's `fileno()` (or chains
/// `create_connection( … ).fileno()` inline). Independent socket and
/// dup2 words never fire: `s = socket.create_connection((host, 443));
/// os.dup2(1, 2)` and `s.connect(…); os.dup2(log.fileno(), 1)` stay
/// silent.
pub(in crate::detect) fn python_reverse_shell(code: &str) -> bool {
    let mut sockets = Vec::new();
    for (index, _) in code.match_indices(".connect(") {
        if let Some(receiver) = dotted_identifier_before(code, index) {
            sockets.push(receiver);
        }
    }
    for (index, _) in code.match_indices("create_connection(") {
        if let Some(target) = assigned_name_before(code, index) {
            sockets.push(target);
        }
    }
    for call in ["dup2(", "Popen("] {
        for (index, _) in code.match_indices(call) {
            let Some((open, close)) = balanced_bracket_span(code, index + call.len() - 1) else {
                continue;
            };
            let args = &code[open..close];
            let wired = sockets
                .iter()
                .any(|socket| args.contains(&format!("{socket}.fileno()")))
                || (args.contains("fileno()") && args.contains("create_connection("));
            if wired {
                return true;
            }
        }
    }
    false
}

/// Receiver chain of a `.connect(` call: the dotted identifier before the
/// dot (`s`, `self.sock`).
pub(in crate::detect) fn dotted_identifier_before(code: &str, dot_index: usize) -> Option<&str> {
    let bytes = code.as_bytes();
    let mut start = dot_index;
    while start > 0
        && (bytes[start - 1].is_ascii_alphanumeric()
            || bytes[start - 1] == b'_'
            || bytes[start - 1] == b'.')
    {
        start -= 1;
    }
    let name = &code[start..dot_index];
    (!name.is_empty()).then_some(name)
}

/// Assignment target feeding a `create_connection(` call: the assignment
/// operator must live in the SAME statement as the call —
/// `s = socket.create_connection(…)` (or `s = wrapper(…)` wrapping it).
/// A `=` left over from an earlier statement (`log = open(…);
/// socket.create_connection(…); os.dup2(log.fileno(), 1)`) binds nothing,
/// and comparison operators (`==`, `<=`, `>=`, `!=`) are never
/// assignments.
pub(in crate::detect) fn assigned_name_before(code: &str, call_index: usize) -> Option<&str> {
    let before = &code[..call_index];
    let statement_start = before.rfind([';', '\n']).map_or(0, |index| index + 1);
    let statement = &before[statement_start..];
    let equals = statement.rfind('=')?;
    if statement[..equals].ends_with(['!', '<', '>', '=']) {
        return None; // ==, !=, <=, >= comparisons
    }
    let target = statement[..equals].trim_end();
    let start = target
        .char_indices()
        .rev()
        .take_while(|(_, character)| character.is_alphanumeric() || *character == '_')
        .last()
        .map(|(byte, _)| byte)?;
    let name = &target[start..];
    (!name.is_empty()).then_some(name)
}
