//! JS/QML string and escape handling: decoding literals into the
//! runtime values classification sees.

/// Decode JS/QML string escape sequences so sink classification sees the
/// value the runtime evaluates: `"\x68ttps://…"` loads `https://…`, so
/// escaped literals must not slip past scheme detection (H2 review). Applies
/// exactly once, at string extraction; classification and evidence carry the
/// decoded runtime value. Unknown escapes decode to the escaped character
/// (JS semantics); a trailing backslash stays literal.
pub(in crate::detect) fn decode_js_escapes(content: &str) -> String {
    if !content.contains('\\') {
        return content.to_owned();
    }
    let mut decoded = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    while let Some(current) = chars.next() {
        if current != '\\' {
            decoded.push(current);
            continue;
        }
        let Some(&next) = chars.peek() else {
            decoded.push('\\');
            break;
        };
        match next {
            // Line-continuation: backslash + LineTerminatorSequence evaluates
            // to the empty string, so `"ht\<LF>tps://…"` is `https://…` at
            // runtime. A CR + LF pair is a single terminator sequence.
            '\n' | '\u{2028}' | '\u{2029}' => {
                chars.next();
            }
            '\r' => {
                chars.next();
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
            }
            // Legacy octal escape (Annex B): backslash + 1–3 octal digits.
            // The first digit bounds the length — 0–3 allow three digits,
            // 4–7 only two — so `\1` is U+0001 and `\101` is 'A'. `\0` not
            // followed by an octal digit is NUL. `\8`/`\9` are not octal and
            // fall through to the identity arm below.
            '0'..='7' => {
                chars.next();
                let mut octal = String::new();
                octal.push(next);
                let max = if next <= '3' { 3 } else { 2 };
                while octal.len() < max
                    && chars.peek().is_some_and(|char| ('0'..='7').contains(char))
                {
                    octal.push(chars.next().unwrap());
                }
                let value = u32::from_str_radix(&octal, 8).unwrap_or(0);
                decoded.push(char::from_u32(value).unwrap_or('\u{FFFD}'));
            }
            'n' | 'r' | 't' | 'b' | 'f' | 'v' => {
                decoded.push(match next {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'b' => '\u{0008}',
                    'f' => '\u{000C}',
                    _ => '\u{000B}',
                });
                chars.next();
            }
            'x' => {
                chars.next();
                let mut hex = String::new();
                while hex.len() < 2 && chars.peek().is_some_and(|char| char.is_ascii_hexdigit()) {
                    hex.push(chars.next().unwrap());
                }
                if hex.len() == 2 {
                    let value = u32::from_str_radix(&hex, 16).unwrap_or(0);
                    decoded.push(char::from_u32(value).unwrap_or('\u{FFFD}'));
                } else {
                    decoded.push_str("\\x");
                    decoded.push_str(&hex);
                }
            }
            'u' => {
                chars.next();
                if chars.peek() == Some(&'{') {
                    chars.next();
                    let mut hex = String::new();
                    while hex.len() < 6 && chars.peek().is_some_and(|char| char.is_ascii_hexdigit())
                    {
                        hex.push(chars.next().unwrap());
                    }
                    if chars.peek() == Some(&'}')
                        && let Some(value) =
                            u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                    {
                        chars.next();
                        decoded.push(value);
                    } else {
                        decoded.push_str("\\u{");
                        decoded.push_str(&hex);
                    }
                } else {
                    let mut hex = String::new();
                    while hex.len() < 4 && chars.peek().is_some_and(|char| char.is_ascii_hexdigit())
                    {
                        hex.push(chars.next().unwrap());
                    }
                    if hex.len() == 4 {
                        let value = u32::from_str_radix(&hex, 16).unwrap_or(0);
                        decoded.push(char::from_u32(value).unwrap_or('\u{FFFD}'));
                    } else {
                        decoded.push_str("\\u");
                        decoded.push_str(&hex);
                    }
                }
            }
            '\'' | '"' | '`' | '\\' | '/' => {
                decoded.push(next);
                chars.next();
            }
            // Unknown escape: JS keeps the escaped character, drops the
            // backslash.
            other => {
                decoded.push(other);
                chars.next();
            }
        }
    }
    decoded
}
