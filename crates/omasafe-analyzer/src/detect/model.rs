//! Shared byte-span helpers used by more than one analysis layer.

/// The bracketed span starting at `open` ('(' or '['): to its matching
/// closer, honoring nesting and quoted strings.
pub(in crate::detect) fn balanced_bracket_span(text: &str, open: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let opener = *bytes.get(open)?;
    let closer = match opener {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        _ => return None,
    };
    let mut depth = 0usize;
    let mut index = open;
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
                } else if byte == opener {
                    depth += 1;
                } else if byte == closer {
                    depth -= 1;
                    if depth == 0 {
                        return Some((open + 1, index));
                    }
                }
            }
        }
        index += 1;
    }
    None
}
