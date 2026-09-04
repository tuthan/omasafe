//! Bounded source parsing for the pre-install candidate workflow.
//!
//! This is intentionally a small finite grammar.  It accepts either one
//! public GitHub repository URL or one copied Omarchy install command.  The
//! command is data: it is never passed to a shell and the parsed verb/flags
//! are only provenance.

use serde::Serialize;

pub const MAX_REQUEST_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateInputKind {
    RawGithubUrl,
    OmarchyInstallCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallVerb {
    None,
    Add,
    Install,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallFlag {
    Enable,
    Yes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParsedCandidateRequest {
    pub input_kind: CandidateInputKind,
    pub install_verb: InstallVerb,
    pub repository_url: String,
    pub discarded_install_flags: Vec<InstallFlag>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceParseError(pub String);

impl std::fmt::Display for SourceParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SourceParseError {}

impl From<&str> for SourceParseError {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// Parses a raw URL or an exact, deliberately small install-command grammar.
pub fn parse_candidate_request(input: &str) -> Result<ParsedCandidateRequest, SourceParseError> {
    if input.len() > MAX_REQUEST_BYTES {
        return Err(SourceParseError(format!(
            "candidate request exceeds the {MAX_REQUEST_BYTES}-byte limit"
        )));
    }
    // The grammar is ASCII by design.  This also rejects Unicode whitespace
    // and confusable command punctuation before tokenization.
    if !input.is_ascii()
        || input
            .bytes()
            .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
    {
        return Err(generic_parse_error());
    }
    let value = trim_ascii_space_tab(input);
    if value.is_empty() {
        return Err(generic_parse_error());
    }

    if value.starts_with("https://") {
        return Ok(ParsedCandidateRequest {
            input_kind: CandidateInputKind::RawGithubUrl,
            install_verb: InstallVerb::None,
            repository_url: canonical_public_github_url(value)?,
            discarded_install_flags: Vec::new(),
        });
    }

    let tokens: Vec<&str> = value
        .split([' ', '\t'])
        .filter(|token| !token.is_empty())
        .collect();
    let mut offset = 0;
    if tokens.first() == Some(&"$") {
        offset = 1;
    }
    let verb = match tokens.get(offset..offset + 3) {
        Some(["omarchy", "plugin", "add"]) => InstallVerb::Add,
        Some(["omarchy", "plugin", "install"]) => InstallVerb::Install,
        _ => return Err(generic_parse_error()),
    };
    let url = *tokens.get(offset + 3).ok_or_else(generic_parse_error)?;
    let repository_url = canonical_public_github_url(url)?;
    let mut flags = Vec::new();
    for token in tokens.iter().skip(offset + 4) {
        let flag = match *token {
            "--enable" => InstallFlag::Enable,
            "--yes" => InstallFlag::Yes,
            value if value.starts_with('-') => {
                return Err(SourceParseError(format!(
                    "unsupported install flag: {}",
                    bounded_token(value)
                )));
            }
            _ => return Err(generic_parse_error()),
        };
        if flags.contains(&flag) {
            return Err(SourceParseError(format!(
                "duplicate install flag: {}",
                match flag {
                    InstallFlag::Enable => "--enable",
                    InstallFlag::Yes => "--yes",
                }
            )));
        }
        flags.push(flag);
    }
    Ok(ParsedCandidateRequest {
        input_kind: CandidateInputKind::OmarchyInstallCommand,
        install_verb: verb,
        repository_url,
        discarded_install_flags: flags,
    })
}

/// Validates and canonicalizes one public GitHub repository URL.  Owner and
/// repository case are retained because the URL is provenance, while the
/// authority is canonicalized to `github.com`.
pub fn canonical_public_github_url(value: &str) -> Result<String, SourceParseError> {
    if !value.starts_with("https://") || value.contains([' ', '\t']) {
        return Err(generic_parse_error());
    }
    let rest = &value["https://".len()..];
    let authority_end = rest.find('/').ok_or_else(generic_parse_error)?;
    let authority = &rest[..authority_end];
    if !authority.eq_ignore_ascii_case("github.com") {
        return Err(SourceParseError(
            "candidate source must be a public HTTPS github.com repository".into(),
        ));
    }
    let raw_path = &rest[authority_end..];
    if raw_path.contains(['?', '#']) || value.contains('@') {
        return Err(generic_parse_error());
    }
    let path = raw_path.strip_prefix('/').ok_or_else(generic_parse_error)?;
    let trailing_slash = path.ends_with('/');
    if path.ends_with("//") {
        return Err(generic_parse_error());
    }
    let path = path.trim_end_matches('/');
    if path.is_empty() || (!trailing_slash && raw_path.ends_with('/')) {
        return Err(generic_parse_error());
    }
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() != 2 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(generic_parse_error());
    }
    let owner = decode_segment(segments[0])?;
    let mut repository = decode_segment(segments[1])?;
    if repository.ends_with(".git") {
        repository.truncate(repository.len() - 4);
    }
    if owner.is_empty()
        || repository.is_empty()
        || owner == "."
        || owner == ".."
        || repository == "."
        || repository == ".."
    {
        return Err(generic_parse_error());
    }
    if owner.contains(['/', '\\'])
        || repository.contains(['/', '\\'])
        || !github_segment_is_safe(&owner)
        || !github_segment_is_safe(&repository)
        || repository.ends_with(".git")
    {
        return Err(generic_parse_error());
    }
    let canonical = format!("https://github.com/{owner}/{repository}.git");
    if canonical.len() > MAX_REQUEST_BYTES {
        return Err(SourceParseError(
            "candidate repository URL is too long".into(),
        ));
    }
    Ok(canonical)
}

fn github_segment_is_safe(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn decode_segment(segment: &str) -> Result<String, SourceParseError> {
    let mut bytes = Vec::with_capacity(segment.len());
    let raw = segment.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        if raw[index] != b'%' {
            if raw[index] < 0x20 || raw[index] == 0x7f {
                return Err(generic_parse_error());
            }
            bytes.push(raw[index]);
            index += 1;
            continue;
        }
        if index + 2 >= raw.len() {
            return Err(generic_parse_error());
        }
        let high = hex(raw[index + 1]).ok_or_else(generic_parse_error)?;
        let low = hex(raw[index + 2]).ok_or_else(generic_parse_error)?;
        let decoded = high * 16 + low;
        // Encoded separators/traversal/control characters are never hidden
        // by decoding into a seemingly valid path segment.
        if matches!(decoded, b'/' | b'\\' | b'\0' | 0x01..=0x1f | 0x7f) || decoded == b'.' {
            return Err(generic_parse_error());
        }
        bytes.push(decoded);
        index += 3;
    }
    String::from_utf8(bytes).map_err(|_| generic_parse_error())
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn trim_ascii_space_tab(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

fn generic_parse_error() -> SourceParseError {
    SourceParseError(
        "paste only the GitHub repository URL or a plain `omarchy plugin add|install URL --enable` command"
            .into(),
    )
}

fn bounded_token(value: &str) -> String {
    let mut token: String = value.chars().take(80).collect();
    if value.chars().count() > 80 {
        token.push('…');
    }
    token
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_urls_and_install_aliases() {
        let raw = parse_candidate_request("  https://GitHub.com/Example/Repo/  ").unwrap();
        assert_eq!(raw.repository_url, "https://github.com/Example/Repo.git");
        assert_eq!(raw.install_verb, InstallVerb::None);
        let tabbed = parse_candidate_request(
            "\tomarchy\tplugin add\thttps://github.com/Example/Repo\t--enable\t--yes\t",
        )
        .unwrap();
        assert_eq!(tabbed.install_verb, InstallVerb::Add);
        assert_eq!(tabbed.discarded_install_flags.len(), 2);
        let command = parse_candidate_request(
            "$ omarchy plugin install https://github.com/Example/Repo --yes --enable",
        )
        .unwrap();
        assert_eq!(command.install_verb, InstallVerb::Install);
        assert_eq!(command.discarded_install_flags.len(), 2);
    }

    #[test]
    fn rejects_wrappers_and_shell_syntax() {
        for input in [
            "sudo omarchy plugin add https://github.com/a/b",
            "omarchy plugin add https://github.com/a/b; echo pwned",
            "omarchy plugin add https://github.com/a/b --force",
            "https://github.com/a/b https://github.com/c/d",
            "omarchy plugin add https://github.com/a/b\nwhoami",
            "omarchy\u{00a0}plugin add https://github.com/a/b",
            "https://github.com/a/%2e%2e",
        ] {
            assert!(
                parse_candidate_request(input).is_err(),
                "accepted {input:?}"
            );
        }
    }
}
