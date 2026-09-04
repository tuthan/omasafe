use std::process::Command;

use crate::bounds::{GIT_PROCESS_BUDGET, MAX_PROCESS_OUTPUT_BYTES_PER_STREAM, run_bounded_capped};

const REMOTE_HEAD_OUTPUT_CAP: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteHead {
    pub branch: String,
    pub revision: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteHeadError {
    #[error("remote HEAD lookup could not be started: {0}")]
    Io(#[from] std::io::Error),
    #[error("remote did not advertise one exact default-branch commit")]
    InvalidResponse,
    #[error("remote HEAD lookup exceeded its time or output bound")]
    Bounded,
}

pub fn command() -> Command {
    let mut command = Command::new("git");
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_ALLOW_PROTOCOL", "file:git:http:https:ssh")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "diff.external=",
            "-c",
            "protocol.ext.allow=never",
            "--no-optional-locks",
        ]);
    command
}

/// Resolve one symbolic default HEAD with bounded argv-only Git execution.
/// Stderr is deliberately not returned: remote text must not become report
/// or UI content.
pub fn resolve_remote_head(repository_url: &str) -> Result<RemoteHead, RemoteHeadError> {
    let mut command = command();
    command.args([
        "ls-remote",
        "--exit-code",
        "--symref",
        repository_url,
        "HEAD",
    ]);
    let output = run_bounded_capped(
        &mut command,
        GIT_PROCESS_BUDGET,
        REMOTE_HEAD_OUTPUT_CAP.min(MAX_PROCESS_OUTPUT_BYTES_PER_STREAM),
    )?
    .ok_or(RemoteHeadError::Bounded)?;
    if !output.status.success() || output.truncated {
        return Err(RemoteHeadError::InvalidResponse);
    }
    parse_remote_head(&output.stdout)
}

/// Parse the exact two-record format emitted by `git ls-remote --symref URL HEAD`.
pub fn parse_remote_head(output: &[u8]) -> Result<RemoteHead, RemoteHeadError> {
    let text = std::str::from_utf8(output).map_err(|_| RemoteHeadError::InvalidResponse)?;
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    if lines.len() != 2 {
        return Err(RemoteHeadError::InvalidResponse);
    }
    if lines
        .iter()
        .any(|line| line.is_empty() || line.contains('\r'))
    {
        return Err(RemoteHeadError::InvalidResponse);
    }
    let symref: Vec<&str> = lines[0].split_ascii_whitespace().collect();
    let branch_ref = symref.get(1).copied().unwrap_or_default();
    if symref.len() != 3
        || symref[0] != "ref:"
        || symref[2] != "HEAD"
        || !branch_ref.starts_with("refs/heads/")
        || branch_ref.len() <= "refs/heads/".len()
    {
        return Err(RemoteHeadError::InvalidResponse);
    }
    let mapping: Vec<&str> = lines[1].split_ascii_whitespace().collect();
    if mapping.len() != 2 || mapping[1] != "HEAD" || !valid_revision(mapping[0]) {
        return Err(RemoteHeadError::InvalidResponse);
    }
    Ok(RemoteHead {
        branch: branch_ref["refs/heads/".len()..].to_owned(),
        revision: mapping[0].to_ascii_lowercase(),
    })
}

pub fn valid_revision(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_exact_symbolic_head_mapping() {
        let revision = "ABCDEF0123456789ABCDEF0123456789ABCDEF01";
        let head =
            parse_remote_head(format!("ref: refs/heads/main\tHEAD\n{revision}\tHEAD\n").as_bytes())
                .unwrap();
        assert_eq!(head.branch, "main");
        assert_eq!(head.revision, revision.to_ascii_lowercase());
    }

    #[test]
    fn rejects_detached_ambiguous_or_malformed_head_output() {
        let revision = "abcdef0123456789abcdef0123456789abcdef01";
        for output in [
            format!("{revision}\tHEAD\n"),
            format!("ref: refs/tags/v1\tHEAD\n{revision}\tHEAD\n"),
            format!("ref: refs/heads/main\tHEAD\n{revision}\tHEAD\n{revision}\tHEAD\n"),
            format!("ref: refs/heads/main\tHEAD\n\n{revision}\tHEAD\n"),
            "ref: refs/heads/main\tHEAD\nnot-a-revision\tHEAD\n".to_string(),
        ] {
            assert!(parse_remote_head(output.as_bytes()).is_err());
        }
    }
}
