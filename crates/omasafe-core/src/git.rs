use std::process::Command;

use crate::bounds::{GIT_PROCESS_BUDGET, MAX_PROCESS_OUTPUT_BYTES_PER_STREAM, run_bounded_capped};

const REMOTE_HEAD_OUTPUT_CAP: usize = 64 * 1024;
const REMOTE_HEAD_LINE_CAP: usize = 4096;

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

// OmaSafe targets the packaged Linux/Omarchy Git. Neither PATH nor a runtime
// environment override may select the executable or its remote helpers.
fn base_command(protocols: &str) -> Command {
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", "/nonexistent")
        .env("XDG_CONFIG_HOME", "/nonexistent")
        .env("GIT_EXEC_PATH", "/usr/lib/git-core")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_ALLOW_PROTOCOL", protocols)
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .args([
            "-c",
            "credential.helper=",
            "-c",
            "core.askPass=",
            "-c",
            "init.templateDir=",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.sslVerify=true",
            "-c",
            "http.lowSpeedLimit=1024",
            "-c",
            "http.lowSpeedTime=10",
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

/// Offline operations never use a transport, including missing promisor objects.
/// Callers use raw cat-file/ls-tree, never --filters, --textconv or external diff.
pub fn offline() -> Command {
    base_command("")
}

/// Transfer objects only from a supervisor-validated local cache path.
pub fn private_local() -> Command {
    base_command("file")
}

/// Public remote acquisition is HTTPS-only, including redirects and helpers.
pub fn remote_https() -> Command {
    base_command("https")
}

/// Compatibility entrypoint for offline callers; no network permission implied.
pub fn command() -> Command {
    offline()
}

/// Resolve one symbolic default HEAD with bounded argv-only Git execution.
/// Stderr is deliberately not returned: remote text must not become report
/// or UI content.
pub fn resolve_remote_head(repository_url: &str) -> Result<RemoteHead, RemoteHeadError> {
    if !valid_https_url(repository_url) {
        return Err(RemoteHeadError::InvalidResponse);
    }
    let mut command = remote_https();
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

pub fn valid_https_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    !authority.is_empty()
        && !url
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        && !rest.contains(['@', '?', '#', '\\'])
}

/// Parse the exact two-record format emitted by `git ls-remote --symref URL HEAD`.
pub fn parse_remote_head(output: &[u8]) -> Result<RemoteHead, RemoteHeadError> {
    if output.len() > REMOTE_HEAD_OUTPUT_CAP {
        return Err(RemoteHeadError::InvalidResponse);
    }
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
        .any(|line| line.is_empty() || line.contains('\r') || line.len() > REMOTE_HEAD_LINE_CAP)
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

    #[test]
    fn rejects_ref_advertisement_floods_before_parsing() {
        let mut flood = String::new();
        for index in 0..4096 {
            flood.push_str(&format!("deadbeef\trefs/heads/flood-{index}\n"));
        }
        assert!(flood.len() > REMOTE_HEAD_OUTPUT_CAP);
        assert_eq!(
            parse_remote_head(flood.as_bytes()).unwrap_err().to_string(),
            "remote did not advertise one exact default-branch commit"
        );
    }

    #[test]
    fn slow_response_fixture_is_stopped_by_the_git_process_budget() {
        use std::process::Command;
        use std::time::Duration;

        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf 'ref: refs/heads/main\\tHEAD\\n'; sleep 1"]);
        let result = run_bounded_capped(&mut command, Duration::from_millis(50), 4096)
            .expect("slow fixture should start");
        assert!(
            result.is_none(),
            "slow response exceeded its process budget"
        );
    }

    #[test]
    fn accepts_only_credential_free_https_urls() {
        for url in [
            "https://github.com/example/plugin.git",
            "https://example.test/owner/repo",
        ] {
            assert!(valid_https_url(url), "expected valid URL: {url}");
        }
        for url in [
            "file:///tmp/plugin.git",
            "ssh://git@example.test/repo.git",
            "https://user:token@example.test/repo.git",
            "https://example.test/repo.git?redirect=1",
            "https://example.test/repo\\.git",
            "https://example.test/repo.git\n--upload-pack=evil",
        ] {
            assert!(!valid_https_url(url), "accepted unsafe URL: {url:?}");
        }
    }

    #[test]
    fn builders_have_distinct_transport_permissions() {
        let offline = format!("{:?}", offline());
        let local = format!("{:?}", private_local());
        let remote = format!("{:?}", remote_https());
        assert!(
            offline.contains("GIT_ALLOW_PROTOCOL: \"\"")
                || offline.contains("GIT_ALLOW_PROTOCOL=\"\"")
        );
        assert!(
            local.contains("GIT_ALLOW_PROTOCOL: \"file\"")
                || local.contains("GIT_ALLOW_PROTOCOL=\"file\"")
        );
        assert!(
            remote.contains("GIT_ALLOW_PROTOCOL: \"https\"")
                || remote.contains("GIT_ALLOW_PROTOCOL=\"https\"")
        );
        assert!(offline.contains("/usr/bin/git"));
    }
}
