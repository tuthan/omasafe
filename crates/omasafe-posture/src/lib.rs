//! Host-scoped posture checks for OmaSafe.
//!
//! The posture engine is deliberately independent from the plugin report
//! family. It consumes bounded command adapters, keeps command stderr out of
//! reports, and makes inability to observe a property explicit.

use omasafe_core::bounds::{MAX_METADATA_BYTES, run_bounded};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const POSTURE_SCHEMA_VERSION: &str = "omasafe.posture.v1";
pub const POSTURE_STATE_SCHEMA_VERSION: u64 = 1;
pub const CHECK_CATALOG_VERSION: u64 = 1;
pub const MAX_EVIDENCE_ITEMS: usize = 32;
pub const MAX_EVIDENCE_BYTES: usize = 4096;
pub const MAX_REPORT_BYTES: usize = 1024 * 1024;
pub const POST_UPDATE_HOOK_NAME: &str = "omasafe-post-update";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    Pass,
    Regression,
    Attention,
    Informational,
    Incomplete,
    NotApplicable,
    Error,
}

impl CheckState {
    pub fn is_non_passing(self) -> bool {
        matches!(
            self,
            Self::Regression | Self::Attention | Self::Incomplete | Self::Error
        )
    }

    pub fn is_coverage_loss(self) -> bool {
        matches!(self, Self::Incomplete | Self::Error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolObservation {
    pub name: String,
    pub path: Option<String>,
    pub version: Option<String>,
    pub available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckResult {
    pub id: String,
    pub title: String,
    pub state: CheckState,
    pub evidence: Vec<String>,
    pub observed_at: String,
    pub dependencies: Vec<String>,
    pub limitations: Vec<String>,
    pub next_step: Option<String>,
    pub tool: Option<ToolObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct HostProfile {
    pub os: String,
    pub arch: String,
    pub omarchy_path: Option<String>,
    pub omarchy_version: Option<String>,
    pub kernel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolInventoryEntry {
    pub name: String,
    pub path: Option<String>,
    pub version: Option<String>,
    pub available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostureReport {
    pub schema: String,
    pub check_catalog_version: u64,
    pub generated_at: String,
    pub host: HostProfile,
    pub tools: Vec<ToolInventoryEntry>,
    pub checks: Vec<CheckResult>,
    pub coverage: CoverageSummary,
    pub last_observed_post_update_hook: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CoverageSummary {
    pub complete: usize,
    pub incomplete: usize,
    pub errors: usize,
    pub not_applicable: usize,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageEpisode {
    pub check_id: String,
    pub started_at: String,
    pub last_seen_at: String,
    pub notified: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostureState {
    pub schema_version: u64,
    pub last_report_at: Option<String>,
    pub last_report_path: Option<String>,
    #[serde(default)]
    pub previous_states: BTreeMap<String, CheckState>,
    #[serde(default)]
    pub coverage_episodes: BTreeMap<String, CoverageEpisode>,
    #[serde(default)]
    pub last_notified_states: BTreeMap<String, CheckState>,
    #[serde(default)]
    pub whole_scan_failures: u32,
}

impl Default for PostureState {
    fn default() -> Self {
        Self {
            schema_version: POSTURE_STATE_SCHEMA_VERSION,
            last_report_at: None,
            last_report_path: None,
            previous_states: BTreeMap::new(),
            coverage_episodes: BTreeMap::new(),
            last_notified_states: BTreeMap::new(),
            whole_scan_failures: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostureNotification {
    pub key: String,
    pub check_id: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum RunnerError {
    #[error("tool is unavailable: {0}")]
    Unavailable(String),
    #[error("tool execution failed: {0}")]
    Io(String),
    #[error("tool output exceeded the capture limit")]
    Truncated,
}

/// Command boundary used by every check. Implementations must not expose
/// stderr; that stream is diagnostic only.
pub trait CommandAdapter {
    fn execute(
        &self,
        tool: &str,
        args: &[&str],
        budget: Duration,
    ) -> Result<CommandOutput, RunnerError>;
    fn describe(&self, tool: &str) -> ToolObservation;
}

#[derive(Debug, Clone)]
pub struct SystemCommandAdapter {
    tool_dir: Option<PathBuf>,
}

impl SystemCommandAdapter {
    pub fn from_environment() -> Self {
        let tool_dir = env::var_os("OMASAFE_POSTURE_TOOL_DIR")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute());
        Self { tool_dir }
    }

    pub fn with_tool_dir(path: impl Into<PathBuf>) -> Self {
        Self {
            tool_dir: Some(path.into()),
        }
    }

    fn resolve(&self, tool: &str) -> Option<PathBuf> {
        if let Some(dir) = &self.tool_dir {
            let candidate = dir.join(tool);
            if executable_file(&candidate) && safe_path_chain(&candidate) {
                return Some(candidate);
            }
        }
        for root in ["/usr/bin", "/usr/sbin", "/bin", "/sbin"] {
            let candidate = Path::new(root).join(tool);
            if executable_file(&candidate) && safe_path_chain(&candidate) {
                return Some(candidate);
            }
        }
        None
    }
}

impl Default for SystemCommandAdapter {
    fn default() -> Self {
        Self::from_environment()
    }
}

impl CommandAdapter for SystemCommandAdapter {
    fn execute(
        &self,
        tool: &str,
        args: &[&str],
        budget: Duration,
    ) -> Result<CommandOutput, RunnerError> {
        let path = self
            .resolve(tool)
            .ok_or_else(|| RunnerError::Unavailable(tool.to_owned()))?;
        let mut command = Command::new(&path);
        command.args(args);
        command.env_clear();
        command.env("LANG", "C");
        command.env("LC_ALL", "C");
        command.env("PATH", "/usr/bin:/usr/sbin:/bin:/sbin");
        command.env("GIT_CONFIG_NOSYSTEM", "1");
        command.env("GIT_TERMINAL_PROMPT", "0");
        command.current_dir("/");
        let output = run_bounded(&mut command, budget)
            .map_err(|error| RunnerError::Io(error.to_string()))?
            .ok_or_else(|| RunnerError::Unavailable(tool.to_owned()))?;
        if output.truncated {
            return Err(RunnerError::Truncated);
        }
        Ok(CommandOutput {
            status: output.status.code(),
            stdout: output.stdout,
            truncated: output.truncated,
        })
    }

    fn describe(&self, tool: &str) -> ToolObservation {
        let path = self.resolve(tool);
        let version = path.as_ref().and_then(|_| {
            self.execute(tool, &["--version"], Duration::from_millis(500))
                .ok()
                .and_then(|output| sanitized_line(&output.stdout))
        });
        ToolObservation {
            name: tool.to_owned(),
            path: path.as_ref().map(|p| p.display().to_string()),
            version,
            available: path.is_some(),
        }
    }
}

/// Deterministic fixture adapter for tests and offline support reproduction.
#[derive(Debug, Clone, Default)]
pub struct FixtureCommandAdapter {
    pub responses: BTreeMap<String, Result<CommandOutput, RunnerError>>,
    pub tools: BTreeMap<String, ToolObservation>,
}

impl FixtureCommandAdapter {
    pub fn response(mut self, tool: &str, output: CommandOutput) -> Self {
        self.responses.insert(tool.to_owned(), Ok(output));
        self
    }

    pub fn failure(mut self, tool: &str, error: RunnerError) -> Self {
        self.responses.insert(tool.to_owned(), Err(error));
        self
    }

    pub fn response_args(mut self, tool: &str, args: &[&str], output: CommandOutput) -> Self {
        self.responses.insert(command_key(tool, args), Ok(output));
        self
    }

    pub fn tool(mut self, tool: &str, path: impl Into<String>, version: impl Into<String>) -> Self {
        self.tools.insert(
            tool.to_owned(),
            ToolObservation {
                name: tool.to_owned(),
                path: Some(path.into()),
                version: Some(version.into()),
                available: true,
            },
        );
        self
    }
}

impl CommandAdapter for FixtureCommandAdapter {
    fn execute(
        &self,
        tool: &str,
        args: &[&str],
        _budget: Duration,
    ) -> Result<CommandOutput, RunnerError> {
        self.responses
            .get(&command_key(tool, args))
            .or_else(|| self.responses.get(tool))
            .cloned()
            .unwrap_or_else(|| Err(RunnerError::Unavailable(tool.to_owned())))
    }

    fn describe(&self, tool: &str) -> ToolObservation {
        self.tools.get(tool).cloned().unwrap_or(ToolObservation {
            name: tool.to_owned(),
            path: None,
            version: None,
            available: self
                .responses
                .keys()
                .any(|key| key == tool || key.starts_with(&format!("{tool} "))),
        })
    }
}

fn command_key(tool: &str, args: &[&str]) -> String {
    if args.is_empty() {
        tool.to_owned()
    } else {
        format!("{tool} {}", args.join(" "))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PostureError {
    #[error("posture I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("posture JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("posture state is malformed at {path}: {source}")]
    State {
        path: String,
        source: serde_json::Error,
    },
}

pub fn now() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_owned())
}

pub fn check_catalog() -> Vec<(&'static str, &'static str)> {
    vec![
        ("host.context", "Omarchy host context"),
        ("updates.repository", "Repository package updates"),
        ("updates.omarchy", "Omarchy update availability"),
        (
            "vulnerabilities.arch_audit",
            "Known official package vulnerabilities",
        ),
        ("encryption.root_luks", "Root filesystem encryption"),
        ("firewall.configuration", "Firewall configuration"),
        ("firewall.service", "Firewall service state"),
        ("firewall.effective", "Effective firewall policy"),
        ("network.listeners", "Listening network sockets"),
        ("kernel.restart", "Kernel restart state"),
        ("packages.foreign", "Foreign package inventory"),
        ("packages.keyring", "Pacman keyring state"),
        ("persistence.selected", "Selected persistence surfaces"),
        ("execution.path", "Executable search path integrity"),
        ("boot.secure_boot", "Secure Boot state"),
        ("ssh.configuration", "SSH daemon configuration"),
        ("packages.integrity", "Pacman package integrity metadata"),
        ("updates.post_update_hook", "Last observed post-update hook"),
    ]
}

pub fn scan() -> PostureReport {
    scan_with_adapter(&SystemCommandAdapter::default())
}

pub fn scan_with_adapter<A: CommandAdapter>(adapter: &A) -> PostureReport {
    let generated_at = now();
    let (host, raw_omarchy_path) = discover_host(adapter);
    let names: BTreeSet<&str> = check_catalog().iter().map(|(id, _)| *id).collect();
    let mut checks = Vec::new();
    checks.push(check_context(&host));
    let repository_check =
        checkupdates(adapter, "updates.repository", "Repository package updates");
    checks.push(repository_check.clone());
    checks.push(check_omarchy_updates(
        adapter,
        raw_omarchy_path.as_deref(),
        &repository_check,
    ));
    checks.push(arch_audit(adapter));
    checks.push(root_luks(adapter));
    checks.push(firewall_configuration(adapter));
    checks.push(firewall_service(adapter));
    checks.push(firewall_effective(adapter));
    checks.push(listeners(adapter));
    checks.push(kernel_restart(adapter, &host));
    checks.push(foreign_packages(adapter));
    checks.push(keyring());
    checks.push(persistence());
    checks.push(path_integrity());
    checks.push(secure_boot(adapter));
    checks.push(ssh_configuration(adapter));
    checks.push(package_integrity(adapter));
    checks.push(post_update_hook());
    checks.retain(|check| names.contains(check.id.as_str()));
    checks.sort_by(|a, b| a.id.cmp(&b.id));
    let tools = [
        "checkupdates",
        "pacman",
        "arch-audit",
        "findmnt",
        "lsblk",
        "nft",
        "ufw",
        "ss",
        "uname",
        "bootctl",
        "systemctl",
        "git",
    ]
    .iter()
    .map(|name| adapter.describe(name))
    .map(|mut tool| {
        if let Some(path) = tool.path.as_mut() {
            *path = redact_path(path);
        }
        ToolInventoryEntry {
            name: tool.name,
            path: tool.path,
            version: tool.version,
            available: tool.available,
        }
    })
    .collect();
    let coverage = summarize_coverage(&checks);
    PostureReport {
        schema: POSTURE_SCHEMA_VERSION.to_owned(),
        check_catalog_version: CHECK_CATALOG_VERSION,
        generated_at,
        host,
        tools,
        checks,
        coverage,
        last_observed_post_update_hook: read_hook_stamp(),
    }
}

pub fn update_state(state: &mut PostureState, report: &PostureReport) -> Vec<PostureNotification> {
    let mut notifications = Vec::new();
    let now = report.generated_at.clone();
    for check in &report.checks {
        let prior = state.previous_states.insert(check.id.clone(), check.state);
        if check.state.is_coverage_loss() {
            state.last_notified_states.remove(&check.id);
            let episode = state
                .coverage_episodes
                .entry(check.id.clone())
                .or_insert_with(|| CoverageEpisode {
                    check_id: check.id.clone(),
                    started_at: now.clone(),
                    last_seen_at: now.clone(),
                    notified: false,
                    reason: first_reason(check),
                });
            episode.last_seen_at = now.clone();
            if !episode.notified && prior.is_some_and(|state| !state.is_coverage_loss()) {
                episode.notified = true;
                notifications.push(PostureNotification {
                    key: format!("coverage:{}:{}", check.id, episode.started_at),
                    check_id: check.id.clone(),
                    message: format!("{} coverage was lost: {}", check.title, first_reason(check)),
                });
            }
        } else if matches!(check.state, CheckState::Regression | CheckState::Attention) {
            if prior.is_some() && state.last_notified_states.get(&check.id) != Some(&check.state) {
                state
                    .last_notified_states
                    .insert(check.id.clone(), check.state);
                notifications.push(PostureNotification {
                    key: format!("state:{}:{:?}", check.id, check.state),
                    check_id: check.id.clone(),
                    message: format!("{} requires review", check.title),
                });
            }
        } else if check.state != CheckState::Error {
            state.coverage_episodes.remove(&check.id);
            state.last_notified_states.remove(&check.id);
        }
    }
    state.last_report_at = Some(now);
    notifications
}

pub fn state_path(paths: &omasafe_core::paths::XdgPaths) -> PathBuf {
    paths.state.join("posture-state.json")
}

pub fn load_state(path: &Path) -> Result<PostureState, PostureError> {
    if fs::metadata(path)
        .ok()
        .is_some_and(|metadata| metadata.len() > MAX_REPORT_BYTES as u64)
    {
        return Err(PostureError::State {
            path: path.display().to_string(),
            source: serde_json::Error::io(io::Error::new(
                io::ErrorKind::InvalidData,
                "posture state exceeds the retention limit",
            )),
        });
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(PostureState::default()),
        Err(error) => return Err(error.into()),
    };
    let state: PostureState =
        serde_json::from_slice(&bytes).map_err(|source| PostureError::State {
            path: path.display().to_string(),
            source,
        })?;
    if state.schema_version != POSTURE_STATE_SCHEMA_VERSION {
        return Err(PostureError::State {
            path: path.display().to_string(),
            source: serde_json::Error::io(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported posture state schema",
            )),
        });
    }
    Ok(state)
}

pub fn store_state(path: &Path, state: &PostureState) -> Result<(), PostureError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(state)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(PostureError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "posture state exceeds the retention limit",
        )));
    }
    atomic_replace(path, &bytes, 0o600)?;
    Ok(())
}

pub fn store_report(path: &Path, report: &PostureReport) -> Result<(), PostureError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(report)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(PostureError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "posture report exceeds the retention limit",
        )));
    }
    atomic_replace(path, &bytes, 0o600)?;
    Ok(())
}

impl PostureState {
    pub fn load(path: &Path) -> Result<Self, PostureError> {
        load_state(path)
    }

    pub fn store(&self, path: &Path) -> Result<(), PostureError> {
        store_state(path, self)
    }
}

fn atomic_replace(path: &Path, bytes: &[u8], mode: u32) -> Result<(), PostureError> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "state file has no parent"))?;
    fs::create_dir_all(parent)?;
    let unique = format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("posture"),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let temporary = parent.join(unique);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    #[cfg(unix)]
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

pub fn render_markdown(report: &PostureReport) -> String {
    let mut out = String::from("# OmaSafe posture report\n\n");
    out.push_str(&format!("Generated: `{}`\n\n", report.generated_at));
    out.push_str("| Check | State | Evidence | Coverage / limitation |\n|---|---|---|---|\n");
    for check in &report.checks {
        let evidence = check
            .evidence
            .first()
            .cloned()
            .unwrap_or_else(|| "—".to_owned());
        let limitation = check
            .limitations
            .first()
            .cloned()
            .unwrap_or_else(|| "—".to_owned());
        out.push_str(&format!(
            "| {} | {:?} | {} | {} |\n",
            check.title,
            check.state,
            markdown_cell(&evidence),
            markdown_cell(&limitation)
        ));
    }
    out
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

fn discover_host<A: CommandAdapter>(adapter: &A) -> (HostProfile, Option<PathBuf>) {
    let raw_omarchy_path = env::var_os("OMARCHY_PATH")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            Path::new("/usr/share/omarchy")
                .is_dir()
                .then(|| PathBuf::from("/usr/share/omarchy"))
        });
    let kernel = adapter
        .execute("uname", &["-r"], Duration::from_secs(1))
        .ok()
        .and_then(|o| sanitized_line(&o.stdout));
    let omarchy_version = raw_omarchy_path.as_ref().and_then(|path| {
        if path == Path::new("/usr/share/omarchy") {
            adapter
                .execute("pacman", &["-Q", "omarchy"], Duration::from_secs(2))
                .ok()
                .and_then(|output| {
                    safe_lines(&output.stdout)
                        .into_iter()
                        .find_map(|line| line.strip_prefix("omarchy ").map(str::to_owned))
                })
        } else {
            read_text_capped(&path.join("VERSION"), MAX_METADATA_BYTES)
                .ok()
                .and_then(|value| sanitized_text(&value))
        }
    });
    let host = HostProfile {
        os: "arch".to_owned(),
        arch: env::consts::ARCH.to_owned(),
        omarchy_path: raw_omarchy_path
            .as_ref()
            .map(|p| redact_path(&p.display().to_string())),
        omarchy_version,
        kernel,
    };
    (host, raw_omarchy_path)
}

fn check_context(host: &HostProfile) -> CheckResult {
    let state = if host.omarchy_path.is_some() {
        CheckState::Pass
    } else {
        CheckState::Informational
    };
    result(
        "host.context",
        "Omarchy host context",
        state,
        vec![if let Some(path) = &host.omarchy_path {
            format!("Omarchy path: {path}")
        } else {
            "Plain Arch context detected; Omarchy package checks may be not applicable".to_owned()
        }],
        Vec::new(),
        Some("Keep OmaSafe checks scoped to this host context.".to_owned()),
        None,
    )
}

fn checkupdates<A: CommandAdapter>(adapter: &A, id: &str, title: &str) -> CheckResult {
    let tool = adapter.describe("checkupdates");
    let output = match adapter.execute("checkupdates", &["--nocolor"], Duration::from_secs(30)) {
        Ok(output) => output,
        Err(error) => {
            return incomplete(
                id,
                title,
                tool,
                format_runner_error(error),
                "Install pacman-contrib and retry the posture scan.",
            );
        }
    };
    if output.truncated {
        return incomplete(
            id,
            title,
            tool,
            "checkupdates output was truncated".to_owned(),
            "Retry the scan after resolving the command-output limit.",
        );
    }
    match output.status {
        Some(0) => {
            let lines = safe_lines(&output.stdout);
            if lines.is_empty() {
                incomplete(
                    id,
                    title,
                    tool,
                    "checkupdates reported updates without a parseable inventory".to_owned(),
                    "Run `omarchy update` after reviewing the package inventory.",
                )
            } else {
                result(
                    id,
                    title,
                    CheckState::Regression,
                    lines,
                    Vec::new(),
                    Some("Run `omarchy update` after reviewing the pending packages.".to_owned()),
                    Some(tool),
                )
            }
        }
        Some(2) => {
            // `checkupdates` uses a private sync database, but its exit status
            // alone cannot prove that the internal package query completed.
            // A separate read-only pacman query is required before reporting
            // that the repository is current.
            match adapter.execute("pacman", &["-Qu"], Duration::from_secs(10)) {
                Ok(query) if query.status == Some(0) && !query.truncated => {
                    let lines = safe_lines(&query.stdout);
                    if lines.is_empty() {
                        result(
                            id,
                            title,
                            CheckState::Pass,
                            vec![
                                "no repository package updates were reported after an independent package query"
                                    .to_owned(),
                            ],
                            vec![
                                "checkupdates returned its no-update status; package-query completion was validated separately"
                                    .to_owned(),
                            ],
                            Some("Keep the supported Omarchy update workflow available.".to_owned()),
                            Some(tool),
                        )
                    } else {
                        result(
                            id,
                            title,
                            CheckState::Regression,
                            lines,
                            vec![
                                "checkupdates returned its no-update status, but the independent package query reported updates"
                                    .to_owned(),
                            ],
                            Some("Run `omarchy update` after reviewing the pending packages.".to_owned()),
                            Some(tool),
                        )
                    }
                }
                Ok(_) => incomplete(
                    id,
                    title,
                    tool,
                    "checkupdates returned its ambiguous no-update status, but the independent package query did not complete",
                    "Retry when the package database and query tools are available.",
                ),
                Err(error) => incomplete(
                    id,
                    title,
                    tool,
                    format!(
                        "checkupdates returned its ambiguous no-update status, but the independent package query was unavailable: {}",
                        format_runner_error(error)
                    ),
                    "Retry when the package database and query tools are available.",
                ),
            }
        }
        Some(code) => incomplete(
            id,
            title,
            tool,
            format!("checkupdates failed with exit status {code}"),
            "Retry the scan and inspect package-manager availability.",
        ),
        None => incomplete(
            id,
            title,
            tool,
            "checkupdates did not return an exit status",
            "Retry the scan.",
        ),
    }
}

fn check_omarchy_updates<A: CommandAdapter>(
    adapter: &A,
    raw_omarchy_path: Option<&Path>,
    repository: &CheckResult,
) -> CheckResult {
    if raw_omarchy_path == Some(Path::new("/usr/share/omarchy")) {
        if repository.state == CheckState::Regression {
            let updates = repository
                .evidence
                .iter()
                .filter(|line| {
                    let package = line.split_whitespace().next().unwrap_or_default();
                    package == "omarchy" || package == "omarchy-dev"
                })
                .cloned()
                .collect::<Vec<_>>();
            if updates.is_empty() {
                result(
                    "updates.omarchy",
                    "Omarchy update availability",
                    CheckState::Pass,
                    vec!["no packaged omarchy or omarchy-dev update was found in the validated inventory".to_owned()],
                    Vec::new(),
                    Some("Keep the supported Omarchy installation current.".to_owned()),
                    repository.tool.clone(),
                )
            } else {
                result(
                    "updates.omarchy",
                    "Omarchy update availability",
                    CheckState::Regression,
                    updates,
                    Vec::new(),
                    Some(
                        "Run `omarchy update` after reviewing the pending Omarchy package."
                            .to_owned(),
                    ),
                    repository.tool.clone(),
                )
            }
        } else {
            result(
                "updates.omarchy",
                "Omarchy update availability",
                repository.state,
                repository.evidence.clone(),
                repository.limitations.clone(),
                Some("Run `omarchy update` after reviewing the package inventory.".to_owned()),
                repository.tool.clone(),
            )
        }
    } else if let Some(path) = raw_omarchy_path {
        development_checkout(adapter, path)
    } else {
        result(
            "updates.omarchy",
            "Omarchy update availability",
            CheckState::NotApplicable,
            vec!["No packaged Omarchy installation was detected".to_owned()],
            Vec::new(),
            Some("Set OMARCHY_PATH for a development checkout to enable this check.".to_owned()),
            None,
        )
    }
}

fn development_checkout<A: CommandAdapter>(adapter: &A, checkout: &Path) -> CheckResult {
    let tool = adapter.describe("git");
    let git_dir = checkout.join(".git");
    let config_path = if git_dir.is_dir() {
        git_dir.join("config")
    } else {
        checkout.join(".git")
    };
    let config = match read_text_capped(&config_path, MAX_METADATA_BYTES) {
        Ok(config) => config,
        Err(_) => {
            return incomplete(
                "updates.omarchy",
                "Omarchy update availability",
                tool,
                "development checkout Git metadata was unavailable",
                "Configure a supported Omarchy upstream and retry.",
            );
        }
    };
    let (url, config_error) = parse_safe_upstream(&config);
    if let Some(error) = config_error {
        return incomplete(
            "updates.omarchy",
            "Omarchy update availability",
            tool,
            error,
            "Use a supported HTTPS upstream without checkout-configured helpers.",
        );
    }
    let Some(url) = url else {
        return incomplete(
            "updates.omarchy",
            "Omarchy update availability",
            tool,
            "development checkout has no supported upstream URL",
            "Configure remote.origin.url for the Omarchy checkout.",
        );
    };
    let head = match read_checkout_head(checkout, &git_dir) {
        Some(head) => head,
        None => {
            return incomplete(
                "updates.omarchy",
                "Omarchy update availability",
                tool,
                "development checkout HEAD was unavailable",
                "Retry after the checkout has a readable HEAD object.",
            );
        }
    };
    let cache = match isolated_git_cache(&url) {
        Ok(cache) => cache,
        Err(error) => {
            return incomplete(
                "updates.omarchy",
                "Omarchy update availability",
                tool,
                format!("OmaSafe Git cache was unavailable: {error}"),
                "Retry after the OmaSafe cache is writable.",
            );
        }
    };
    let cache_text = cache.to_string_lossy().to_string();
    let init = adapter.execute(
        "git",
        &["init", "--bare", "--quiet", &cache_text],
        Duration::from_secs(5),
    );
    if init.as_ref().is_err() || init.as_ref().is_ok_and(|output| output.status != Some(0)) {
        return incomplete(
            "updates.omarchy",
            "Omarchy update availability",
            tool,
            "isolated Git cache initialization failed",
            "Retry after the OmaSafe cache is writable.",
        );
    }
    let output = match adapter.execute(
        "git",
        &[
            "--git-dir",
            &cache_text,
            "fetch",
            "--no-tags",
            "--prune",
            &url,
            "HEAD",
        ],
        Duration::from_secs(30),
    ) {
        Ok(output) => output,
        Err(error) => {
            return incomplete(
                "updates.omarchy",
                "Omarchy update availability",
                tool,
                format!("upstream fetch failed: {}", format_runner_error(error)),
                "Retry when the upstream is reachable.",
            );
        }
    };
    if output.status != Some(0) {
        return incomplete(
            "updates.omarchy",
            "Omarchy update availability",
            tool,
            "upstream fetch failed",
            "Retry when the upstream is reachable.",
        );
    }
    let fetched = if output.status == Some(0) {
        adapter
            .execute(
                "git",
                &["--git-dir", &cache_text, "rev-parse", "FETCH_HEAD"],
                Duration::from_secs(3),
            )
            .ok()
            .map(|output| output.stdout)
            .unwrap_or_else(|| output.stdout.clone())
    } else {
        output.stdout.clone()
    };
    let upstream = safe_lines(&fetched)
        .into_iter()
        .find_map(|line| line.split_whitespace().next().map(str::to_owned));
    let Some(upstream) = upstream else {
        return incomplete(
            "updates.omarchy",
            "Omarchy update availability",
            tool,
            "upstream HEAD output was unavailable",
            "Retry with a reachable, valid upstream.",
        );
    };
    if !is_hex_commit(&head) || !is_hex_commit(&upstream) {
        return incomplete(
            "updates.omarchy",
            "Omarchy update availability",
            tool,
            "checkout or upstream HEAD was malformed",
            "Retry with a valid Git checkout and upstream.",
        );
    }
    let state = if head == upstream {
        CheckState::Pass
    } else {
        CheckState::Regression
    };
    result(
        "updates.omarchy",
        "Omarchy update availability",
        state,
        vec![
            format!("checkout HEAD: {head}"),
            format!("upstream HEAD: {upstream}"),
        ],
        vec![
            "development-checkout comparison reads upstream metadata without writing the checkout"
                .to_owned(),
        ],
        Some("Run `omarchy update` after reviewing the upstream change.".to_owned()),
        Some(tool),
    )
}

fn parse_safe_upstream(config: &str) -> (Option<String>, Option<String>) {
    let mut in_origin = false;
    let mut url = None;
    for raw in config.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            let section = line.trim_matches(['[', ']']).to_ascii_lowercase();
            in_origin = section == "remote \"origin\"";
            if section.starts_with("include") || section.starts_with("submodule") {
                return (
                    None,
                    Some(
                        "development checkout uses unsupported Git includes or submodules"
                            .to_owned(),
                    ),
                );
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if key.contains("sshcommand")
            || key.contains("credential")
            || key.contains("hook")
            || key.contains("helper")
            || key.contains("insteadof")
            || key.contains("remotehelpers")
        {
            return (
                None,
                Some(
                    "development checkout Git configuration contains an executable helper"
                        .to_owned(),
                ),
            );
        }
        if in_origin && key == "url" {
            if value.contains('@')
                || !value.starts_with("https://")
                || value.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                return (
                    None,
                    Some(
                        "development checkout upstream must be a credential-free HTTPS URL"
                            .to_owned(),
                    ),
                );
            }
            url = Some(value.trim_end_matches('/').to_owned());
        }
        if in_origin && key == "fetch" && value != "+refs/heads/*:refs/remotes/origin/*" {
            return (
                None,
                Some("development checkout upstream refspec is unsupported".to_owned()),
            );
        }
    }
    (url, None)
}

fn read_checkout_head(checkout: &Path, git_dir: &Path) -> Option<String> {
    let head = read_text_capped(&git_dir.join("HEAD"), MAX_METADATA_BYTES).ok()?;
    let head = head.trim();
    if let Some(reference) = head.strip_prefix("ref: ") {
        return read_text_capped(&git_dir.join(reference), MAX_METADATA_BYTES)
            .ok()
            .map(|value| value.trim().to_owned());
    }
    if head.len() == 40 && is_hex_commit(head) {
        Some(head.to_owned())
    } else {
        let _ = checkout;
        None
    }
}

fn isolated_git_cache(url: &str) -> io::Result<PathBuf> {
    let root = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(".cache")
        })
        .join("omasafe/posture/git");
    fs::create_dir_all(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    }
    let digest = Sha256::digest(url.as_bytes());
    let path = root.join(format!("{digest:x}"));
    if let Ok(metadata) = fs::symlink_metadata(&path)
        && (metadata.file_type().is_symlink() || !metadata.is_dir())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "isolated Git cache path is not a directory",
        ));
    }
    Ok(path)
}

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn arch_audit<A: CommandAdapter>(adapter: &A) -> CheckResult {
    let tool = adapter.describe("arch-audit");
    let output = match adapter.execute("arch-audit", &["--quiet"], Duration::from_secs(30)) {
        Ok(output) => output,
        Err(error) => {
            return incomplete(
                "vulnerabilities.arch_audit",
                "Known official package vulnerabilities",
                tool,
                format_runner_error(error),
                "Install the official `arch-audit` package and retry.",
            );
        }
    };
    if output.status != Some(0) {
        return incomplete(
            "vulnerabilities.arch_audit",
            "Known official package vulnerabilities",
            tool,
            "arch-audit could not complete",
            "Refresh official vulnerability data and retry.",
        );
    }
    let lines = safe_lines(&output.stdout);
    if lines.is_empty() {
        result(
            "vulnerabilities.arch_audit",
            "Known official package vulnerabilities",
            CheckState::Pass,
            vec!["No matching official-repository advisories were reported".to_owned()],
            Vec::new(),
            Some("Keep official vulnerability data current.".to_owned()),
            Some(tool),
        )
    } else {
        result(
            "vulnerabilities.arch_audit",
            "Known official package vulnerabilities",
            CheckState::Regression,
            lines,
            vec!["AUR and foreign packages are outside arch-audit coverage".to_owned()],
            Some(
                "Review the advisory and update through the supported Omarchy workflow.".to_owned(),
            ),
            Some(tool),
        )
    }
}

fn root_luks<A: CommandAdapter>(adapter: &A) -> CheckResult {
    let tool = adapter.describe("lsblk");
    let output = match adapter.execute(
        "lsblk",
        &[
            "--json",
            "--tree",
            "--output",
            "NAME,TYPE,PKNAME,MOUNTPOINTS",
        ],
        Duration::from_secs(3),
    ) {
        Ok(output) => output,
        Err(error) => {
            return incomplete(
                "encryption.root_luks",
                "Root filesystem encryption",
                tool,
                format_runner_error(error),
                "Install util-linux or grant access to block-device metadata.",
            );
        }
    };
    let value: serde_json::Value = match serde_json::from_slice(&output.stdout) {
        Ok(value) => value,
        Err(_) => {
            return incomplete(
                "encryption.root_luks",
                "Root filesystem encryption",
                tool,
                "lsblk returned malformed block-device metadata",
                "Retry with readable block-device metadata.",
            );
        }
    };
    if output.status != Some(0) || !value.get("blockdevices").is_some() {
        return incomplete(
            "encryption.root_luks",
            "Root filesystem encryption",
            tool,
            "lsblk returned malformed block-device metadata",
            "Retry with readable block-device metadata.",
        );
    }
    let Some(encrypted) = json_root_has_crypt(&value) else {
        return incomplete(
            "encryption.root_luks",
            "Root filesystem encryption",
            tool,
            "lsblk did not identify the root mountpoint in the block-device ancestry",
            "Retry with readable root block-device metadata.",
        );
    };
    result(
        "encryption.root_luks",
        "Root filesystem encryption",
        if encrypted {
            CheckState::Pass
        } else {
            CheckState::Attention
        },
        vec![if encrypted {
            "A LUKS/crypt ancestor was found for the root device".to_owned()
        } else {
            "No LUKS/crypt ancestor was found in the root device ancestry".to_owned()
        }],
        Vec::new(),
        Some("Review the root-device layout before changing encryption settings.".to_owned()),
        Some(tool),
    )
}

fn firewall_configuration<A: CommandAdapter>(adapter: &A) -> CheckResult {
    let nft = adapter.describe("nft");
    let ufw = adapter.describe("ufw");
    let nft_out = adapter.execute("nft", &["-s", "list", "ruleset"], Duration::from_secs(3));
    let ufw_out = adapter.execute("ufw", &["show", "raw"], Duration::from_secs(3));
    let nft_ok = nft_out
        .as_ref()
        .is_ok_and(|output| output.status == Some(0));
    let ufw_ok = ufw_out
        .as_ref()
        .is_ok_and(|output| output.status == Some(0));
    if !nft_ok && !ufw_ok {
        return incomplete(
            "firewall.configuration",
            "Firewall configuration",
            nft,
            "Neither nftables nor ufw configuration was readable",
            "Install or configure a supported firewall frontend.",
        );
    }
    let mut evidence = Vec::new();
    if nft_ok {
        evidence.push("nftables configuration is readable".to_owned());
    }
    if ufw_ok {
        evidence.push("ufw configuration is readable".to_owned());
    }
    result(
        "firewall.configuration",
        "Firewall configuration",
        CheckState::Informational,
        evidence,
        Vec::new(),
        Some("Review the active firewall configuration if listeners change.".to_owned()),
        Some(if nft_ok { nft } else { ufw }),
    )
}

fn firewall_service<A: CommandAdapter>(adapter: &A) -> CheckResult {
    let tool = adapter.describe("systemctl");
    let nft = adapter.execute(
        "systemctl",
        &["is-active", "nftables.service"],
        Duration::from_secs(2),
    );
    let ufw = adapter.execute(
        "systemctl",
        &["is-active", "ufw.service"],
        Duration::from_secs(2),
    );
    let active = nft.as_ref().is_ok_and(|output| output.status == Some(0))
        || ufw.as_ref().is_ok_and(|output| output.status == Some(0));
    if nft.is_err() && ufw.is_err() {
        return incomplete(
            "firewall.service",
            "Firewall service state",
            tool,
            "firewall service state was unavailable",
            "Retry with systemd user-session access.",
        );
    }
    result(
        "firewall.service",
        "Firewall service state",
        if active {
            CheckState::Informational
        } else {
            CheckState::Attention
        },
        vec![if active {
            "a supported firewall service is active; runtime policy is checked separately"
                .to_owned()
        } else {
            "no supported firewall service was reported active".to_owned()
        }],
        Vec::new(),
        Some("Review firewall service state together with the effective-policy check.".to_owned()),
        Some(tool),
    )
}

fn firewall_effective<A: CommandAdapter>(adapter: &A) -> CheckResult {
    let tool = adapter.describe("nft");
    match adapter.execute("nft", &["list", "ruleset"], Duration::from_secs(3)) {
        Ok(output) if output.status == Some(0) => result(
            "firewall.effective",
            "Effective firewall policy",
            CheckState::Pass,
            vec!["The runtime nftables policy was readable".to_owned()],
            Vec::new(),
            Some("Recheck after firewall changes.".to_owned()),
            Some(tool),
        ),
        Ok(_) => incomplete(
            "firewall.effective",
            "Effective firewall policy",
            tool,
            "runtime firewall policy was denied or unavailable to the unprivileged scan",
            "Run the posture scan as the supported user session; OmaSafe does not request elevation.",
        ),
        Err(error) => incomplete(
            "firewall.effective",
            "Effective firewall policy",
            tool,
            format_runner_error(error),
            "Runtime firewall policy is unobserved without supported permissions.",
        ),
    }
}

fn listeners<A: CommandAdapter>(adapter: &A) -> CheckResult {
    let tool = adapter.describe("ss");
    let output = match adapter.execute("ss", &["-H", "-ltnup"], Duration::from_secs(3)) {
        Ok(output) => output,
        Err(error) => {
            return incomplete(
                "network.listeners",
                "Listening network sockets",
                tool,
                format_runner_error(error),
                "Install iproute2 and retry the listener scan.",
            );
        }
    };
    let lines = safe_lines(&output.stdout);
    if output.status != Some(0) {
        return incomplete(
            "network.listeners",
            "Listening network sockets",
            tool,
            "ss could not enumerate listening sockets",
            "Retry with readable socket metadata.",
        );
    }
    let mut evidence = Vec::new();
    let mut attribution_missing = false;
    for line in lines.iter().take(16) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let Some(local) = fields.get(3) {
            evidence.push(format!("listening: {}", sanitize_socket(local)));
        }
        if !line.contains("users:(") {
            attribution_missing = true;
        }
    }
    if evidence.is_empty() {
        evidence.push("No TCP listeners were reported".to_owned());
    }
    let mut limitations = Vec::new();
    if attribution_missing {
        limitations.push(
            "process attribution is incomplete because socket ownership was not readable"
                .to_owned(),
        );
    }
    result("network.listeners", "Listening network sockets", CheckState::Informational, evidence, limitations, Some("Review listeners against your expected services; ports 22 and 53317 are common Omarchy defaults.".to_owned()), Some(tool))
}

fn kernel_restart<A: CommandAdapter>(adapter: &A, host: &HostProfile) -> CheckResult {
    let tool = adapter.describe("pacman");
    let output = match adapter.execute("pacman", &["-Q"], Duration::from_secs(5)) {
        Ok(output) => output,
        Err(error) => {
            return incomplete(
                "kernel.restart",
                "Kernel restart state",
                tool,
                format_runner_error(error),
                "Install pacman or retry with package-query access.",
            );
        }
    };
    let current = host.kernel.clone().unwrap_or_default();
    let installed = safe_lines(&output.stdout)
        .into_iter()
        .filter(|line| {
            line.starts_with("linux ")
                || line.starts_with("linux-zen ")
                || line.starts_with("linux-lts ")
        })
        .collect::<Vec<_>>();
    if installed.is_empty() || current.is_empty() {
        return incomplete(
            "kernel.restart",
            "Kernel restart state",
            tool,
            "running or installed kernel information was incomplete",
            "Retry after package metadata is readable.",
        );
    }
    let running_matches_installed = installed.iter().any(|line| {
        let mut fields = line.split_whitespace();
        let _package = fields.next();
        let Some(version) = fields.next() else {
            return false;
        };
        let normalized_version = version.replace(".arch", "-arch");
        current == version
            || current == normalized_version
            || current.starts_with(&format!("{version}-"))
            || current.starts_with(&format!("{normalized_version}-"))
    });
    let state = if running_matches_installed {
        CheckState::Pass
    } else {
        CheckState::Attention
    };
    let mut evidence = vec![
        format!("running kernel: {current}"),
        format!("installed kernel packages: {}", installed.len()),
    ];
    if !running_matches_installed {
        evidence.push(
            "running kernel does not match an installed kernel package; a restart may be pending"
                .to_owned(),
        );
    }
    result(
        "kernel.restart",
        "Kernel restart state",
        state,
        evidence,
        Vec::new(),
        Some("Restart after a kernel update when convenient.".to_owned()),
        Some(tool),
    )
}

fn foreign_packages<A: CommandAdapter>(adapter: &A) -> CheckResult {
    let tool = adapter.describe("pacman");
    let output = match adapter.execute("pacman", &["-Qm"], Duration::from_secs(5)) {
        Ok(output) => output,
        Err(error) => {
            return incomplete(
                "packages.foreign",
                "Foreign package inventory",
                tool,
                format_runner_error(error),
                "Retry with pacman query access.",
            );
        }
    };
    if output.status != Some(0) {
        return incomplete(
            "packages.foreign",
            "Foreign package inventory",
            tool,
            "pacman could not enumerate foreign packages",
            "Retry the package inventory.",
        );
    }
    let lines = safe_lines(&output.stdout);
    result(
        "packages.foreign",
        "Foreign package inventory",
        CheckState::Informational,
        vec![format!("{} foreign package(s) reported", lines.len())],
        vec![
            "Foreign packages are inventoried but are not declared unsafe by this check".to_owned(),
        ],
        Some("Review foreign packages when investigating a vulnerability.".to_owned()),
        Some(tool),
    )
}

fn keyring() -> CheckResult {
    let path = Path::new("/etc/pacman.d/gnupg");
    let exists = path.is_dir();
    result(
        "packages.keyring",
        "Pacman keyring state",
        if exists {
            CheckState::Pass
        } else {
            CheckState::Incomplete
        },
        vec![if exists {
            "pacman keyring directory is present".to_owned()
        } else {
            "pacman keyring directory is unavailable".to_owned()
        }],
        Vec::new(),
        Some("Initialize or refresh the supported pacman keyring.".to_owned()),
        None,
    )
}

fn persistence() -> CheckResult {
    let mut found = Vec::new();
    for path in [
        PathBuf::from("/etc/systemd/system"),
        PathBuf::from("/etc/cron.d"),
        env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".config/autostart"),
        env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".config/systemd/user"),
    ] {
        if let Ok(entries) = fs::read_dir(&path) {
            let count = entries
                .flatten()
                .take(MAX_EVIDENCE_ITEMS.saturating_add(1))
                .count();
            if count > 0 {
                let count_display = if count > MAX_EVIDENCE_ITEMS {
                    format!("at least {MAX_EVIDENCE_ITEMS}")
                } else {
                    count.to_string()
                };
                found.push(format!(
                    "{}: {count_display} entry(s)",
                    redact_path(&path.display().to_string())
                ));
            }
        }
    }
    result(
        "persistence.selected",
        "Selected persistence surfaces",
        CheckState::Informational,
        if found.is_empty() {
            vec!["No entries were found in the selected system persistence directories".to_owned()]
        } else {
            found
        },
        Vec::new(),
        Some("Review unexpected persistence entries before accepting a baseline.".to_owned()),
        None,
    )
}

fn path_integrity() -> CheckResult {
    let mut writable = Vec::new();
    for entry in env::var_os("PATH")
        .unwrap_or_default()
        .to_string_lossy()
        .split(':')
        .filter(|entry| !entry.is_empty())
    {
        let path = Path::new(entry);
        #[cfg(unix)]
        if fs::metadata(path).ok().is_some_and(|metadata| {
            use std::os::unix::fs::PermissionsExt;
            metadata.is_dir() && metadata.permissions().mode() & 0o002 != 0
        }) {
            writable.push(entry.to_owned());
        }
    }
    if writable.is_empty() {
        result(
            "execution.path",
            "Executable search path integrity",
            CheckState::Pass,
            vec!["no world-writable PATH entry was observed".to_owned()],
            Vec::new(),
            Some(
                "Keep executable search directories owned and non-writable by other users."
                    .to_owned(),
            ),
            None,
        )
    } else {
        result(
            "execution.path",
            "Executable search path integrity",
            CheckState::Regression,
            writable
                .into_iter()
                .map(|path| format!("world-writable PATH entry: {path}"))
                .collect(),
            vec!["a shadowed posture tool could produce a false observation; posture tools themselves use fixed absolute paths".to_owned()],
            Some("Remove world-writable entries from PATH and rerun the posture scan.".to_owned()),
            None,
        )
    }
}

fn secure_boot<A: CommandAdapter>(adapter: &A) -> CheckResult {
    let tool = adapter.describe("bootctl");
    match adapter.execute("bootctl", &["is-secure-boot-enabled"], Duration::from_secs(2)) {
        Ok(output) if output.status == Some(0) => result("boot.secure_boot", "Secure Boot state", CheckState::Informational, vec!["Secure Boot is enabled".to_owned()], Vec::new(), Some("Secure Boot state is reported for context and is not graded.".to_owned()), Some(tool)),
        Ok(_) => result("boot.secure_boot", "Secure Boot state", CheckState::Informational, vec!["Secure Boot is disabled or unavailable; this is informational on a normal Omarchy installation".to_owned()], Vec::new(), Some("Secure Boot state is reported for context and is not graded.".to_owned()), Some(tool)),
        Err(_) => result("boot.secure_boot", "Secure Boot state", CheckState::NotApplicable, vec!["bootctl is unavailable".to_owned()], vec!["optional firmware evidence was not available".to_owned()], Some("Use bootctl or firmware state when diagnosing boot policy.".to_owned()), Some(tool)),
    }
}

fn ssh_configuration<A: CommandAdapter>(adapter: &A) -> CheckResult {
    let tool = adapter.describe("systemctl");
    match adapter.execute(
        "systemctl",
        &["is-active", "sshd.service"],
        Duration::from_secs(2),
    ) {
        Ok(output) if output.status == Some(0) => {
            let config_path = Path::new("/etc/ssh/sshd_config");
            let config = match read_text_capped(config_path, MAX_METADATA_BYTES) {
                Ok(config) => config,
                Err(_) => {
                    return incomplete(
                        "ssh.configuration",
                        "SSH daemon configuration",
                        tool,
                        "sshd is active but its bounded configuration file was unavailable",
                        "Review /etc/ssh/sshd_config with the supported SSH configuration tools.",
                    );
                }
            };
            let mut directives = BTreeMap::new();
            for line in config.lines() {
                let line = line.split('#').next().unwrap_or_default().trim();
                let mut fields = line.split_whitespace();
                let Some(name) = fields.next() else {
                    continue;
                };
                if matches!(
                    name.to_ascii_lowercase().as_str(),
                    "permitrootlogin" | "passwordauthentication" | "pubkeyauthentication"
                ) && let Some(value) = fields.next()
                {
                    directives.insert(name.to_ascii_lowercase(), value.to_owned());
                }
            }
            let value = |name: &str| {
                directives
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| "default or included configuration".to_owned())
            };
            result(
                "ssh.configuration",
                "SSH daemon configuration",
                CheckState::Informational,
                vec![
                    "sshd is active; bounded configuration review is applicable".to_owned(),
                    format!("PermitRootLogin: {}", value("permitrootlogin")),
                    format!("PasswordAuthentication: {}", value("passwordauthentication")),
                    format!("PubkeyAuthentication: {}", value("pubkeyauthentication")),
                ],
                vec![
                    "Include directives and effective Match blocks are not expanded by this read-only check".to_owned(),
                ],
                Some("Review sshd configuration and key authentication policy.".to_owned()),
                Some(tool),
            )
        }
        Ok(_) => result(
            "ssh.configuration",
            "SSH daemon configuration",
            CheckState::NotApplicable,
            vec!["sshd is not active".to_owned()],
            Vec::new(),
            Some("Enable this check when an SSH service is intentionally enabled.".to_owned()),
            Some(tool),
        ),
        Err(_) => result(
            "ssh.configuration",
            "SSH daemon configuration",
            CheckState::NotApplicable,
            vec!["sshd service state is unavailable".to_owned()],
            vec!["SSH was not confirmed active".to_owned()],
            Some("Review SSH configuration if sshd is enabled.".to_owned()),
            Some(tool),
        ),
    }
}

fn package_integrity<A: CommandAdapter>(adapter: &A) -> CheckResult {
    let tool = adapter.describe("pacman");
    if !tool.available {
        return result(
            "packages.integrity",
            "Pacman package integrity metadata",
            CheckState::NotApplicable,
            vec![
                "Scheduled pacman -Qkk integrity checks are not enabled in this profile".to_owned(),
            ],
            Vec::new(),
            Some(
                "Enable the weekly integrity profile when support evidence requires it.".to_owned(),
            ),
            Some(tool),
        );
    }
    result(
        "packages.integrity",
        "Pacman package integrity metadata",
        CheckState::NotApplicable,
        vec![
            "Integrity verification is scheduled separately from the quick posture scan".to_owned(),
        ],
        Vec::new(),
        Some("Use the weekly integrity profile for pacman -Qkk metadata.".to_owned()),
        Some(tool),
    )
}

fn post_update_hook() -> CheckResult {
    match read_hook_stamp() {
        Some(stamp) => result("updates.post_update_hook", "Last observed post-update hook", CheckState::Informational, vec![format!("last observed post-update hook: {stamp}")], vec!["This timestamp records reaching the Omarchy post-update hook; later update steps may still fail".to_owned()], Some("Use `omarchy update` for the complete supported workflow.".to_owned()), None),
        None => result("updates.post_update_hook", "Last observed post-update hook", CheckState::Informational, vec!["No verified OmaSafe post-update hook observation is available".to_owned()], vec!["missing or unverified hook stamp is reported as unknown".to_owned()], Some("Run `omasafe-cli posture hook install` before the next supported `omarchy update`.".to_owned()), None),
    }
}

fn read_hook_stamp() -> Option<String> {
    let path = production_stamp_path();
    let metadata = fs::metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > 128 {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return None;
        }
    }
    let contents = fs::read_to_string(path).ok()?;
    let value = contents.trim();
    (!value.is_empty() && value.chars().all(|c| c.is_ascii_digit())).then(|| value.to_owned())
}

/// Absolute path of the OmaSafe-owned observation stamp.
pub fn hook_stamp_path() -> PathBuf {
    production_stamp_path()
}

pub fn hook_install_path() -> PathBuf {
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(".config")
        })
        .join("omarchy/hooks/post-update.d")
        .join(POST_UPDATE_HOOK_NAME)
}

/// Installs only the OmaSafe hook file. It does not invoke Omarchy hooks or
/// update commands; the Omarchy hook dispatcher discovers this exact file.
pub fn install_post_update_hook() -> Result<PathBuf, PostureError> {
    let path = hook_install_path();
    let stamp = production_stamp_path();
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "hook has no parent"))?;
    fs::create_dir_all(parent)?;
    let script = hook_script(&stamp);
    atomic_replace(&path, script.as_bytes(), 0o755)?;
    Ok(path)
}

/// Directly exercises the installed OmaSafe hook with an isolated stamp. No
/// user hook dispatcher is called and the production observation cannot move.
pub fn self_test_post_update_hook() -> Result<String, PostureError> {
    let path = hook_install_path();
    let script = fs::read_to_string(&path)?;
    if script != hook_script(&production_stamp_path()) {
        return Err(PostureError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "installed post-update hook does not match the OmaSafe script",
        )));
    }
    let test_root = env::temp_dir().join(format!(
        "omasafe-post-update-self-test-{}",
        std::process::id()
    ));
    fs::create_dir_all(&test_root)?;
    let test_stamp = test_root.join("stamp");
    let production_before = fs::read_to_string(production_stamp_path()).ok();
    let mut command = Command::new("/bin/sh");
    command.arg(&path);
    command.env_clear();
    command.env("LANG", "C");
    command.env("LC_ALL", "C");
    command.env("PATH", "/usr/bin:/bin");
    command.env("OMASAFE_POST_UPDATE_STAMP", &test_stamp);
    command.env("OMASAFE_POST_UPDATE_SELF_TEST", "1");
    command.current_dir("/");
    let output = run_bounded(&mut command, Duration::from_secs(3))
        .map_err(PostureError::Io)?
        .ok_or_else(|| {
            PostureError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "post-update hook self-test timed out",
            ))
        })?;
    let test_value = fs::read_to_string(&test_stamp).ok();
    let _ = fs::remove_dir_all(&test_root);
    if output.truncated || !output.status.success() {
        return Err(PostureError::Io(io::Error::other(
            "post-update hook self-test failed",
        )));
    }
    if fs::read_to_string(production_stamp_path()).ok() != production_before {
        return Err(PostureError::Io(io::Error::other(
            "post-update self-test changed the production stamp",
        )));
    }
    if !test_value.as_deref().is_some_and(|value| {
        value.trim().chars().all(|c| c.is_ascii_digit()) && !value.trim().is_empty()
    }) {
        return Err(PostureError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "post-update hook self-test did not create a valid isolated stamp",
        )));
    }
    Ok("isolated post-update hook self-test passed".to_owned())
}

pub fn uninstall_post_update_hook() -> Result<bool, PostureError> {
    let path = hook_install_path();
    let script = match fs::read_to_string(&path) {
        Ok(script) => script,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if script != hook_script(&production_stamp_path()) {
        return Err(PostureError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "refusing to remove a hook that is not the OmaSafe-owned script",
        )));
    }
    fs::remove_file(path)?;
    Ok(true)
}

fn production_stamp_path() -> PathBuf {
    env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(".local/state")
        })
        .join("omasafe/post-update.stamp")
}

fn hook_script(stamp: &Path) -> String {
    let stamp = shell_quote(stamp.to_string_lossy().as_ref());
    format!(
        "#!/bin/sh\nset -eu\nproduction_stamp={stamp}\nif [ \"${{OMASAFE_POST_UPDATE_SELF_TEST:-0}}\" = 1 ]; then\n  stamp=\"${{OMASAFE_POST_UPDATE_STAMP:?missing isolated self-test stamp}}\"\nelse\n  stamp=\"$production_stamp\"\nfi\ndir=${{stamp%/*}}\nmkdir -p -- \"$dir\"\ntmp=\"$dir/.omasafe-post-update.$$\"\ntrap 'rm -f -- \"$tmp\"' EXIT\n/bin/date +%s >\"$tmp\"\nchmod 600 \"$tmp\"\nmv -f -- \"$tmp\" \"$stamp\"\ntrap - EXIT\n"
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn summarize_coverage(checks: &[CheckResult]) -> CoverageSummary {
    let mut summary = CoverageSummary::default();
    for check in checks {
        match check.state {
            CheckState::Incomplete => summary.incomplete += 1,
            CheckState::Error => summary.errors += 1,
            CheckState::NotApplicable => summary.not_applicable += 1,
            _ => summary.complete += 1,
        }
        summary
            .limitations
            .extend(check.limitations.iter().cloned());
    }
    summary.limitations.sort();
    summary.limitations.dedup();
    summary
}

fn result(
    id: &str,
    title: &str,
    state: CheckState,
    evidence: Vec<String>,
    limitations: Vec<String>,
    next_step: Option<String>,
    tool: Option<ToolObservation>,
) -> CheckResult {
    let mut tool = tool;
    if let Some(tool) = tool.as_mut()
        && let Some(path) = tool.path.as_mut()
    {
        *path = redact_path(path);
    }
    CheckResult {
        id: id.to_owned(),
        title: title.to_owned(),
        state,
        evidence: bound_strings(evidence),
        observed_at: now(),
        dependencies: tool.iter().map(|t| t.name.clone()).collect(),
        limitations: bound_strings(limitations),
        next_step,
        tool,
    }
}

fn incomplete(
    id: &str,
    title: &str,
    tool: ToolObservation,
    limitation: impl Into<String>,
    next_step: &str,
) -> CheckResult {
    result(
        id,
        title,
        CheckState::Incomplete,
        Vec::new(),
        vec![limitation.into()],
        Some(next_step.to_owned()),
        Some(tool),
    )
}
fn first_reason(check: &CheckResult) -> String {
    check
        .limitations
        .first()
        .cloned()
        .unwrap_or_else(|| "coverage became unavailable".to_owned())
}
fn format_runner_error(error: RunnerError) -> String {
    match error {
        RunnerError::Unavailable(tool) => format!("required tool {tool} was unavailable"),
        RunnerError::Io(_) => "required tool could not be executed".to_owned(),
        RunnerError::Truncated => "tool output was truncated".to_owned(),
    }
}

fn bound_strings(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .take(MAX_EVIDENCE_ITEMS)
        .map(|value| value.chars().take(MAX_EVIDENCE_BYTES).collect())
        .collect()
}

fn safe_lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(sanitized_text)
        .take(MAX_EVIDENCE_ITEMS)
        .collect()
}

fn read_text_capped(path: &Path, max_bytes: usize) -> io::Result<String> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > max_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "metadata file exceeds the bounded posture limit",
        ));
    }
    let bytes = fs::read(path)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "metadata file exceeds the bounded posture limit",
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "metadata file is not valid UTF-8",
        )
    })
}

fn sanitized_line(bytes: &[u8]) -> Option<String> {
    safe_lines(bytes).into_iter().next()
}
fn sanitized_text(value: &str) -> Option<String> {
    let text: String = value
        .chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .take(MAX_EVIDENCE_BYTES)
        .collect();
    (!text.trim().is_empty()).then(|| text.trim().to_owned())
}

fn redact_path(value: &str) -> String {
    let home = env::var_os("HOME").map(PathBuf::from);
    if let Some(home) = home {
        let home = home.to_string_lossy();
        if value == home {
            return "$HOME".to_owned();
        }
        if let Some(rest) = value.strip_prefix(&format!("{home}/")) {
            return format!("$HOME/{rest}");
        }
    }
    value.to_owned()
}
fn sanitize_socket(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '[' | ']' | '/' | '%'))
        .take(128)
        .collect()
}

fn json_root_has_crypt(value: &serde_json::Value) -> Option<bool> {
    value
        .get("blockdevices")
        .and_then(serde_json::Value::as_array)
        .and_then(|devices| {
            devices
                .iter()
                .find_map(|device| walk_block_device(device, false))
        })
}

fn walk_block_device(value: &serde_json::Value, inherited_crypt: bool) -> Option<bool> {
    let object = value.as_object()?;
    let current_crypt = inherited_crypt
        || object
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| kind.eq_ignore_ascii_case("crypt"));
    let root_mount = object
        .get("mountpoints")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|mountpoints| mountpoints.iter().any(|mount| mount.as_str() == Some("/")))
        || object.get("mountpoint").and_then(serde_json::Value::as_str) == Some("/");
    if root_mount {
        return Some(current_crypt);
    }
    object
        .get("children")
        .and_then(serde_json::Value::as_array)
        .and_then(|children| {
            children
                .iter()
                .find_map(|child| walk_block_device(child, current_crypt))
        })
}

fn executable_file(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn safe_path_chain(path: &Path) -> bool {
    let mut current = path.parent();
    while let Some(dir) = current {
        let Ok(meta) = fs::metadata(dir) else {
            return false;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o002 != 0 {
                return false;
            }
        }
        current = dir.parent();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(status: i32, text: &str) -> CommandOutput {
        CommandOutput {
            status: Some(status),
            stdout: text.as_bytes().to_vec(),
            truncated: false,
        }
    }

    #[test]
    fn ambiguous_checkupdates_exit_two_is_incomplete() {
        let adapter = FixtureCommandAdapter::default().response("checkupdates", output(2, ""));
        let report = scan_with_adapter(&adapter);
        let check = report
            .checks
            .iter()
            .find(|check| check.id == "updates.repository")
            .unwrap();
        assert_eq!(check.state, CheckState::Incomplete);
        assert!(check.limitations[0].contains("ambiguous"));
    }

    #[test]
    fn exit_two_requires_and_uses_independent_package_query() {
        let adapter = FixtureCommandAdapter::default()
            .response("checkupdates", output(2, ""))
            .response_args("pacman", &["-Qu"], output(0, ""));
        let report = scan_with_adapter(&adapter);
        let check = report
            .checks
            .iter()
            .find(|check| check.id == "updates.repository")
            .expect("repository check");
        assert_eq!(check.state, CheckState::Pass);
        assert!(check.evidence[0].contains("independent package query"));
    }

    #[test]
    fn independent_package_query_can_surface_updates_after_exit_two() {
        let adapter = FixtureCommandAdapter::default()
            .response("checkupdates", output(2, ""))
            .response_args("pacman", &["-Qu"], output(0, "openssl 3.0.0-1"));
        let report = scan_with_adapter(&adapter);
        let check = report
            .checks
            .iter()
            .find(|check| check.id == "updates.repository")
            .expect("repository check");
        assert_eq!(check.state, CheckState::Regression);
        assert!(
            check
                .evidence
                .iter()
                .any(|line| line.starts_with("openssl"))
        );
    }

    #[test]
    fn kernel_mismatch_is_attention_until_restart() {
        let adapter = FixtureCommandAdapter::default().response_args(
            "pacman",
            &["-Q"],
            output(0, "linux 6.12.1.arch1-1"),
        );
        let host = HostProfile {
            kernel: Some("6.11.9-arch1-1".to_owned()),
            ..HostProfile::default()
        };
        let check = kernel_restart(&adapter, &host);
        assert_eq!(check.state, CheckState::Attention);
        assert!(
            check
                .evidence
                .iter()
                .any(|line| line.contains("does not match"))
        );
    }

    #[test]
    fn stderr_never_enters_the_report_contract() {
        let adapter = FixtureCommandAdapter::default()
            .response("checkupdates", output(1, "secret stderr is never captured"));
        let report = scan_with_adapter(&adapter);
        let bytes = serde_json::to_vec(&report).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("stderr"));
    }

    #[test]
    fn root_encryption_follows_the_root_mount_ancestry() {
        let lsblk = r#"{"blockdevices":[{"type":"disk","children":[{"type":"crypt","children":[{"type":"lvm","mountpoints":["/"]}]}]}]}"#;
        let adapter = FixtureCommandAdapter::default().response("lsblk", output(0, lsblk));
        let report = scan_with_adapter(&adapter);
        let check = report
            .checks
            .iter()
            .find(|check| check.id == "encryption.root_luks")
            .unwrap();
        assert_eq!(check.state, CheckState::Pass);

        let unrelated = r#"{"blockdevices":[{"type":"crypt","mountpoints":["/mnt/backup"]},{"type":"disk","mountpoints":["/"]}]}"#;
        let adapter = FixtureCommandAdapter::default().response("lsblk", output(0, unrelated));
        let report = scan_with_adapter(&adapter);
        let check = report
            .checks
            .iter()
            .find(|check| check.id == "encryption.root_luks")
            .unwrap();
        assert_eq!(check.state, CheckState::Attention);
    }

    #[test]
    fn coverage_loss_notifies_once_and_recurrence_after_recovery_notifies_again() {
        let mut state = PostureState::default();
        let mut report = PostureReport {
            schema: POSTURE_SCHEMA_VERSION.into(),
            check_catalog_version: 1,
            generated_at: "1".into(),
            host: HostProfile::default(),
            tools: vec![],
            checks: vec![incomplete(
                "x",
                "X",
                ToolObservation {
                    name: "x".into(),
                    path: None,
                    version: None,
                    available: false,
                },
                "missing",
                "retry",
            )],
            coverage: CoverageSummary::default(),
            last_observed_post_update_hook: None,
        };
        report.checks[0].state = CheckState::Pass;
        assert!(update_state(&mut state, &report).is_empty());
        report.checks[0].state = CheckState::Incomplete;
        report.generated_at = "2".into();
        assert_eq!(update_state(&mut state, &report).len(), 1);
        report.generated_at = "3".into();
        assert!(update_state(&mut state, &report).is_empty());
        report.checks[0].state = CheckState::Pass;
        report.generated_at = "4".into();
        assert!(update_state(&mut state, &report).is_empty());
        report.checks[0].state = CheckState::Error;
        report.generated_at = "5".into();
        assert_eq!(update_state(&mut state, &report).len(), 1);
    }

    #[test]
    fn regression_notification_deduplicates_and_reopens_after_recovery() {
        let mut state = PostureState::default();
        let mut report = PostureReport {
            schema: POSTURE_SCHEMA_VERSION.into(),
            check_catalog_version: 1,
            generated_at: "1".into(),
            host: HostProfile::default(),
            tools: vec![],
            checks: vec![result(
                "updates.repository",
                "Repository updates",
                CheckState::Pass,
                vec!["clean".into()],
                vec![],
                None,
                None,
            )],
            coverage: CoverageSummary::default(),
            last_observed_post_update_hook: None,
        };
        assert!(update_state(&mut state, &report).is_empty());
        report.generated_at = "2".into();
        report.checks[0].state = CheckState::Regression;
        assert_eq!(update_state(&mut state, &report).len(), 1);
        report.generated_at = "3".into();
        assert!(update_state(&mut state, &report).is_empty());
        report.generated_at = "4".into();
        report.checks[0].state = CheckState::Pass;
        assert!(update_state(&mut state, &report).is_empty());
        report.generated_at = "5".into();
        report.checks[0].state = CheckState::Regression;
        assert_eq!(update_state(&mut state, &report).len(), 1);
    }
}
