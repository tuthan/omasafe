//! Host-scoped posture checks for OmaSafe.
//!
//! The posture engine is deliberately independent from the plugin report
//! family. It consumes bounded command adapters, keeps command stderr out of
//! reports, and makes inability to observe a property explicit.

use omasafe_core::bounds::{MAX_METADATA_BYTES, run_bounded};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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
    /// Stable position in `check_catalog()`. The catalog order is deliberate and not
    /// alphabetical, so without this a consumer can only sort by id and the reading
    /// order the catalog encodes is lost at the boundary (v0.3.1 C3).
    #[serde(default)]
    pub catalog_index: Option<u64>,
    /// The state this check held in the immediately preceding completed report.
    ///
    /// `None` on the FIRST observation of a check — not the current state, and never
    /// omitted-as-equal. It is annotated from `PostureState::prior_states` after
    /// `update_state()` has run; see the warning on that map (v0.3.1 C1).
    #[serde(default)]
    pub previous_state: Option<CheckState>,
    /// When this check's current coverage-loss episode began, RFC-3339. `None` when the
    /// check is not in a gap (v0.3.1 C2).
    #[serde(default)]
    pub gap_open_since: Option<String>,
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
    /// The states of the report that produced this file — i.e. the CURRENT states, not
    /// the previous ones, despite the name. It exists to suppress duplicate coverage
    /// notifications and must never be exported as `previous_state`; doing so would
    /// make `previous_state == state` for every check and silently render zero change
    /// marks forever. Use `prior_states` for that.
    #[serde(default)]
    pub previous_states: BTreeMap<String, CheckState>,
    /// The state each check held in the immediately PRECEDING completed report — the
    /// value `update_state()` displaces out of `previous_states` and used to throw
    /// away. A check absent from this map has never been observed twice, and exports
    /// `previous_state: null` rather than a value equal to its current state.
    ///
    /// `serde(default)` is the whole migration: an older state file loads with an empty
    /// map and the first scan after the upgrade populates it.
    #[serde(default)]
    pub prior_states: BTreeMap<String, CheckState>,
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
            prior_states: BTreeMap::new(),
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
    pub stderr_nonempty: bool,
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
    fn execute_with_env(
        &self,
        tool: &str,
        args: &[&str],
        budget: Duration,
        env: &[(&str, &str)],
    ) -> Result<CommandOutput, RunnerError> {
        let _ = env;
        self.execute(tool, args, budget)
    }
    fn describe(&self, tool: &str) -> ToolObservation;
}

#[derive(Debug, Clone)]
pub struct SystemCommandAdapter {}

impl SystemCommandAdapter {
    pub fn from_environment() -> Self {
        // Production scans resolve only from fixed, root-owned system paths.
        // FixtureCommandAdapter is the test boundary; inherited environment
        // variables must not be able to shadow posture tools.
        Self {}
    }

    fn resolve(&self, tool: &str) -> Option<PathBuf> {
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
        self.execute_with_env(tool, args, budget, &[])
    }

    fn execute_with_env(
        &self,
        tool: &str,
        args: &[&str],
        budget: Duration,
        extra_env: &[(&str, &str)],
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
        for (key, value) in extra_env {
            command.env(key, value);
        }
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
            stderr_nonempty: !output.stderr.is_empty(),
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

    fn execute_with_env(
        &self,
        tool: &str,
        args: &[&str],
        budget: Duration,
        env: &[(&str, &str)],
    ) -> Result<CommandOutput, RunnerError> {
        let output = self.execute(tool, args, budget)?;
        if tool == "checkupdates"
            && matches!(output.status, Some(0..=2))
            && !output.truncated
            && let Some((_, tmpdir)) = env.iter().find(|(key, _)| *key == "TMPDIR")
        {
            let uid = unsafe { libc::geteuid() };
            let sync = Path::new(tmpdir)
                .join(format!("checkup-db-{uid}"))
                .join("sync");
            fs::create_dir_all(&sync).map_err(|error| RunnerError::Io(error.to_string()))?;
            fs::write(sync.join("core.db"), b"fixture sync database")
                .map_err(|error| RunnerError::Io(error.to_string()))?;
        }
        Ok(output)
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

/// Coerce a stored timestamp to RFC-3339.
///
/// `CoverageEpisode::started_at` is a `String`, so the type system never caught that
/// some episodes were written as bare unix seconds (`"1788872597"`) while `last_seen_at`
/// beside them was RFC-3339. New episodes take `report.generated_at` and are already
/// correct; this migrates the ones that are not, so every reader sees one shape and the
/// state file self-heals on its next write.
fn normalize_timestamp(value: &str) -> String {
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        if let Ok(seconds) = value.parse::<i64>() {
            return format_timestamp(seconds);
        }
    }
    value.to_owned()
}

/// Attach the fields that can only be known once `update_state` has run: the state each
/// check held in the PRECEDING report, and when an open coverage gap began.
///
/// Call this after `update_state` and before the report is persisted, so `posture
/// export` can return the stored report without consulting the state file at all.
pub fn annotate_report(report: &mut PostureReport, state: &PostureState) {
    for check in &mut report.checks {
        // Absent from `prior_states` means never observed twice, which is `null` — a
        // different claim from "unchanged".
        check.previous_state = state.prior_states.get(&check.id).copied();
        check.gap_open_since = if check.state.is_coverage_loss() {
            state
                .coverage_episodes
                .get(&check.id)
                .map(|episode| normalize_timestamp(&episode.started_at))
        } else {
            None
        };
    }
}

pub fn now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    format_timestamp(seconds)
}

fn format_timestamp(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_part = (5 * doy + 2) / 153;
    let day = doy - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

pub fn timestamp_seconds(value: &str) -> Option<i64> {
    let value = value.strip_suffix('Z')?;
    let (date, time) = value.split_once('T')?;
    let mut date_parts = date.split('-');
    let year = date_parts.next()?.parse::<i64>().ok()?;
    let month = date_parts.next()?.parse::<i64>().ok()?;
    let day = date_parts.next()?.parse::<i64>().ok()?;
    if date_parts.next().is_some() {
        return None;
    }
    let mut time_parts = time.split(':');
    let hour = time_parts.next()?.parse::<i64>().ok()?;
    let minute = time_parts.next()?.parse::<i64>().ok()?;
    let second = time_parts.next()?.parse::<i64>().ok()?;
    if time_parts.next().is_some()
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let month_from_march = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
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
    // The catalog order is deliberate and not alphabetical. The emitted array stays
    // sorted by id — that ordering is a published shape — so the position travels as a
    // field instead, and a consumer that wants the catalog's reading order has it.
    let catalog_index: BTreeMap<&str, u64> = check_catalog()
        .iter()
        .enumerate()
        .map(|(index, (id, _))| (*id, index as u64))
        .collect();
    let mut checks = Vec::new();
    checks.push(check_context(&host));
    let (repository_check, repository_inventory) =
        checkupdates_with_inventory(adapter, "updates.repository", "Repository package updates");
    checks.push(repository_check.clone());
    checks.push(check_omarchy_updates(
        adapter,
        raw_omarchy_path.as_deref(),
        &repository_check,
        &repository_inventory,
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
    checks.retain(|check| catalog_index.contains_key(check.id.as_str()));
    checks.sort_by(|a, b| a.id.cmp(&b.id));
    for check in &mut checks {
        check.catalog_index = catalog_index.get(check.id.as_str()).copied();
    }
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
        // Keep the value the insert displaced. It is the state from the immediately
        // preceding report, it is the only place that value exists, and until v0.3.1 it
        // was used for notification suppression and then dropped on the floor.
        match prior {
            Some(prior) => {
                state.prior_states.insert(check.id.clone(), prior);
            }
            // First observation: `previous_state` must be null, which is a different
            // claim from "unchanged".
            None => {
                state.prior_states.remove(&check.id);
            }
        }
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
        } else {
            // Observation RECOVERED, and the episode is over whatever state it
            // recovered into. `Attention` and `Regression` are observations that
            // succeeded and reported something — they are not coverage gaps.
            //
            // This used to clear the episode only on the third branch (pass,
            // informational, not applicable), so `Incomplete → Attention → Incomplete`
            // left the first episode in place and `or_insert_with` above then kept its
            // original `started_at`. That was invisible while episodes were internal;
            // exporting `gap_open_since` made it a wrong date on screen. It also
            // carried `notified: true` across the recovery, so the REOPENED gap was
            // silently not notified.
            state.coverage_episodes.remove(&check.id);
            if matches!(check.state, CheckState::Regression | CheckState::Attention) {
                if prior.is_some()
                    && state.last_notified_states.get(&check.id) != Some(&check.state)
                {
                    state
                        .last_notified_states
                        .insert(check.id.clone(), check.state);
                    notifications.push(PostureNotification {
                        key: format!("state:{}:{:?}", check.id, check.state),
                        check_id: check.id.clone(),
                        message: format!("{} requires review", check.title),
                    });
                }
            } else {
                state.last_notified_states.remove(&check.id);
            }
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
    let mut state = state;
    for episode in state.coverage_episodes.values_mut() {
        episode.started_at = normalize_timestamp(&episode.started_at);
        episode.last_seen_at = normalize_timestamp(&episode.last_seen_at);
    }
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
                    parse_lines(&output.stdout)
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

fn checkupdates_with_inventory<A: CommandAdapter>(
    adapter: &A,
    id: &str,
    title: &str,
) -> (CheckResult, Vec<String>) {
    let tool = adapter.describe("checkupdates");
    let (tmpdir, dbpath) = match private_checkupdates_database() {
        Ok(paths) => paths,
        Err(error) => {
            return (
                incomplete(
                    id,
                    title,
                    tool,
                    format!("private checkupdates database was unavailable: {error}"),
                    "Retry after the OmaSafe temporary directory is writable.",
                ),
                Vec::new(),
            );
        }
    };
    let tmpdir_text = tmpdir.to_string_lossy().to_string();
    let output = match adapter.execute_with_env(
        "checkupdates",
        &["--nocolor"],
        Duration::from_secs(30),
        &[("TMPDIR", tmpdir_text.as_str())],
    ) {
        Ok(output) => output,
        Err(error) => {
            let _ = fs::remove_dir_all(&tmpdir);
            return (
                incomplete(
                    id,
                    title,
                    tool,
                    format_runner_error(error),
                    "Install pacman-contrib and retry the posture scan.",
                ),
                Vec::new(),
            );
        }
    };
    if output.truncated {
        let _ = fs::remove_dir_all(&tmpdir);
        return (
            incomplete(
                id,
                title,
                tool,
                "checkupdates output was truncated".to_owned(),
                "Retry the scan after resolving the command-output limit.",
            ),
            Vec::new(),
        );
    }
    match output.status {
        Some(0) => {
            let lines = parse_lines(&output.stdout);
            let check = if lines.is_empty() {
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
                    // Pending updates are maintenance, not a regression: nothing about
                    // this host got worse, it is behind. `Regression` is reserved for
                    // a defect, and now that `previous_state` carries the comparison
                    // the word has to mean what it says (v0.3.1 D1).
                    CheckState::Attention,
                    lines.clone(),
                    Vec::new(),
                    Some("Run `omarchy update` after reviewing the pending packages.".to_owned()),
                    Some(tool),
                )
            };
            let _ = fs::remove_dir_all(&tmpdir);
            (check, lines)
        }
        Some(1 | 2) if !(output.status == Some(1) && output.stderr_nonempty) => {
            // checkupdates uses exit 1 or 2 for its no-update/ambiguous branch
            // across pacman-contrib releases. Validate the same private DB that
            // checkupdates populated; never query the user's live system DB.
            let dbpath_text = dbpath.to_string_lossy().to_string();
            if !private_database_is_synced(&dbpath) {
                let _ = fs::remove_dir_all(&tmpdir);
                return (
                    incomplete(
                        id,
                        title,
                        tool,
                        "checkupdates did not leave a readable private sync database",
                        "Retry after the private package database has synchronized successfully.",
                    ),
                    Vec::new(),
                );
            }
            let query = adapter.execute(
                "pacman",
                &["-Qu", "--dbpath", dbpath_text.as_str()],
                Duration::from_secs(10),
            );
            let check = match query {
                Ok(query)
                    if !query.truncated && !query.stderr_nonempty && query.status == Some(0) =>
                {
                    let lines = parse_lines(&query.stdout);
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
                            CheckState::Attention,
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
                Ok(query)
                    if !query.truncated
                        && !query.stderr_nonempty
                        && query.status == Some(1)
                        && query.stdout.is_empty() => result(
                        id,
                        title,
                        CheckState::Pass,
                        vec!["the private package database reported no updates".to_owned()],
                        vec![
                            "checkupdates returned its no-update status; pacman -Qu exit 1 with empty output was validated as current"
                                .to_owned(),
                        ],
                        Some("Keep the supported Omarchy update workflow available.".to_owned()),
                        Some(tool),
                    ),
                Ok(_) => incomplete(
                    id,
                    title,
                    tool,
                    "checkupdates returned its no-update status, but the independent package query did not complete",
                    "Retry when the private package database and query tools are available.",
                ),
                Err(error) => incomplete(
                    id,
                    title,
                    tool,
                    format!(
                        "checkupdates returned its no-update status, but the independent package query was unavailable: {}",
                        format_runner_error(error)
                    ),
                    "Retry when the private package database and query tools are available.",
                ),
            };
            let _ = fs::remove_dir_all(&tmpdir);
            (check, Vec::new())
        }
        Some(code) => {
            let _ = fs::remove_dir_all(&tmpdir);
            (
                incomplete(
                    id,
                    title,
                    tool,
                    format!("checkupdates failed with exit status {code}"),
                    "Retry the scan and inspect package-manager availability.",
                ),
                Vec::new(),
            )
        }
        None => {
            let _ = fs::remove_dir_all(&tmpdir);
            (
                incomplete(
                    id,
                    title,
                    tool,
                    "checkupdates did not return an exit status",
                    "Retry the scan.",
                ),
                Vec::new(),
            )
        }
    }
}

fn check_omarchy_updates<A: CommandAdapter>(
    adapter: &A,
    raw_omarchy_path: Option<&Path>,
    repository: &CheckResult,
    repository_inventory: &[String],
) -> CheckResult {
    if raw_omarchy_path == Some(Path::new("/usr/share/omarchy")) {
        // Follows `updates.repository`'s state: when that check moved from `Regression`
        // to `Attention` (v0.3.1 D1) this gate had to move with it, or the branch that
        // reads the validated inventory would never run again.
        if repository.state == CheckState::Attention {
            let updates = repository_inventory
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
                    CheckState::Attention,
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
    let Some(git_dir) = resolve_git_dir(checkout) else {
        return incomplete(
            "updates.omarchy",
            "Omarchy update availability",
            tool,
            "development checkout Git directory was unavailable",
            "Retry after the checkout has readable Git metadata.",
        );
    };
    let config_path = git_dir.join("config");
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
        // A development checkout behind its upstream is behind, not broken (D1).
        CheckState::Attention
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
        if let Ok(value) = read_text_capped(&git_dir.join(reference), MAX_METADATA_BYTES) {
            let value = value.trim();
            if is_hex_commit(value) {
                return Some(value.to_owned());
            }
        }
        let packed = read_text_capped(&git_dir.join("packed-refs"), MAX_METADATA_BYTES).ok()?;
        return packed.lines().find_map(|line| {
            let mut fields = line.split_whitespace();
            let commit = fields.next()?;
            let packed_ref = fields.next()?;
            (packed_ref == reference && is_hex_commit(commit)).then(|| commit.to_owned())
        });
    }
    if is_hex_commit(head) {
        Some(head.to_owned())
    } else {
        let _ = checkout;
        None
    }
}

fn resolve_git_dir(checkout: &Path) -> Option<PathBuf> {
    let entry = checkout.join(".git");
    if entry.is_dir() {
        return Some(entry);
    }
    let pointer = read_text_capped(&entry, MAX_METADATA_BYTES).ok()?;
    let value = pointer.trim().strip_prefix("gitdir:")?.trim();
    let path = PathBuf::from(value);
    Some(if path.is_absolute() {
        path
    } else {
        checkout.join(path)
    })
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
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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
    let lines = parse_lines(&output.stdout);
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
    let nft_config = read_text_capped(Path::new("/etc/nftables.conf"), MAX_METADATA_BYTES).ok();
    let ufw_config = [
        "/etc/ufw/ufw.conf",
        "/etc/ufw/user.rules",
        "/etc/ufw/before.rules",
    ]
    .iter()
    .find_map(|path| read_text_capped(Path::new(path), MAX_METADATA_BYTES).ok());
    if nft_config.is_none() && ufw_config.is_none() {
        return incomplete(
            "firewall.configuration",
            "Firewall configuration",
            if nft.available { nft } else { ufw },
            "No readable nftables or ufw configuration file was found",
            "Review /etc/nftables.conf or /etc/ufw/ with the supported firewall tools.",
        );
    }
    let mut evidence = Vec::new();
    if nft_config.is_some() {
        evidence.push("/etc/nftables.conf is readable".to_owned());
    }
    if ufw_config.is_some() {
        evidence.push("an /etc/ufw configuration file is readable".to_owned());
    }
    result(
        "firewall.configuration",
        "Firewall configuration",
        CheckState::Informational,
        evidence,
        Vec::new(),
        Some("Review the active firewall configuration if listeners change.".to_owned()),
        Some(if nft_config.is_some() { nft } else { ufw }),
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
        Ok(output) if output.status == Some(0) => {
            let text = String::from_utf8_lossy(&output.stdout);
            let has_base_chain = nft_has_base_chain(&text);
            if has_base_chain {
                result(
                    "firewall.effective",
                    "Effective firewall policy",
                    CheckState::Pass,
                    vec![
                        "The runtime nftables policy has a readable base chain and default policy"
                            .to_owned(),
                    ],
                    Vec::new(),
                    Some("Recheck after firewall changes.".to_owned()),
                    Some(tool),
                )
            } else {
                result(
                    "firewall.effective",
                    "Effective firewall policy",
                    CheckState::Attention,
                    vec!["The runtime nftables ruleset was readable but no base chain/default policy was observed".to_owned()],
                    vec!["An empty or non-filtering ruleset does not establish an effective firewall policy".to_owned()],
                    Some("Review nftables base chains and default policies before relying on firewall coverage.".to_owned()),
                    Some(tool),
                )
            }
        }
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
    let lines = parse_lines(&output.stdout);
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
        if let Some(local) = fields.get(4) {
            evidence.push(format!("listening: {}", sanitize_socket(local)));
        }
        if !line.contains("users:(") {
            attribution_missing = true;
        }
    }
    if evidence.is_empty() {
        evidence.push("No listening TCP or UDP sockets were reported".to_owned());
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
    let installed = parse_lines(&output.stdout)
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
    let lines = parse_lines(&output.stdout);
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
    secure_boot_with_efi(adapter, Path::new("/sys/firmware/efi").is_dir())
}

fn secure_boot_with_efi<A: CommandAdapter>(adapter: &A, efi_present: bool) -> CheckResult {
    let tool = adapter.describe("bootctl");
    if !efi_present {
        return result(
            "boot.secure_boot",
            "Secure Boot state",
            CheckState::NotApplicable,
            vec!["EFI firmware interface is not present on this host".to_owned()],
            vec!["Secure Boot state is not observable on a legacy-BIOS host".to_owned()],
            Some("Use firmware settings when diagnosing boot policy.".to_owned()),
            Some(tool),
        );
    }
    match adapter.execute("bootctl", &["status", "--no-pager"], Duration::from_secs(2)) {
        Ok(output) if output.status == Some(0) => {
            let status = String::from_utf8_lossy(&output.stdout)
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(key, _)| key.trim() == "Secure Boot")
                        .map(|(_, value)| value.trim().to_ascii_lowercase())
                });
            let Some(status) = status else {
                return incomplete(
                    "boot.secure_boot",
                    "Secure Boot state",
                    tool,
                    "bootctl status did not include a Secure Boot field",
                    "Retry with firmware status metadata available.",
                );
            };
            let state = if status.contains("enabled") {
                "Secure Boot is enabled"
            } else if status.contains("disabled") {
                "Secure Boot is disabled"
            } else {
                "Secure Boot state is unsupported or unavailable"
            };
            result(
                "boot.secure_boot",
                "Secure Boot state",
                CheckState::Informational,
                vec![state.to_owned()],
                Vec::new(),
                Some("Secure Boot state is reported for context and is not graded.".to_owned()),
                Some(tool),
            )
        }
        Ok(_) => incomplete(
            "boot.secure_boot",
            "Secure Boot state",
            tool,
            "bootctl status was unavailable",
            "Retry with firmware status metadata available.",
        ),
        Err(_) => incomplete(
            "boot.secure_boot",
            "Secure Boot state",
            tool,
            "bootctl was unavailable",
            "Use bootctl or firmware state when diagnosing boot policy.",
        ),
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
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".config/omarchy/hooks/post-update.d")
        .join(POST_UPDATE_HOOK_NAME)
}

fn legacy_hook_install_path() -> Option<PathBuf> {
    let config = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())?;
    let path = config
        .join("omarchy/hooks/post-update.d")
        .join(POST_UPDATE_HOOK_NAME);
    (path != hook_install_path()).then_some(path)
}

fn remove_owned_legacy_hook(stamp: &Path) -> io::Result<bool> {
    let Some(path) = legacy_hook_install_path() else {
        return Ok(false);
    };
    let script = match fs::read_to_string(&path) {
        Ok(script) => script,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if script != hook_script(stamp) {
        return Ok(false);
    }
    fs::remove_file(path)?;
    Ok(true)
}

fn require_omarchy_hook_tree() -> io::Result<()> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    let root = home.join(".config/omarchy");
    if !root.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Omarchy hook tree is absent at {}", root.display()),
        ));
    }
    Ok(())
}

/// Installs only the OmaSafe hook file. It does not invoke Omarchy hooks or
/// update commands; the Omarchy hook dispatcher discovers this exact file.
pub fn install_post_update_hook() -> Result<PathBuf, PostureError> {
    require_omarchy_hook_tree()?;
    let path = hook_install_path();
    let stamp = production_stamp_path();
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "hook has no parent"))?;
    fs::create_dir_all(parent)?;
    let script = hook_script(&stamp);
    atomic_replace(&path, script.as_bytes(), 0o755)?;
    let _ = remove_owned_legacy_hook(&stamp)?;
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
    let stamp = production_stamp_path();
    let mut removed = false;
    match fs::read_to_string(&path) {
        Ok(script) if script == hook_script(&stamp) => {
            fs::remove_file(path)?;
            removed = true;
        }
        Ok(_) => {
            return Err(PostureError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "refusing to remove a hook that is not the OmaSafe-owned script",
            )));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if remove_owned_legacy_hook(&stamp)? {
        removed = true;
    }
    Ok(removed)
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
        // Annotated after the fact: `catalog_index` in `scan_with_adapter`, the other
        // two in `annotate_report` once `update_state` has computed them.
        catalog_index: None,
        previous_state: None,
        gap_open_since: None,
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
    parse_lines(bytes)
        .into_iter()
        .take(MAX_EVIDENCE_ITEMS)
        .collect()
}

fn parse_lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(sanitized_text)
        .collect()
}

fn private_checkupdates_database() -> io::Result<(PathBuf, PathBuf)> {
    let temp_root = env::temp_dir();
    sweep_stale_checkupdates_databases(&temp_root);
    let root = temp_root.join(format!(
        "omasafe-checkupdates-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    }
    let uid = unsafe { libc::geteuid() };
    Ok((root.clone(), root.join(format!("checkup-db-{uid}"))))
}

fn private_database_is_synced(dbpath: &Path) -> bool {
    dbpath.join("sync/core.db").is_file()
}

fn sweep_stale_checkupdates_databases(temp_root: &Path) {
    let Ok(entries) = fs::read_dir(temp_root) else {
        return;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        if !entry
            .file_name()
            .to_string_lossy()
            .starts_with("omasafe-checkupdates-")
        {
            continue;
        }
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        let stale = metadata.is_dir()
            && metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age >= Duration::from_secs(60 * 60));
        if stale {
            let _ = fs::remove_dir_all(path);
        }
    }
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
        .filter(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '[' | ']' | '/' | '%' | '*' | '-')
        })
        .take(128)
        .collect()
}

fn nft_has_base_chain(text: &str) -> bool {
    let mut in_chain = false;
    let mut has_hook = false;
    let mut has_policy = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("chain ") {
            in_chain = true;
            has_hook = false;
            has_policy = false;
        }
        if in_chain {
            has_hook |= line.contains("hook ");
            has_policy |= line.contains("policy ");
            if has_hook && has_policy {
                return true;
            }
            if line == "}" {
                in_chain = false;
            }
        }
    }
    false
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
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        meta.uid() == 0
            && meta.permissions().mode() & 0o022 == 0
            && meta.permissions().mode() & 0o111 != 0
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
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if meta.uid() != 0 || meta.permissions().mode() & 0o022 != 0 {
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
            stderr_nonempty: false,
        }
    }

    fn output_with_stderr(status: i32, text: &str) -> CommandOutput {
        CommandOutput {
            stderr_nonempty: true,
            ..output(status, text)
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
        assert!(check.limitations[0].contains("independent package query"));
    }

    #[test]
    fn exit_two_requires_and_uses_independent_package_query() {
        let adapter = FixtureCommandAdapter::default()
            .response("checkupdates", output(2, ""))
            .response("pacman", output(0, ""));
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
            .response("pacman", output(0, "openssl 3.0.0-1"));
        let report = scan_with_adapter(&adapter);
        let check = report
            .checks
            .iter()
            .find(|check| check.id == "updates.repository")
            .expect("repository check");
        // Pending updates are `Attention`, not `Regression` (v0.3.1 D1).
        assert_eq!(check.state, CheckState::Attention);
        assert!(
            check
                .evidence
                .iter()
                .any(|line| line.starts_with("openssl"))
        );
    }

    #[test]
    fn complete_update_inventory_drives_omarchy_filter_beyond_evidence_cap() {
        let mut packages = (0..40)
            .map(|index| format!("package-{index} 1.0.0-1"))
            .collect::<Vec<_>>();
        packages.push("omarchy 4.0.0-1".to_owned());
        let adapter = FixtureCommandAdapter::default()
            .response("checkupdates", output(0, &packages.join("\n")));
        let (repository, inventory) =
            checkupdates_with_inventory(&adapter, "updates.repository", "Repository updates");
        assert_eq!(inventory.len(), 41);
        assert_eq!(repository.evidence.len(), MAX_EVIDENCE_ITEMS);
        let omarchy = check_omarchy_updates(
            &adapter,
            Some(Path::new("/usr/share/omarchy")),
            &repository,
            &inventory,
        );
        // Also asserts the gate in `check_omarchy_updates` followed the repository
        // check's new state: if it still tested for `Regression` this branch would never
        // run and the evidence below would be empty.
        assert_eq!(omarchy.state, CheckState::Attention);
        assert!(omarchy.evidence.iter().any(|line| line.contains("omarchy")));
    }

    #[test]
    fn checkupdates_exit_one_empty_output_is_validated_empty() {
        let adapter = FixtureCommandAdapter::default()
            .response("checkupdates", output(1, ""))
            .response("pacman", output(1, ""));
        let report = scan_with_adapter(&adapter);
        let check = report
            .checks
            .iter()
            .find(|check| check.id == "updates.repository")
            .unwrap();
        assert_eq!(check.state, CheckState::Pass);
    }

    #[test]
    fn checkupdates_exit_one_with_stderr_is_not_treated_as_empty() {
        let adapter =
            FixtureCommandAdapter::default().response("checkupdates", output_with_stderr(1, ""));
        let report = scan_with_adapter(&adapter);
        let check = report
            .checks
            .iter()
            .find(|check| check.id == "updates.repository")
            .unwrap();
        assert_eq!(check.state, CheckState::Incomplete);
    }

    #[test]
    fn private_query_stderr_is_not_treated_as_current() {
        let adapter = FixtureCommandAdapter::default()
            .response("checkupdates", output(1, ""))
            .response("pacman", output_with_stderr(1, ""));
        let report = scan_with_adapter(&adapter);
        let check = report
            .checks
            .iter()
            .find(|check| check.id == "updates.repository")
            .unwrap();
        assert_eq!(check.state, CheckState::Incomplete);
    }

    #[test]
    fn listeners_retain_local_address_and_wildcard_port() {
        let adapter = FixtureCommandAdapter::default().response(
            "ss",
            output(
                0,
                "udp UNCONN 0 0 172.17.0.1:53 0.0.0.0:* users:((\"dns\",pid=1,fd=2))",
            ),
        );
        let check = listeners(&adapter);
        assert!(
            check
                .evidence
                .iter()
                .any(|line| line.contains("172.17.0.1:53"))
        );
        assert!(!check.evidence.iter().any(|line| line.ends_with(" 0")));
    }

    #[test]
    fn secure_boot_reads_bootctl_status_field() {
        let adapter = FixtureCommandAdapter::default().response(
            "bootctl",
            output(0, "Systemd Boot Loader:\nSecure Boot: enabled\n"),
        );
        let check = secure_boot_with_efi(&adapter, true);
        assert!(check.evidence.iter().any(|line| line.contains("enabled")));
    }

    #[test]
    fn secure_boot_is_not_applicable_without_efi() {
        let adapter = FixtureCommandAdapter::default();
        let check = secure_boot_with_efi(&adapter, false);
        assert_eq!(check.state, CheckState::NotApplicable);
    }

    #[test]
    fn report_timestamps_use_rfc3339_utc_shape() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(timestamp_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            timestamp_seconds("2026-09-08T00:00:00Z").map(format_timestamp),
            Some("2026-09-08T00:00:00Z".to_owned())
        );
        assert!(now().ends_with('Z'));
    }

    #[test]
    fn empty_effective_ruleset_is_not_a_pass() {
        let adapter = FixtureCommandAdapter::default().response("nft", output(0, ""));
        let check = firewall_effective(&adapter);
        assert_eq!(check.state, CheckState::Attention);
    }

    #[test]
    fn multiline_nft_base_chain_is_a_readable_policy() {
        let adapter = FixtureCommandAdapter::default().response(
            "nft",
            output(
                0,
                "table inet filter {\n chain input {\n  type filter hook input priority filter;\n  policy drop;\n }\n}",
            ),
        );
        let check = firewall_effective(&adapter);
        assert_eq!(check.state, CheckState::Pass);
    }

    #[test]
    fn checkout_head_reads_packed_refs_and_worktree_git_pointers() {
        let root = env::temp_dir().join(format!(
            "omasafe-posture-git-fixture-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let git_dir = root.join("gitdir/worktrees/fixture");
        fs::create_dir_all(&git_dir).unwrap();
        fs::write(
            root.join(".git"),
            format!("gitdir: {}\n", git_dir.display()),
        )
        .unwrap();
        fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(
            git_dir.join("packed-refs"),
            "# pack-refs with: peeled fully-peeled\n0123456789012345678901234567890123456789 refs/heads/main\n",
        )
        .unwrap();
        let resolved = resolve_git_dir(&root).unwrap();
        assert_eq!(
            read_checkout_head(&root, &resolved).as_deref(),
            Some("0123456789012345678901234567890123456789")
        );
        fs::remove_dir_all(root).unwrap();
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

    // ---- v0.3.1 C1/C2/C3 ------------------------------------------------------

    fn one_check_report(state: CheckState, generated_at: &str) -> PostureReport {
        PostureReport {
            schema: POSTURE_SCHEMA_VERSION.to_owned(),
            check_catalog_version: CHECK_CATALOG_VERSION,
            generated_at: generated_at.to_owned(),
            host: HostProfile::default(),
            tools: vec![],
            checks: vec![result(
                "updates.repository",
                "Repository updates",
                state,
                vec!["evidence".into()],
                vec![],
                None,
                None,
            )],
            coverage: CoverageSummary::default(),
            last_observed_post_update_hook: None,
        }
    }

    #[test]
    fn previous_state_is_the_preceding_report_not_the_current_one() {
        let mut state = PostureState::default();
        let mut report = one_check_report(CheckState::Pass, "2026-09-08T00:00:00Z");

        // First observation: nothing precedes it, and `null` is the honest answer.
        update_state(&mut state, &report);
        annotate_report(&mut report, &state);
        assert_eq!(report.checks[0].previous_state, None);

        // Second run, changed. THIS is the assertion the whole field exists for: if
        // `previous_states` were exported instead of `prior_states`, previous_state
        // would come back as `Attention` — equal to the current state — and every
        // change mark downstream would silently disappear.
        let mut next = one_check_report(CheckState::Attention, "2026-09-09T00:00:00Z");
        update_state(&mut state, &next);
        annotate_report(&mut next, &state);
        assert_eq!(next.checks[0].previous_state, Some(CheckState::Pass));
        assert_ne!(next.checks[0].previous_state, Some(next.checks[0].state));
    }

    #[test]
    fn an_unchanged_check_reports_a_previous_state_equal_to_its_state() {
        // The degenerate case, reachable deliberately. It is also exactly what the
        // `previous_states` bug would produce for EVERY check, which is why it must
        // never be the only case covered.
        let mut state = PostureState::default();
        let mut first = one_check_report(CheckState::Pass, "2026-09-08T00:00:00Z");
        update_state(&mut state, &first);
        annotate_report(&mut first, &state);
        let mut second = one_check_report(CheckState::Pass, "2026-09-09T00:00:00Z");
        update_state(&mut state, &second);
        annotate_report(&mut second, &state);
        assert_eq!(second.checks[0].previous_state, Some(CheckState::Pass));
        assert_eq!(
            second.checks[0].previous_state,
            Some(second.checks[0].state)
        );
    }

    #[test]
    fn gap_open_since_is_set_only_while_a_coverage_gap_is_open() {
        let mut state = PostureState::default();
        let mut open = one_check_report(CheckState::Incomplete, "2026-09-08T00:00:00Z");
        update_state(&mut state, &open);
        annotate_report(&mut open, &state);
        assert_eq!(
            open.checks[0].gap_open_since.as_deref(),
            Some("2026-09-08T00:00:00Z")
        );

        // The episode keeps its ORIGINAL start across later reports, which is the whole
        // point of "open N days".
        let mut still_open = one_check_report(CheckState::Incomplete, "2026-09-14T00:00:00Z");
        update_state(&mut state, &still_open);
        annotate_report(&mut still_open, &state);
        assert_eq!(
            still_open.checks[0].gap_open_since.as_deref(),
            Some("2026-09-08T00:00:00Z")
        );

        let mut recovered = one_check_report(CheckState::Pass, "2026-09-15T00:00:00Z");
        update_state(&mut state, &recovered);
        annotate_report(&mut recovered, &state);
        assert_eq!(recovered.checks[0].gap_open_since, None);
    }

    #[test]
    fn a_reopened_coverage_gap_starts_when_it_reopened() {
        // Incomplete -> Attention -> Incomplete. The middle report is a SUCCESSFUL
        // observation that happened to report something, so the first gap ended there
        // and the third report opens a new one. Inheriting the first episode's date
        // would report a gap as nine days old when it is one day old.
        let mut state = PostureState::default();

        let mut first = one_check_report(CheckState::Incomplete, "2026-09-01T00:00:00Z");
        update_state(&mut state, &first);
        annotate_report(&mut first, &state);
        assert_eq!(
            first.checks[0].gap_open_since.as_deref(),
            Some("2026-09-01T00:00:00Z")
        );

        let mut recovered = one_check_report(CheckState::Attention, "2026-09-02T00:00:00Z");
        update_state(&mut state, &recovered);
        annotate_report(&mut recovered, &state);
        assert_eq!(recovered.checks[0].gap_open_since, None);
        assert!(
            !state.coverage_episodes.contains_key("updates.repository"),
            "recovering into Attention must end the episode, not park it"
        );

        let mut reopened = one_check_report(CheckState::Incomplete, "2026-09-09T00:00:00Z");
        let notifications = update_state(&mut state, &reopened);
        annotate_report(&mut reopened, &state);
        assert_eq!(
            reopened.checks[0].gap_open_since.as_deref(),
            Some("2026-09-09T00:00:00Z"),
            "the reopened gap starts when it reopened, not when the first one did"
        );
        // The same stale episode also carried `notified: true`, which silently
        // suppressed the notification for the reopened gap.
        assert_eq!(notifications.len(), 1, "a reopened gap notifies again");
    }

    #[test]
    fn recovering_into_a_passing_state_also_ends_the_episode() {
        let mut state = PostureState::default();
        let first = one_check_report(CheckState::Incomplete, "2026-09-01T00:00:00Z");
        update_state(&mut state, &first);
        let pass = one_check_report(CheckState::Pass, "2026-09-02T00:00:00Z");
        update_state(&mut state, &pass);
        assert!(state.coverage_episodes.is_empty());
        let mut reopened = one_check_report(CheckState::Incomplete, "2026-09-09T00:00:00Z");
        update_state(&mut state, &reopened);
        annotate_report(&mut reopened, &state);
        assert_eq!(
            reopened.checks[0].gap_open_since.as_deref(),
            Some("2026-09-09T00:00:00Z")
        );
    }

    #[test]
    fn a_continuing_gap_keeps_its_original_start() {
        // The other half of the contract: while the gap stays open the date must NOT
        // move, or "open N days" resets on every scan.
        let mut state = PostureState::default();
        let first = one_check_report(CheckState::Incomplete, "2026-09-01T00:00:00Z");
        update_state(&mut state, &first);
        let mut later = one_check_report(CheckState::Error, "2026-09-09T00:00:00Z");
        update_state(&mut state, &later);
        annotate_report(&mut later, &state);
        assert_eq!(
            later.checks[0].gap_open_since.as_deref(),
            Some("2026-09-01T00:00:00Z"),
            "Incomplete and Error are both coverage loss; the episode continues"
        );
    }

    #[test]
    fn stored_unix_second_timestamps_are_normalized_on_load() {
        // `started_at` was written as bare unix seconds by an earlier version while
        // `last_seen_at` beside it was RFC-3339 — same String type, so nothing caught
        // it. Loading migrates the value so every reader sees one shape.
        let dir = std::env::temp_dir().join(format!("omasafe-posture-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("posture-state.json");
        let mut state = PostureState::default();
        state.coverage_episodes.insert(
            "firewall.effective".to_owned(),
            CoverageEpisode {
                check_id: "firewall.effective".to_owned(),
                started_at: "1788872597".to_owned(),
                last_seen_at: "2026-09-09T05:00:15Z".to_owned(),
                notified: false,
                reason: "denied".to_owned(),
            },
        );
        store_state(&path, &state).expect("store");
        let loaded = load_state(&path).expect("load");
        let episode = &loaded.coverage_episodes["firewall.effective"];
        assert_eq!(episode.started_at, format_timestamp(1_788_872_597));
        assert!(episode.started_at.ends_with('Z'));
        // An already-correct value is left exactly as it was.
        assert_eq!(episode.last_seen_at, "2026-09-09T05:00:15Z");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_check_carries_its_catalog_position() {
        let report = scan_with_adapter(&FixtureCommandAdapter::default());
        let catalog = check_catalog();
        let mut seen: Vec<u64> = report
            .checks
            .iter()
            .map(|check| check.catalog_index.expect("every check carries an index"))
            .collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), report.checks.len(), "indices are unique");
        assert!(
            seen.iter().all(|index| (*index as usize) < catalog.len()),
            "every index addresses a catalog entry"
        );
        // The index must reconstruct the catalog's own order, which is deliberate and
        // NOT the id order the array is emitted in.
        let by_index = {
            let mut checks: Vec<&CheckResult> = report.checks.iter().collect();
            checks.sort_by_key(|check| check.catalog_index);
            checks
                .iter()
                .map(|check| check.id.as_str())
                .collect::<Vec<_>>()
        };
        let expected: Vec<&str> = catalog
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| report.checks.iter().any(|check| check.id == *id))
            .collect();
        assert_eq!(by_index, expected);
        assert_ne!(
            by_index,
            report
                .checks
                .iter()
                .map(|check| check.id.as_str())
                .collect::<Vec<_>>(),
            "catalog order differs from the emitted id order, which is why C3 exists"
        );
    }

    #[test]
    fn pending_updates_are_attention_and_real_defects_stay_regression() {
        // D1: no disk encryption was `Attention` while a pending package update was
        // `Regression`. Maintenance and defects now sit on the right side of that line.
        let report = scan_with_adapter(&FixtureCommandAdapter::default());
        for id in ["updates.repository", "updates.omarchy"] {
            if let Some(check) = report.checks.iter().find(|check| check.id == id) {
                assert_ne!(
                    check.state,
                    CheckState::Regression,
                    "{id} must not report a regression for pending maintenance"
                );
            }
        }
    }
}
