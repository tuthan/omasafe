//! Shared bounded-ingest primitives for untrusted plugin trees and Git sources.
//!
//! v0.2 generalizes the private v0.1 limits from `omasafe-plugin-trust` so the
//! analyzer meets the frozen untrusted-input contract: elapsed time, file count,
//! aggregate bytes, individual file size, nesting depth, generated evidence, and
//! child-process/cache budgets are all explicit and shared.

use std::io;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::{Duration, Instant};

/// Maximum number of regular entries collected from one target tree.
pub const MAX_FILES: usize = 10_000;
/// Maximum size in bytes of a single collected file before sampling kicks in.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum aggregate bytes read across one collection pass.
pub const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum bytes buffered for metadata-like files (Git config/HEAD/refs).
pub const MAX_METADATA_BYTES: usize = 1024 * 1024;
/// Bytes sampled from the head/tail of oversize files for digesting.
pub const SAMPLE_BYTES: u64 = 1024 * 1024;
/// Maximum bytes emitted in a text diff result (presentation limit; excluded
/// from analyzer policy identity because it cannot change analysis outcomes).
pub const MAX_DIFF_BYTES: usize = 128 * 1024;
/// Maximum directory nesting depth followed inside one target tree.
pub const MAX_TREE_DEPTH: usize = 64;
/// Default elapsed-time budget for one bounded collection or analysis pass.
pub const DEFAULT_TIME_BUDGET: Duration = Duration::from_secs(30);
/// Default wall-clock budget for one external Git child process.
pub const GIT_PROCESS_BUDGET: Duration = Duration::from_secs(60);
/// Default on-disk quota for disposable cached Git objects per repository.
pub const MAX_CACHE_BYTES: u64 = 512 * 1024 * 1024;
/// Upper bound on evidence excerpts retained per finding, in bytes.
pub const MAX_EVIDENCE_BYTES_PER_RESULT: usize = 16 * 1024;
/// Hard per-stream cap on captured child-process output. A chatty child can
/// neither grow memory without bound nor deadlock the polling loop.
pub const MAX_PROCESS_OUTPUT_BYTES_PER_STREAM: usize = 8 * 1024 * 1024;

const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);
const DRAIN_CHUNK_BYTES: usize = 64 * 1024;

/// Elapsed-time budget for bounded work; expired budgets degrade coverage
/// visibly instead of aborting the whole scan.
#[derive(Debug, Clone)]
pub struct TimeBudget {
    started_at: Instant,
    limit: Duration,
}

impl Default for TimeBudget {
    fn default() -> Self {
        Self::new(DEFAULT_TIME_BUDGET)
    }
}

impl TimeBudget {
    pub fn new(limit: Duration) -> Self {
        Self {
            started_at: Instant::now(),
            limit,
        }
    }

    pub fn remaining(&self) -> Duration {
        self.limit.saturating_sub(self.started_at.elapsed())
    }

    pub fn expired(&self) -> bool {
        self.remaining().is_zero()
    }
}

/// Captured result of a child process that completed within its budget.
///
/// `truncated` is set whenever output fidelity was lost: a stream hit its cap,
/// a drain read failed, or a pipe stayed open past the collection window
/// (typically because a descendant inherited it). Truncation is data, never a
/// silent success.
#[derive(Debug)]
pub struct BoundedProcessOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
}

struct DrainOutcome {
    bytes: Vec<u8>,
    truncated: bool,
    /// True when the stream gave up because the budget expired rather than
    /// reaching EOF, a capture cap, or an error. This is the observable
    /// signal that a descendant may still hold the pipe open.
    deadline_hit: bool,
}

/// Joins a drain worker through a channel so collection can give up when a
/// descendant inherited the pipe and keeps it open past the budget. The
/// retained worker handle documents ownership; workers always terminate by
/// their deadline because every read is readiness-bounded.
struct DrainHandle {
    _worker: std::thread::JoinHandle<()>,
    receiver: std::sync::mpsc::Receiver<DrainOutcome>,
}

/// Last-resort cleanup when bounded tracking itself fails: kill the whole
/// process group and reap so no child or descendant outlives the call.
#[cfg(unix)]
fn fail_child_cleanup(child: &mut Child) {
    let pid = child.id() as libc::pid_t;
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
    let mut raw_status: libc::c_int = 0;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut raw_status, 0) };
        if !(result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted) {
            break;
        }
    }
}

/// Runs an argv-only child command under a hard wall-clock budget and the
/// default per-stream output cap.
pub fn run_bounded(
    command: &mut Command,
    budget: Duration,
) -> io::Result<Option<BoundedProcessOutput>> {
    run_bounded_capped(command, budget, MAX_PROCESS_OUTPUT_BYTES_PER_STREAM)
}

/// Like [`run_bounded`] but with an explicit per-stream output cap. Workers
/// stop reading at the cap and report `truncated`; the child may receive
/// EPIPE/SIGPIPE when the readers close, which self-limits chatty writers.
pub fn run_bounded_capped(
    command: &mut Command,
    budget: Duration,
    max_output_bytes_per_stream: usize,
) -> io::Result<Option<BoundedProcessOutput>> {
    spawn_bounded(command, budget, max_output_bytes_per_stream)
}

fn spawn_bounded(
    command: &mut Command,
    budget: Duration,
    output_cap: usize,
) -> io::Result<Option<BoundedProcessOutput>> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Own process group: the timeout kill also reaches forked descendants.
        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let deadline = Instant::now() + budget;
    let stdout_drain = match child
        .stdout
        .take()
        .map(|pipe| spawn_drain(pipe, deadline, output_cap))
    {
        Some(result) => match result {
            Ok(handle) => Some(handle),
            Err(error) => {
                fail_child_cleanup(&mut child);
                return Err(error);
            }
        },
        None => None,
    };
    let stderr_drain = match child
        .stderr
        .take()
        .map(|pipe| spawn_drain(pipe, deadline, output_cap))
    {
        Some(result) => match result {
            Ok(handle) => Some(handle),
            Err(error) => {
                fail_child_cleanup(&mut child);
                return Err(error);
            }
        },
        None => None,
    };

    // Exit detection must not collect the leader before every group-kill
    // decision has been made: waitid(WNOWAIT|WNOHANG) observes exit while
    // leaving the child a zombie, so its pid and process group stay pinned and
    // a late group kill cannot be redirected by pid reuse. std's try_wait/wait
    // would reap too early.
    #[cfg(unix)]
    {
        match unix_poll_exit(&child, deadline) {
            Ok(PollExit::Expired) => {
                // The group was killed and the leader reaped inside the poll.
                return Ok(None);
            }
            Ok(PollExit::Exited) => {
                // Interrupt responsiveness on this path comes from pipe EOF:
                // an interrupt kills the group before exit observation in
                // practice, and any surviving descendants holding pipes are
                // disclosed as truncation by the bounded drains rather than
                // silently waited out.
            }
            Err(error) => {
                fail_child_cleanup(&mut child);
                return Err(error);
            }
        }
        // The leader is a zombie now: it pins pid and process group while we
        // collect drains and make the group-kill decision.
        let mut truncated = false;
        let stdout = collect_drain(stdout_drain, deadline);
        let stderr = collect_drain(stderr_drain, deadline);
        if stdout.abandoned() || stderr.abandoned() {
            kill_process_group(child.id() as libc::pid_t);
        }
        let raw_status = reap_collecting(child.id() as libc::pid_t)?;
        let status = std::os::unix::process::ExitStatusExt::from_raw(raw_status);
        let stdout = stdout.into_result(&mut truncated)?;
        let stderr = stderr.into_result(&mut truncated)?;
        Ok(Some(BoundedProcessOutput {
            status,
            stdout,
            stderr,
            truncated,
        }))
    }
    #[cfg(not(unix))]
    {
        let _ = (&stdout_drain, &stderr_drain, &deadline);
        non_unix_run_bounded(child, deadline, stdout_drain, stderr_drain)
    }
}

#[cfg(unix)]
enum PollExit {
    Exited,
    Expired,
}

/// Observes child exit WITHOUT collecting it (waitid with WNOWAIT|WNOHANG), so
/// the exited child stays a zombie and keeps pinning its pid/process group
/// until the caller's group-kill decision is made. On budget expiry the whole
/// process group is killed and the leader reaped before returning `Expired`.
///
/// Known limitation: a descendant that calls `setsid()` escapes its process
/// group and survives a group kill; such survivors surface as `truncated`
/// output rather than a hang, because drain collection is deadline-bounded.
#[cfg(unix)]
fn unix_poll_exit(child: &Child, deadline: Instant) -> io::Result<PollExit> {
    let pid = child.id() as libc::id_t;
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 && info.si_signo != 0 {
            return Ok(PollExit::Exited);
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted
                || error.raw_os_error() == Some(libc::EAGAIN)
                || error.kind() == io::ErrorKind::WouldBlock
            {
                // Child still running; fall through to the deadline check.
            } else {
                // Cleanup ownership stays with the caller's error arm
                // (fail_child_cleanup) so reaping happens exactly once.
                return Err(error);
            }
        }
        if Instant::now() >= deadline || crate::interrupt::raised() {
            kill_process_group(child.id() as libc::pid_t);
            reap_collecting(child.id() as libc::pid_t)?;
            return Ok(PollExit::Expired);
        }
        std::thread::sleep(
            PROCESS_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

#[cfg(unix)]
fn kill_process_group(pid: libc::pid_t) {
    // Negative pid targets the process group; ignore errors because the group
    // may already be gone. Safe against pid reuse: while uncollected (zombie),
    // the leader still pins both pid and group.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
}

#[cfg(unix)]
fn reap_collecting(pid: libc::pid_t) -> io::Result<libc::c_int> {
    loop {
        let mut raw_status: libc::c_int = 0;
        let result = unsafe { libc::waitpid(pid, &mut raw_status, 0) };
        if result == pid {
            return Ok(raw_status);
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        // waitpid returning 0 without WNOHANG cannot happen; treat defensively.
        return Err(io::Error::other("unexpected waitpid result"));
    }
}

#[cfg(not(unix))]
fn non_unix_run_bounded(
    mut child: Child,
    deadline: Instant,
    stdout_drain: Option<DrainHandle>,
    stderr_drain: Option<DrainHandle>,
) -> io::Result<Option<BoundedProcessOutput>> {
    // Portable fallback without process groups: descendants cannot be tracked,
    // so pipe-holding survivors are disclosed as truncation instead of killed.
    loop {
        match child.try_wait()? {
            Some(status) => {
                let mut truncated = false;
                let stdout = collect_drain(stdout_drain, deadline);
                let stderr = collect_drain(stderr_drain, deadline);
                let stdout = stdout.into_result(&mut truncated)?;
                let stderr = stderr.into_result(&mut truncated)?;
                return Ok(Some(BoundedProcessOutput {
                    status,
                    stdout,
                    stderr,
                    truncated,
                }));
            }
            None => {
                if Instant::now() >= deadline || crate::interrupt::raised() {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(None);
                }
                std::thread::sleep(
                    PROCESS_POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
        }
    }
}

fn spawn_drain<R>(pipe: R, deadline: Instant, output_cap: usize) -> io::Result<DrainHandle>
where
    R: io::Read + Send + AsRawFdMarker + 'static,
{
    let (sender, receiver) = channel();
    let worker = std::thread::Builder::new()
        .name("omasafe-drain".to_owned())
        .spawn(move || {
            let outcome = drain_stream(pipe, deadline, output_cap);
            let _ = sender.send(outcome);
        })
        .map_err(|error| {
            io::Error::other(format!("output drain thread failed to spawn: {error}"))
        })?;
    Ok(DrainHandle {
        _worker: worker,
        receiver,
    })
}

/// Marks streams usable by the platform-specific bounded reader.
#[cfg(unix)]
pub trait AsRawFdMarker: std::os::fd::AsRawFd {}
#[cfg(unix)]
impl<T: std::os::fd::AsRawFd> AsRawFdMarker for T {}

#[cfg(not(unix))]
pub trait AsRawFdMarker {}
#[cfg(not(unix))]
impl<T> AsRawFdMarker for T {}

fn drain_stream<S: io::Read + AsRawFdMarker>(
    mut stream: S,
    deadline: Instant,
    output_cap: usize,
) -> DrainOutcome {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut deadline_hit = false;
    let mut chunk = [0u8; DRAIN_CHUNK_BYTES];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            truncated = true;
            deadline_hit = true;
            break;
        }
        match wait_readable(&stream, deadline) {
            WaitReadable::Ready => {}
            WaitReadable::TimedOut => {
                truncated = true;
                deadline_hit = true;
                break;
            }
            WaitReadable::Failed => {
                truncated = true;
                break;
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                let budget = output_cap.saturating_sub(bytes.len());
                if budget == 0 {
                    truncated = true;
                    break;
                }
                let keep = read.min(budget);
                bytes.extend_from_slice(&chunk[..keep]);
                if keep < read {
                    truncated = true;
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                truncated = true;
                break;
            }
        }
    }
    DrainOutcome {
        bytes,
        truncated,
        deadline_hit,
    }
}

#[cfg(unix)]
enum WaitReadable {
    Ready,
    TimedOut,
    Failed,
}

/// Waits until the stream is readable or hup, strictly within `deadline`.
/// EINTR re-polls with a recomputed budget instead of falling through to a
/// blocking read that a silent pipe holder could strand forever.
#[cfg(unix)]
fn wait_readable<S: io::Read + AsRawFdMarker>(stream: &S, deadline: Instant) -> WaitReadable {
    let mut poll_fd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return WaitReadable::TimedOut;
        }
        let timeout_ms = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        let result = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return WaitReadable::Failed;
        }
        if result == 0 {
            return WaitReadable::TimedOut;
        }
        break;
    }
    if poll_fd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return WaitReadable::Failed;
    }
    // POLLIN and/or POLLHUP: a read will make progress or report EOF.
    WaitReadable::Ready
}

#[cfg(not(unix))]
fn wait_readable<S: io::Read + AsRawFdMarker>(_stream: &S, _remaining: Duration) -> WaitReadable {
    // No portable readiness primitive: reads may block past the deadline on
    // platforms without process-group support. Linux is the supported target.
    WaitReadable::Ready
}

/// Outcome of waiting for one output stream's drain worker.
enum DrainCollection {
    Output {
        bytes: Vec<u8>,
        truncated: bool,
        deadline_hit: bool,
    },
    /// The worker never reported back before the budget: a pipe holder may
    /// still be alive and the caller must clean up the process group.
    Abandoned,
    /// The drain worker died unexpectedly.
    Failed,
}

impl DrainCollection {
    fn abandoned(&self) -> bool {
        match self {
            DrainCollection::Abandoned => true,
            // A worker that gave up at the deadline signals the same hazard:
            // some descendant may still hold its pipe open.
            DrainCollection::Output { deadline_hit, .. } => *deadline_hit,
            DrainCollection::Failed => false,
        }
    }

    fn into_result(self, truncated: &mut bool) -> io::Result<Vec<u8>> {
        match self {
            DrainCollection::Output {
                bytes,
                truncated: lost,
                ..
            } => {
                *truncated |= lost;
                Ok(bytes)
            }
            DrainCollection::Abandoned => {
                *truncated = true;
                Ok(Vec::new())
            }
            DrainCollection::Failed => Err(io::Error::other(
                "bounded child output drain thread terminated unexpectedly",
            )),
        }
    }
}

fn collect_drain(drain: Option<DrainHandle>, deadline: Instant) -> DrainCollection {
    let Some(drain) = drain else {
        return DrainCollection::Output {
            bytes: Vec::new(),
            truncated: false,
            deadline_hit: false,
        };
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    match drain.receiver.recv_timeout(remaining) {
        Ok(outcome) => DrainCollection::Output {
            bytes: outcome.bytes,
            truncated: outcome.truncated,
            deadline_hit: outcome.deadline_hit,
        },
        // A pipe is still held past the budget (typically an unreaped
        // descendant). Report loss instead of blocking indefinitely; the
        // caller performs the group kill.
        Err(RecvTimeoutError::Timeout) => DrainCollection::Abandoned,
        Err(RecvTimeoutError::Disconnected) => DrainCollection::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn time_budget_expires_and_reports_remaining() {
        let budget = TimeBudget::new(Duration::from_millis(20));
        assert!(!budget.expired());
        std::thread::sleep(Duration::from_millis(40));
        assert!(budget.expired());
        assert_eq!(budget.remaining(), Duration::ZERO);
    }

    #[test]
    fn bounded_command_enforces_wall_clock_budget() {
        let mut command = Command::new("sleep");
        command.arg("5");
        let started = Instant::now();
        let outcome = run_bounded(&mut command, Duration::from_millis(50)).unwrap();
        assert!(outcome.is_none(), "budget expiry must be reported");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn bounded_command_returns_status_and_output_on_completion() {
        let mut command = Command::new("sh");
        command.args(["-c", "echo hello; echo boom >&2"]);
        let output = run_bounded(&mut command, Duration::from_secs(5))
            .unwrap()
            .expect("fast child must complete");
        assert!(output.status.success());
        assert!(!output.truncated);
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim_end(), "hello");
        assert_eq!(String::from_utf8_lossy(&output.stderr).trim_end(), "boom");
    }

    #[test]
    fn bounded_command_captures_large_output_without_deadlock() {
        let mut command = Command::new("sh");
        command.args(["-c", "yes abracadabra | head -c 2000000"]);
        let output = run_bounded(&mut command, Duration::from_secs(20))
            .unwrap()
            .expect("large-but-capped output must complete");
        assert_eq!(output.stdout.len(), 2_000_000);
        assert!(!output.truncated);
    }

    #[test]
    fn bounded_command_marks_output_over_cap_truncated() {
        let mut command = Command::new("sh");
        command.args(["-c", "yes abracadabra | head -c 20000000"]);
        let output = run_bounded(&mut command, Duration::from_secs(30))
            .unwrap()
            .expect("oversize output must still complete");
        assert!(output.truncated);
        assert_eq!(
            output.stdout.len(),
            MAX_PROCESS_OUTPUT_BYTES_PER_STREAM,
            "capture must stop exactly at the cap"
        );
    }

    #[test]
    fn bounded_command_kills_descendants_on_timeout() {
        let mut command = Command::new("sh");
        // The sleep inherits our pipes; only a process-group kill prevents the
        // post-exit collection from stalling until the sleep exits naturally.
        command.args(["-c", "sleep 30 & wait"]);
        let started = Instant::now();
        let outcome = run_bounded(&mut command, Duration::from_millis(200)).unwrap();
        assert!(outcome.is_none(), "expired child must be reported as None");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "descendants must not extend the wait"
        );
    }

    #[test]
    fn bounded_command_kills_pipe_holding_descendants_on_success() {
        let marker = std::env::temp_dir().join(format!(
            "omasafe-bounds-marker-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let script = format!("( sleep 2; touch {} ) & echo done", marker.display());
        let mut command = Command::new("sh");
        command.arg("-c").arg(&script);
        // The direct child finishes instantly; the background subshell holds
        // the pipe and must be killed by group even though we return Some.
        let output = run_bounded(&mut command, Duration::from_millis(300))
            .unwrap()
            .expect("direct child completes quickly");
        assert!(output.status.success());
        assert!(output.truncated, "held pipes must be disclosed");
        std::thread::sleep(Duration::from_millis(2500));
        assert!(
            !marker.exists(),
            "the pipe-holding descendant must have been killed before writing its marker"
        );
    }
}
