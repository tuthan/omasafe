//! Cooperative interruption for long-running commands.
//!
//! Installing these handlers changes default process death into a
//! cooperative stop: the flag is set, in-flight bounded children are killed
//! by their poll loops, and each long-running command checks the flag at
//! phase boundaries so it can unwind through its normal cleanup paths
//! (atomic state files stay closed, temporary checkouts are swept, the
//! reviewed-update record keeps its recovery semantics) instead of dying
//! mid-write. Handlers only touch an atomic bool; everything else happens
//! on the main thread.

use std::sync::atomic::{AtomicBool, Ordering};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_signal: i32) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Installs SIGINT/SIGTERM handlers. Idempotent; safe to call once at
/// process start. Child processes reset caught signals to their defaults on
/// exec, so bounded subprocesses keep terminating directly on terminal
/// interrupts. A failed registration leaves the default disposition in place
/// (hard death on signal), which is always a safe fallback, so the result is
/// deliberately not surfaced.
pub fn install() {
    let handler = on_signal as extern "C" fn(i32) as usize;
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

/// Whether an interruption signal has been observed.
pub fn raised() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

#[cfg(unix)]
/// Whether `pid` refers to a live process. Used to sweep temporary working
/// directories left behind by processes that died hard (SIGKILL, power loss)
/// before cooperative cleanup could run.
pub fn process_alive(pid: i32) -> bool {
    // 0 signals no-op existence probe: success = alive, ESRCH = gone,
    // EPERM = alive but owned by someone else.
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_liveness_probe_distinguishes_self_from_bogus_pid() {
        assert!(super::process_alive(std::process::id() as i32));
        // PID 4 is negligible in modern systems; probing it must simply
        // report not-alive rather than panicking.
        assert!(!super::process_alive(4_000_000));
    }
}
