use std::collections::BTreeSet;
use std::fs;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use omasafe_core::{TOOL_VERSION, paths::XdgPaths};
use omasafe_marketplace::{
    Correlation, MAX_CATALOG_BYTES, OFFICIAL_REPOSITORY, correlate, fetch_pinned_catalog,
    load_cached_catalog, load_catalog, resolve_latest_commit, valid_commit,
};
use omasafe_plugin_trust::{
    DiffResult, SourceIdentity,
    baseline::{
        ReviewDecision, ScanState, TrustHistory, TrustRecord, UpdateFlowRecord, lock as lock_state,
    },
    collect, collect_one, git_diff, omarchy_bar_use_default, omarchy_plugin_disable,
    omarchy_plugin_enable, omarchy_plugin_update, query_shell, source_identity,
};
use omasafe_report::Report;
use sha2::{Digest, Sha256};

fn main() {
    omasafe_core::interrupt::install();
    match run(std::env::args().skip(1).collect()) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("omasafe: {error}");
            if omasafe_core::interrupt::raised() {
                std::process::exit(INTERRUPTED_EXIT_CODE);
            }
            std::process::exit(1);
        }
    }
}

/// Exit status for commands stopped by SIGINT/SIGTERM after cooperative
/// cleanup. Deliberately unified at 128+SIGINT for both signals so callers
/// need not distinguish; the specific signal is not otherwise meaningful to
/// OmaSafe's flows.
const INTERRUPTED_EXIT_CODE: i32 = 130;

fn interrupted(context: &str) -> Box<dyn std::error::Error> {
    format!("interrupted: {context}").into()
}

/// Phase-boundary stop for long-running commands: bounded children are
/// already killed by their poll loops once the flag is set, so reaching a
/// checkpoint with the flag up means unwind now.
fn interruption_checkpoint(context: &str) -> Result<(), Box<dyn std::error::Error>> {
    if omasafe_core::interrupt::raised() {
        return Err(interrupted(context));
    }
    Ok(())
}

/// Removes candidate checkouts orphaned by hard deaths (SIGKILL, power loss)
/// whose owning pid no longer exists. Live concurrent runs are never touched.
#[cfg(unix)]
fn sweep_orphaned_review_checkouts() {
    let prefix = "omasafe-review-update-";
    let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(prefix) {
            continue;
        }
        let dir = entry.path();
        // A live owner holds LOCK_EX on .owner.lock for its entire run; the
        // kernel drops that lock exactly when the owner dies. Acquiring it
        // here therefore proves the checkout is orphaned regardless of pid
        // reuse. Directories predating the lock scheme have no lock file and
        // are treated as orphans.
        let lock_path = dir.join(".owner.lock");
        if lock_path.exists() {
            let Ok(lock) = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
            else {
                continue;
            };
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                let result =
                    unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                if result != 0 {
                    continue; // live owner
                }
            }
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(not(unix))]
fn sweep_orphaned_review_checkouts() {}

fn run(args: Vec<String>) -> Result<i32, Box<dyn std::error::Error>> {
    let exit_code = match args.as_slice() {
        [] => {
            println!("omasafe-cli {TOOL_VERSION}");
            0
        }
        [flag] if flag == "--version" || flag == "-V" => {
            println!("omasafe-cli {TOOL_VERSION}");
            0
        }
        [command] if command == "paths" => {
            print_paths()?;
            0
        }
        [command] if command == "provenance" => {
            provenance(&[])?;
            0
        }
        [command, rest @ ..] if command == "provenance" => {
            provenance(rest)?;
            0
        }
        [command, subcommand, rest @ ..] if command == "plugins" && subcommand == "inventory" => {
            inventory(rest)?;
            0
        }
        [command, subcommand, id, rest @ ..] if command == "plugins" && subcommand == "trust" => {
            trust(id, rest)?;
            0
        }
        [command, subcommand, id, rest @ ..] if command == "plugins" && subcommand == "status" => {
            status(id, rest)?;
            0
        }
        [command, subcommand, id, rest @ ..] if command == "plugins" && subcommand == "diff" => {
            diff(id, rest)?;
            0
        }
        [command, subcommand, id, rest @ ..]
            if command == "plugins" && subcommand == "review-update" =>
        {
            review_update(id, rest)?;
            0
        }
        [command, subcommand, id, rest @ ..] if command == "plugins" && subcommand == "review" => {
            review(id, rest)?;
            0
        }
        [command] if command == "scan" => {
            if scan(&[])? {
                3
            } else {
                0
            }
        }
        [command, rest @ ..] if command == "scan" => {
            if scan(rest)? {
                3
            } else {
                0
            }
        }
        [command, subcommand, rest @ ..] if command == "schedule" && subcommand == "install" => {
            schedule_install(rest)?;
            0
        }
        [command, subcommand, rest @ ..] if command == "marketplace" && subcommand == "refresh" => {
            marketplace_refresh(rest)?;
            0
        }
        [command, subcommand, rest @ ..] if command == "rules" && subcommand == "list" => {
            rules_list(rest)?;
            0
        }
        [command, subcommand, id, rest @ ..] if command == "rules" && subcommand == "explain" => {
            rules_explain(id, rest)?;
            0
        }
        [command, subcommand, id, rest @ ..] if command == "plugins" && subcommand == "analyze" => {
            plugins_analyze(id, rest)?
        }
        [command, rest @ ..] if command == "scan-plugin" => scan_plugin(rest)?,
        _ => {
            eprintln!(
                "usage: omasafe-cli plugins ... | scan [--format text|json] [--notify] [--only-new] | marketplace refresh [--commit COMMIT|--latest] | rules list [--format text|json] | rules explain RULE_ID [--format text|json] | plugins analyze PLUGIN_ID [--format text|json] [--fail-on SEVERITY] | plugins review-update PLUGIN_ID [--expected-commit SHA] [--yes] | scan-plugin (--path DIR|--git URL --revision COMMIT) [--format text|json] | schedule install | paths | provenance [--format text|json]"
            );
            std::process::exit(2);
        }
    };
    Ok(exit_code)
}

fn provenance(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut format = "text";
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--format" => {
                format = next_value(args, index, "provenance format")?;
                index += 2;
            }
            value => return Err(format!("unknown provenance argument: {value}").into()),
        }
    }

    let report = serde_json::json!({
        "schema": "omasafe.provenance.v1",
        "tool": "omasafe-cli",
        "tool_version": TOOL_VERSION,
        "source_revision": env!("OMASAFE_SOURCE_REVISION"),
        "target": env!("OMASAFE_TARGET"),
        "rust_toolchain": env!("OMASAFE_RUST_TOOLCHAIN"),
        "cargo_lock_sha256": env!("OMASAFE_CARGO_LOCK_SHA256"),
        "supported_runtime": {
            "omarchy": "4.0.0-1",
            "quickshell": "0.3.0"
        },
        "coverage_limitations": [
            "Omarchy plugin inventory depends on omarchy plugin list --json.",
            "Filesystem-only inventory is partial when native Omarchy metadata is unavailable.",
            "Runtime behavior of unsandboxed plugin QML is described, not executed by the CLI."
        ]
    });

    match format {
        "json" => println!("{}", serde_json::to_string_pretty(&report)?),
        "text" => {
            println!("OmaSafe provenance");
            println!("schema: {}", report["schema"]);
            println!("tool: {} {}", report["tool"], report["tool_version"]);
            println!("source_revision: {}", report["source_revision"]);
            println!("target: {}", report["target"]);
            println!("rust_toolchain: {}", report["rust_toolchain"]);
            println!("cargo_lock_sha256: {}", report["cargo_lock_sha256"]);
            println!(
                "supported_runtime: Omarchy {} / Quickshell {}",
                report["supported_runtime"]["omarchy"], report["supported_runtime"]["quickshell"]
            );
            println!("coverage_limitations:");
            for limitation in report["coverage_limitations"]
                .as_array()
                .expect("static provenance limitations")
            {
                println!("- {limitation}");
            }
        }
        value => return Err(format!("unsupported provenance format: {value}").into()),
    }
    Ok(())
}

fn trust(id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut yes = false;
    let mut expected_head = None;
    let mut expected_tree = None;
    let mut expected_digest = None;
    let mut note = "accepted by user".to_owned();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--yes" => {
                yes = true;
                index += 1;
            }
            "--expected-head" => {
                expected_head = Some(next_value(args, index, "expected HEAD")?.to_owned());
                index += 2;
            }
            "--expected-tree" => {
                expected_tree = Some(next_value(args, index, "expected tree")?.to_owned());
                index += 2;
            }
            "--expected-digest" => {
                expected_digest = Some(next_value(args, index, "expected digest")?.to_owned());
                index += 2;
            }
            "--note" => {
                note = next_value(args, index, "note")?.to_owned();
                index += 2;
            }
            value => return Err(format!("unknown trust argument: {value}").into()),
        }
    }
    let plugin_root = plugin_root()?;
    let (shell_json, _shell_error) = query_shell();
    let inventory = collect_one(&plugin_root, id, shell_json.as_deref());
    let record = inventory
        .plugins
        .iter()
        .find(|plugin| plugin.id == id)
        .ok_or_else(|| format!("plugin not found: {id}"))?;
    let identity = SourceIdentity {
        plugin_id: record.id.clone(),
        repository: record.repository.clone(),
        head: record.head.clone(),
        tree: record.tree.clone(),
        content_digest: record.content_digest.clone(),
        file_count: record.content_file_count.unwrap_or_default(),
        limitations: record.limitations.clone(),
        file_digests: record.file_digests.clone(),
    };
    println!(
        "Plugin: {}\nPath: {}\nIdentity: {}",
        safe_text(&record.id),
        safe_text(&record.path),
        serde_json::to_string_pretty(&identity)?
    );
    if yes {
        if expected_head.is_none() && expected_tree.is_none() && expected_digest.is_none() {
            return Err("unattended trust requires an expected identity and --yes".into());
        }
        if !expected_component(identity.head.as_deref(), expected_head.as_deref())
            || !expected_component(identity.tree.as_deref(), expected_tree.as_deref())
            || !expected_component(
                identity.content_digest.as_deref(),
                expected_digest.as_deref(),
            )
        {
            return Err("current identity does not exactly match the expected identity".into());
        }
    } else {
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            return Err(
                "interactive trust requires a terminal; use --yes with expected identity values"
                    .into(),
            );
        }
        eprint!("Type 'trust' to accept this exact identity: ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if answer.trim() != "trust" {
            return Err("trust not accepted".into());
        }
    }
    let paths = XdgPaths::discover()?;
    paths.ensure()?;
    let history_path = paths.state.join("trust-history.json");
    let _history_lock = lock_state(&history_path)?;
    let mut history = TrustHistory::load(&history_path)?;
    history.accept(TrustRecord {
        plugin_id: id.into(),
        accepted: identity,
        accepted_at: now(),
        note,
    });
    history.write_atomic_locked(&history_path)?;
    println!("Trusted identity recorded in {}", history_path.display());
    Ok(())
}

fn expected_component(current: Option<&str>, expected: Option<&str>) -> bool {
    match (current, expected) {
        (Some(current), Some(expected)) => current == expected,
        (None, None) => true,
        _ => false,
    }
}

/// Creates and owns a candidate checkout. The `.owner.lock` file inside is
/// flock-held for the struct's whole lifetime, so the stale-checkout sweeper
/// can distinguish a live run from an orphaned one without pid heuristics —
/// the kernel releases the lock when (and only when) the owning process dies,
/// which closes the pid-reuse race.
struct TempCandidate(PathBuf, Option<std::fs::File>);

impl TempCandidate {
    fn create(path: PathBuf) -> Result<Self, std::io::Error> {
        std::fs::create_dir_all(&path)?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .create(true)
            .open(path.join(".owner.lock"))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(Self(path, Some(lock)))
    }
}

impl Drop for TempCandidate {
    fn drop(&mut self) {
        // Release the ownership lock first so removal never races a sweeper
        // that observed us as orphans mid-teardown.
        self.1.take();
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `.git/config` is the one identity input that benign lifecycle commands
/// legitimately rewrite (clone wiring, branch tracking), so it cannot be
/// byte-compared. Instead it is parsed by Git itself (bounded argv, hardened
/// env, NUL-delimited `--file` mode so CLI-injected hygiene settings can never
/// leak into the audit) and every ENTRY outside this allowlist of known-benign
/// repository-local entries is refused. Section and variable names are
/// case-insensitive in Git, so both are matched lowercased; subsections stay
/// case-sensitive. Exact keys only — no wildcards: `gc.*` is denied wholesale
/// because Git executes values like `gc.recentObjectsHook` through the shell,
/// and `remote.*` beyond the two origin keys below would admit arbitrary
/// transport URLs (`ext::` runs a command). The origin URL must equal the
/// production HTTPS repository exactly and the refspec must be the standard
/// tracking refspec. Everything executable or dataflow-redirecting —
/// hooksPath, sshCommand, fsmonitor, askPass, credential helpers, diff/gpg
/// programs, aliases, filters, includes, insteadOf redirects, submodule
/// machinery — is absent from the allowlist and therefore fails closed.
fn benign_git_config_entry(key: &str, value: &str, expected_origin: &str) -> bool {
    let Some((head, variable)) = key.rsplit_once('.') else {
        return false;
    };
    let variable = variable.to_lowercase();
    let (section, subsection) = match head.split_once('.') {
        Some((section, subsection)) => (section.to_lowercase(), Some(subsection)),
        None => (head.to_lowercase(), None),
    };
    match section.as_str() {
        "core" => matches!(
            variable.as_str(),
            "repositoryformatversion"
                | "filemode"
                | "bare"
                | "logallrefupdates"
                | "symlinks"
                | "compression"
                | "precomposeunicode"
                | "bigfilethreshold"
                | "autocrlf"
                | "safecrlf"
                | "fscache"
                | "untrackedcache"
        ),
        "user" => matches!(variable.as_str(), "name" | "email" | "signingkey"),
        "init" => variable == "defaultbranch",
        "remote" if subsection == Some("origin") => match variable.as_str() {
            "url" => value.trim_end_matches('/') == expected_origin.trim_end_matches('/'),
            "fetch" => value == "+refs/heads/*:refs/remotes/origin/*",
            _ => false,
        },
        "branch" => match variable.as_str() {
            // The tracking remote must name a configured remote, never a path
            // or URL: a path would let `git pull` reach local transports.
            "remote" => value == "origin" || value == ".",
            "merge" => value.starts_with("refs/heads/"),
            _ => false,
        },
        "pull" => match variable.as_str() {
            "rebase" => matches!(value, "true" | "false" | "merges" | "interactive"),
            "ff" => matches!(value, "true" | "false" | "only"),
            _ => false,
        },
        "fetch" => {
            matches!(
                variable.as_str(),
                "prune" | "prunetags" | "showforcedupdates"
            ) && matches!(value, "true" | "false")
        }
        "push" => match variable.as_str() {
            "default" => matches!(
                value,
                "nothing" | "matching" | "current" | "upstream" | "tracking" | "simple"
            ),
            "followtags" => matches!(value, "true" | "false"),
            _ => false,
        },
        _ => false,
    }
}

/// Lists every config entry in the installed repository's .git/config that the
/// allowlist refuses. Keys are reported lowercased for stable operator output.
fn non_benign_git_config_entries(
    root: &Path,
    expected_origin: &str,
) -> Result<Vec<String>, String> {
    let raw = bounded_git(
        Some(root),
        &["config", "--file", ".git/config", "--list", "--null"],
    )?;
    Ok(raw
        .split('\0')
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| {
            let (key, value) = match entry.split_once('\n') {
                Some((key, value)) => (key, value),
                None => (entry, ""),
            };
            (!benign_git_config_entry(key, value, expected_origin)).then(|| key.to_lowercase())
        })
        .collect())
}

/// Every hook entry in the repository's .git/hooks that is not a regular
/// `*.sample` template file. `Err` means the hooks directory is unreadable,
/// which is itself a refusal: an unauditable hook directory is not
/// trustworthy.
fn active_hooks_in(repo: &Path) -> Result<Vec<String>, String> {
    const MAX_HOOK_ENTRIES: usize = omasafe_core::bounds::MAX_FILES;
    const MAX_HOOK_AUDIT_TIME: Duration = Duration::from_secs(10);
    let hooks_dir = repo.join(".git").join("hooks");
    let mut live = Vec::new();
    let mut entries = std::fs::read_dir(&hooks_dir)
        .map_err(|error| format!(".git/hooks could not be read: {error}"))?;
    let started_at = Instant::now();
    let mut entry_count = 0;
    loop {
        if omasafe_core::interrupt::raised() {
            return Err(".git/hooks audit was interrupted".into());
        }
        if started_at.elapsed() > MAX_HOOK_AUDIT_TIME {
            return Err(".git/hooks audit exceeded its time budget".into());
        }
        let Some(entry) = entries.next() else {
            break;
        };
        entry_count += 1;
        if entry_count > MAX_HOOK_ENTRIES {
            return Err(format!(
                ".git/hooks contains more than {MAX_HOOK_ENTRIES} entries"
            ));
        }
        let entry =
            entry.map_err(|error| format!(".git/hooks entry could not be read: {error}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_file = entry
            .path()
            .symlink_metadata()
            .map_err(|error| {
                format!(".git/hooks entry {name:?} metadata could not be read: {error}")
            })?
            .is_file();
        if !(is_file && name.ends_with(".sample")) {
            live.push(name);
        }
    }
    live.sort();
    live.dedup();
    Ok(live)
}

/// Hook and config audit shared by the pre-mutation gate and the update
/// postcondition. The native updater runs `git fetch` + `git merge`, which
/// executes merge-time hooks and honors every directive in the installed
/// .git/config, so anything executable or dataflow-redirecting must be
/// refused BEFORE that mutation; the postcondition repeats the audit to close
/// the window for changes made during the update itself.
fn audit_installed_git_state(installed_dir: &Path, expected_origin: &str) -> Result<(), String> {
    match active_hooks_in(installed_dir) {
        Err(error) => {
            return Err(format!(
                ".git/hooks is not safely auditable; a repository whose hooks cannot be audited \
                 is not trustworthy: {error}"
            ));
        }
        Ok(hooks) if !hooks.is_empty() => {
            return Err(format!(
                "active (non-template) git hook(s) present in the repository: {hooks:?}. Remove \
                 them or accept them explicitly before re-running 'plugins review-update'."
            ));
        }
        Ok(_) => {}
    }
    match non_benign_git_config_entries(installed_dir, expected_origin) {
        Err(error) => return Err(error),
        Ok(keys) if !keys.is_empty() => {
            return Err(format!(
                "git configuration contains entries outside OmaSafe's benign allowlist: {keys:?}"
            ));
        }
        Ok(_) => {}
    }
    Ok(())
}

/// Snapshot-swaps the installed repository's `.git/config` with a hardened
/// minimal config for the duration of the native update window, restoring the
/// audited original afterwards — on success, failure, and interrupt alike,
/// via `Drop`.
///
/// Why a snapshot rather than more env overrides: between the pre-mutation
/// audit and the postcondition, native Git children (fetch, merge, the
/// checkout of the fast-forward) read `.git/config`. `GIT_CONFIG_COUNT`-style
/// env injection overrides enumerable keys (fsmonitor, hooksPath, credential
/// helper list, diff external), but subsection-keyed executable sinks —
/// `filter.<name>.smudge`/`process` consumed via attributes during checkout,
/// `merge.<name>.driver`, `url.<base>.insteadOf` URL rewriting that can point
/// the fetch at an attacker-controlled host or transport — cannot be
/// enumerated. With the hardened snapshot in place, native Git consumes only
/// known-benign entries during the window: the replacement config DEFINES no
/// executable sink at all, so there is nothing for Git to run. This
/// content-neutralization is the primary defense and is exercised by
/// `hardened_config_neutralizes_a_smudge_filter`, which runs a real smudge
/// payload through `git checkout` under the guard and asserts its marker is
/// never created.
///
/// Residual threat and its bound: a same-UID process racing a NEW config into
/// place between our swap and Git's read could still get a sink executed —
/// userspace cannot make a file the file's own owner cannot rewrite, so this
/// specific race is not preventable without privilege. It is instead made
/// non-advancing: the metadata witness below detects ANY concurrent write
/// (see next paragraph), so trust never advances over a window that was
/// tampered with, even though the injected command may already have run.
///
/// The snapshot is also tamper-evident, and NOT by final-byte comparison
/// alone: `restore` compares both the hardened bytes AND a metadata witness
/// (`ConfigWitness`) captured when the snapshot was installed. A writer that
/// injects a directive, lets Git consume it, then restores the exact hardened
/// bytes before `restore` runs would defeat a bytes-only check — but any such
/// write bumps the inode's ctime (in-place edit) or replaces the inode
/// entirely (atomic rename), and ctime cannot be moved backwards by an
/// unprivileged process. The witness therefore detects write-and-revert; the
/// injection is discarded, and the caller refuses. Unreviewed config writes
/// are untrusted by definition — discarding them is fail-closed. The
/// pre-mutation audit has already refused `extensions.*`, so
/// `repositoryformatversion = 0` is exact for every auditable repository.
///
/// Durability: the audited original is written to a durable, fsync'd backup
/// in the state directory and its path recorded in the `UpdateFlowRecord`
/// BEFORE the swap, so a SIGKILL or power loss mid-window (which skips `Drop`)
/// leaves a recoverable copy on disk, not only in this process's memory. A
/// subsequent run reconciles the target from that backup — see
/// `reconcile_config_backup`.
struct GitConfigGuard {
    config_path: PathBuf,
    original: Vec<u8>,
    original_mode: u32,
    hardened: Vec<u8>,
    witness: ConfigWitness,
    restored: bool,
}

/// Result of `GitConfigGuard::restore`, kept distinct so the caller clears the
/// durable recovery pointer ONLY when the original was positively reinstalled.
enum RestoreOutcome {
    /// Original reinstalled and the window showed no tampering.
    Clean,
    /// Original reinstalled, but the window was tampered with — trust must not
    /// advance.
    Tampered,
    /// The original could NOT be reinstalled; the target may still hold the
    /// hardened snapshot and the durable backup must be preserved for recovery.
    RestoreFailed(String),
}

/// Metadata witness of the installed hardened config. `ctime` advances on ANY
/// inode change — content, mode, or being the target of a rename — and an
/// unprivileged process cannot move it backwards (`utimensat` sets atime/mtime
/// but bumps ctime itself). So a write-then-revert-to-identical-bytes still
/// shows a changed ctime, and an atomic-rename replacement shows a changed
/// inode. Comparing this witness, not just the final bytes, is what makes the
/// child-process window tamper-evident.
#[derive(PartialEq, Eq)]
struct ConfigWitness {
    dev: u64,
    ino: u64,
    ctime: i128,
    mtime: i128,
    size: u64,
}

impl ConfigWitness {
    #[cfg(unix)]
    fn of(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            ctime: i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec()),
            mtime: i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec()),
            size: metadata.size(),
        }
    }

    #[cfg(not(unix))]
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            dev: 0,
            ino: 0,
            ctime: 0,
            mtime: 0,
            size: metadata.len(),
        }
    }
}

impl GitConfigGuard {
    fn swap_to_hardened(
        installed_dir: &Path,
        origin_url: &str,
        backup_path: &Path,
        flow: &mut UpdateFlowRecord,
        flow_path: &Path,
    ) -> Result<Self, String> {
        let config_path = installed_dir.join(".git").join("config");
        // symlink_metadata: never follow a symlink standing in for the config.
        let metadata = fs::symlink_metadata(&config_path).map_err(|error| {
            format!("could not stat {config_path:?} to snapshot before hardening: {error}")
        })?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "{config_path:?} is not a regular file; refusing to harden a symlinked or \
                 special config"
            ));
        }
        let original = fs::read(&config_path).map_err(|error| {
            format!("could not read {config_path:?} to snapshot before hardening: {error}")
        })?;
        let original_mode = config_file_mode(&metadata);

        // Durable backup + recovery record BEFORE the swap. If this process
        // dies after the swap, a later run restores config_target from
        // config_backup instead of adopting the hardened minimal config as the
        // original.
        secure_replace(backup_path, &original, 0o600)?;
        flow.config_backup = Some(backup_path.to_string_lossy().into_owned());
        flow.config_target = Some(config_path.to_string_lossy().into_owned());
        flow.config_original_mode = Some(original_mode);
        flow.store(flow_path).map_err(|error| {
            format!("could not persist config-swap recovery record before hardening: {error}")
        })?;

        let hardened = format!(
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\
             \tlogallrefupdates = true\n[remote \"origin\"]\n\turl = {origin_url}\n\
             \tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        )
        .into_bytes();
        secure_replace(&config_path, &hardened, 0o600)?;
        let witness = ConfigWitness::of(&fs::symlink_metadata(&config_path).map_err(|error| {
            format!("could not stat hardened {config_path:?} to witness it: {error}")
        })?);
        Ok(Self {
            config_path,
            original,
            original_mode,
            hardened,
            witness,
            restored: false,
        })
    }

    /// Restores the audited original with its original mode and reports the
    /// outcome. The recovery backup is intentionally NOT removed here: only
    /// after the caller has positively cleared and persisted the recovery
    /// record is the backup safe to delete, so a crash mid-restore never
    /// orphans it. On `RestoreFailed` the target may still hold the hardened
    /// snapshot; `restored` stays false so `Drop` makes a best-effort retry,
    /// and the caller must keep the recovery pointer.
    fn restore(mut self) -> RestoreOutcome {
        let tampered = self.tampered();
        match secure_replace(&self.config_path, &self.original, self.original_mode) {
            Ok(()) => {
                self.restored = true;
                if tampered {
                    RestoreOutcome::Tampered
                } else {
                    RestoreOutcome::Clean
                }
            }
            Err(error) => RestoreOutcome::RestoreFailed(error),
        }
    }

    /// True if the installed snapshot changed in any way during the window:
    /// the file is no longer a regular file, its inode/ctime/mtime/size
    /// witness moved (catching write-then-revert), or its bytes differ.
    fn tampered(&self) -> bool {
        match fs::symlink_metadata(&self.config_path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                if ConfigWitness::of(&metadata) != self.witness {
                    return true;
                }
                fs::read(&self.config_path)
                    .map(|current| current != self.hardened)
                    .unwrap_or(true)
            }
            _ => true,
        }
    }
}

impl Drop for GitConfigGuard {
    fn drop(&mut self) {
        if self.restored {
            return;
        }
        self.restored = true;
        // Best-effort in-memory restore on unwinding/early return. The durable
        // backup file is intentionally left in place: only the terminal
        // success path (or a reconciliation run) removes it.
        if let Err(error) = secure_replace(&self.config_path, &self.original, self.original_mode) {
            eprintln!(
                "omasafe: restoring the original .git/config failed: {error}.\
                 \nInspect the plugin's git configuration manually before re-enabling."
            );
        }
    }
}

/// Reconciles a leftover config-swap backup from an interrupted update. If the
/// record carries a durable backup of the audited original `.git/config`,
/// restore the target from it — idempotent, since the target is either the
/// hardened snapshot from a mid-window death or already the restored original
/// — preserving the recorded original mode, then clear the swap state and
/// remove the backup.
///
/// Fail-closed: any read/restore failure, and a MISSING backup while the
/// record still references one, return `Err`. `restore` never deletes the
/// backup before the cleared record is persisted, so a referenced-but-missing
/// backup is not the normal "already restored" case — it means the target
/// cannot be verified back to the audited original, and the caller must block
/// rather than start a fresh attempt over a possibly still-hardened config.
/// `Ok` means there is nothing left to reconcile.
fn reconcile_config_backup(record: &mut UpdateFlowRecord, flow_path: &Path) -> Result<(), String> {
    let (Some(backup), Some(target)) = (record.config_backup.clone(), record.config_target.clone())
    else {
        return Ok(());
    };
    let backup_path = PathBuf::from(&backup);
    let target_path = PathBuf::from(&target);
    let original = fs::read(&backup_path).map_err(|error| {
        format!(
            "the interrupted update's config backup {backup_path:?} is unavailable ({error}); \
             {target_path:?} cannot be verified back to the audited original and may still hold \
             the hardened snapshot. Inspect it manually and remove {} before retrying.",
            flow_path.display()
        )
    })?;
    let mode = record.config_original_mode.unwrap_or(0o644);
    secure_replace(&target_path, &original, mode).map_err(|error| {
        format!(
            "could not reconcile {target_path:?} from the interrupted update's config backup: \
             {error}. Restore it manually from {backup_path:?} before trusting the plugin."
        )
    })?;
    // Clear and durably persist the record BEFORE deleting the backup — the
    // same ordering as the Clean/Tampered paths. If the process died or the
    // store failed after an early remove_file, the durable record would still
    // reference a now-missing backup and permanently block recovery.
    record.config_backup = None;
    record.config_target = None;
    record.config_original_mode = None;
    record
        .store(flow_path)
        .map_err(|error| format!("could not persist the reconciled recovery record: {error}"))?;
    let _ = fs::remove_file(&backup_path);
    Ok(())
}

/// Atomically installs `bytes` at `path` with mode `mode`, using a random,
/// exclusively-created, non-following temporary in the SAME directory, then
/// fsync + rename + parent fsync. `create_new` (O_CREAT|O_EXCL) plus
/// O_NOFOLLOW means a pre-planted symlink or file at the temp path fails the
/// open instead of being followed or overwritten — closing the predictable
/// temp-name symlink-overwrite hole. The random name also denies an attacker a
/// predictable path to squat.
fn secure_replace(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| format!("{path:?} has no parent directory"))?;
    let mut last_error: Option<String> = None;
    for _ in 0..8 {
        let temp = dir.join(format!(
            ".omasafe-cfg.{:016x}{:016x}",
            random_u64(),
            random_u64()
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(mode)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = match options.open(&temp) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(error.to_string());
                continue;
            }
            Err(error) => {
                return Err(format!("could not create config temp in {dir:?}: {error}"));
            }
        };
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&temp);
            return Err(format!("could not write config temp {temp:?}: {error}"));
        }
        drop(file);
        if let Err(error) = fs::rename(&temp, path) {
            let _ = fs::remove_file(&temp);
            return Err(format!(
                "could not install config snapshot at {path:?}: {error}"
            ));
        }
        // The rename is not durably committed until the parent directory is
        // fsync'd; a failure here means the swap/backup may not survive power
        // loss, so it must be reported rather than swallowed.
        sync_dir(dir).map_err(|error| {
            format!("could not fsync {dir:?} after installing {path:?}: {error}")
        })?;
        return Ok(());
    }
    Err(format!(
        "could not create a unique config temp in {dir:?}: {}",
        last_error.unwrap_or_else(|| "exhausted attempts".into())
    ))
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

#[cfg(unix)]
fn config_file_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn config_file_mode(_metadata: &fs::Metadata) -> u32 {
    0o644
}

/// 64 bits from the OS CSPRNG for unpredictable temp names. Falls back to a
/// time/PID mix only if `getrandom` is unavailable; `create_new` still
/// guarantees exclusivity regardless of name quality.
fn random_u64() -> u64 {
    #[cfg(unix)]
    {
        let mut buffer = [0u8; 8];
        let read =
            unsafe { libc::getrandom(buffer.as_mut_ptr() as *mut libc::c_void, buffer.len(), 0) };
        if read == buffer.len() as isize {
            return u64::from_ne_bytes(buffer);
        }
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ ((std::process::id() as u64) << 32)
}

fn review_update(id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut yes = false;
    let mut expected_commit: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--yes" => {
                yes = true;
                index += 1;
            }
            "--expected-commit" => {
                let value = next_value(args, index, "expected commit")?;
                if !valid_commit(value) {
                    return Err(format!(
                        "--expected-commit must be a full hex commit SHA, got: {value}"
                    )
                    .into());
                }
                expected_commit = Some(value.to_owned());
                index += 2;
            }
            value => return Err(format!("unknown review-update argument: {value}").into()),
        }
    }
    if yes && expected_commit.is_none() {
        // v0.1 unattended-trust rule: --yes alone never decides WHAT to trust.
        return Err(
            "--yes requires --expected-commit SHA: unattended updates must pin the exact reviewed commit"
                .into(),
        );
    }

    sweep_orphaned_review_checkouts();
    interruption_checkpoint("before evaluation started")?;

    let paths = XdgPaths::discover()?;
    paths.ensure()?;
    let flow_path = paths.state.join("review-update.json");
    match UpdateFlowRecord::load(&flow_path) {
        Ok(Some(mut record)) if record.plugin_id != id => {
            // One in-flight update at a time: another plugin's unresolved
            // record must never be overwritten or deleted by this run. Still
            // reconcile a leftover config swap so that plugin's .git/config is
            // never left as the hardened minimal snapshot; the record itself
            // is kept for the operator to resolve.
            if let Err(error) = reconcile_config_backup(&mut record, &flow_path) {
                eprintln!("omasafe: {error}");
            }
            eprintln!(
                "an interrupted reviewed update for '{}' (candidate {}, phase {}) is still unresolved;\n\
                 resolve it first — see its manual checks below — before reviewing a different plugin.",
                record.plugin_id, record.candidate_commit, record.phase
            );
            return Err(format!(
                "unresolved interrupted update for {} blocks this operation",
                record.plugin_id
            )
            .into());
        }
        Ok(Some(mut record)) => {
            // Same plugin: reconcile any leftover config swap back to the
            // audited original BEFORE proceeding. If reconciliation cannot
            // verify the target back to the audited original, block the fresh
            // attempt — otherwise it would overwrite the recovery record and
            // backup while the installed config may still be the hardened
            // snapshot.
            if let Err(error) = reconcile_config_backup(&mut record, &flow_path) {
                eprintln!(
                    "omasafe: refusing a fresh attempt for '{}': {error}",
                    record.plugin_id
                );
                return Err("unresolved config-swap recovery blocks this reviewed update".into());
            }
            eprintln!(
                "WARNING: an interrupted reviewed update for '{}' was found\n  candidate commit: {}\n  phase at interruption: {} (started {})\n  quiescing actions taken before it stopped: {}",
                record.plugin_id,
                record.candidate_commit,
                record.phase,
                record.started_at,
                if record.quiesced.is_empty() {
                    "none".to_owned()
                } else {
                    record.quiesced.join(", ")
                },
            );
            eprintln!(
                "  manual checks before trusting this plugin again:\n    - omarchy plugin list --json   (is the plugin enabled? which HEAD?)\n    - git -C ~/.config/omarchy/plugins/{0} log --oneline -3\n    - omarchy plugin validate ~/.config/omarchy/plugins/{0}\n  restore service only after HEAD matches a reviewed commit:\n    - omarchy plugin enable {0}   (or: omarchy bar use {0})",
                record.plugin_id
            );
            eprintln!("  proceeding with a fresh attempt; the stale record is replaced on success");
        }
        Ok(None) => {}
        Err(error) => {
            return Err(format!(
                "interrupted-update record at {} is unreadable ({error}); inspect and remove it manually before running a reviewed update",
                flow_path.display()
            )
            .into());
        }
    }

    // --- Pre-flight: refuse before anything mutates ---
    let plugin_root = plugin_root()?;
    let (shell_json, _shell_error) = query_shell();
    let inventory = collect_one(&plugin_root, id, shell_json.as_deref());
    let record = inventory
        .plugins
        .iter()
        .find(|plugin| plugin.id == id)
        .ok_or_else(|| format!("plugin not found: {id}"))?;

    if record.dirty == Some(true) {
        return Err(
            "refusing: installed worktree is dirty; commit or clean local changes before a reviewed update"
                .into(),
        );
    }
    if record.dirty.is_none() {
        return Err(
            "refusing: installed worktree git status is unavailable, so a safe update cannot be guaranteed"
                .into(),
        );
    }

    let history_path = paths.state.join("trust-history.json");
    let _history_lock = lock_state(&history_path)?;
    let mut history = TrustHistory::load(&history_path)?;
    let baseline = history
        .latest(id)
        .ok_or_else(|| format!("no trusted baseline for {id}; run plugins trust first"))?
        .accepted
        .clone();

    let full_bar_active = record.active == Some(true)
        && record.kinds.iter().any(|kind| kind == "bar")
        || inventory.active_full_bars.iter().any(|bar| bar == id);
    let was_enabled = record.enabled.unwrap_or(false);

    // --- Candidate resolution: exact commit or explicit pin, never HEAD-text ---
    let url = record
        .repository
        .clone()
        .filter(|value| value.starts_with("https://"))
        .ok_or("refusing: plugin origin is missing or not an HTTPS repository")?;
    let registry_note;
    let candidate = match &expected_commit {
        Some(commit) => {
            registry_note = format!("candidate pinned via --expected-commit ({commit})");
            commit.clone()
        }
        None => {
            let snapshot = load_cached_catalog(&paths.cache)?.ok_or(
                "no cached catalog snapshot; run marketplace refresh or pass --expected-commit",
            )?;
            let correlation = correlate(
                id,
                record.repository.as_deref(),
                record.head.as_deref(),
                &snapshot,
            );
            let claim = correlation
                .registry_claim
                .as_ref()
                .and_then(|claim| claim.upstream_observed_commit.clone());
            match claim {
                Some(commit)
                    if matches!(correlation.status.as_str(), "listed" | "installed-differs") =>
                {
                    registry_note = format!(
                        "registry claim from catalog commit {} (correlation: {})",
                        snapshot.repository_commit, correlation.status
                    );
                    commit
                }
                _ => {
                    return Err(format!(
                        "no pinned registry claim available (correlation status: {}); pass --expected-commit to pin the candidate explicitly",
                        correlation.status
                    )
                    .into());
                }
            }
        }
    };
    if Some(candidate.as_str()) == record.head.as_deref() {
        println!("Already at pinned commit {candidate}; nothing to update.");
        return Ok(());
    }

    // --- Fetch the exact candidate into the bounded analysis cache ---
    let cache_root = paths.cache.join("analysis");
    let bare = omasafe_analyzer::ensure_pinned_repository(&cache_root, &url, &candidate)
        .map_err(|error| format!("candidate fetch failed: {error}"))?;
    let baseline_head_available = baseline
        .head
        .as_deref()
        .filter(|head| *head != candidate)
        .map(|head| omasafe_analyzer::ensure_pinned_repository(&cache_root, &url, head).is_ok())
        .unwrap_or(false);

    // Materialize a working tree for validation + filesystem analysis.
    let checkout_path = std::env::temp_dir().join(format!(
        "omasafe-review-update-{}-{}",
        id.replace(['/', ':', ' '], "_"),
        std::process::id()
    ));
    let checkout = TempCandidate::create(checkout_path)
        .map_err(|error| format!("candidate checkout failed: {error}"))?;
    bounded_git(
        None,
        &["init", "--quiet", checkout.0.to_string_lossy().as_ref()],
    )
    .map_err(|error| format!("candidate checkout failed: {error}"))?;
    bounded_git(
        Some(&checkout.0),
        &[
            "fetch",
            "--quiet",
            bare.to_string_lossy().as_ref(),
            &candidate,
        ],
    )
    .map_err(|error| format!("candidate checkout failed: {error}"))?;
    bounded_git(
        Some(&checkout.0),
        &["checkout", "--quiet", "--detach", "FETCH_HEAD"],
    )
    .map_err(|error| format!("candidate checkout failed: {error}"))?;
    // Shape the candidate's .git/config exactly like an installed clone:
    // source-identity verification byte-compares security-relevant git
    // metadata, and the installed repository legitimately carries the
    // production HTTPS remote. Refspecs stay identical because both write
    // through a standard `origin` remote.
    bounded_git(
        Some(&checkout.0),
        &["remote", "add", "origin", bare.to_string_lossy().as_ref()],
    )
    .map_err(|error| format!("candidate checkout failed: {error}"))?;
    bounded_git(
        Some(&checkout.0),
        &["remote", "set-url", "origin", url.as_str()],
    )
    .map_err(|error| format!("candidate checkout failed: {error}"))?;
    if baseline_head_available && let Some(head) = baseline.head.as_deref() {
        let _ = bounded_git(
            Some(&checkout.0),
            &["fetch", "--quiet", bare.to_string_lossy().as_ref(), head],
        );
    }

    // Native-parity manifest validation on the candidate BEFORE any mutation.
    let issues = omasafe_marketplace::manifest::validate_plugin_folder(&checkout.0);
    if !issues.is_empty() {
        for issue in &issues {
            eprintln!("manifest issue: {}: {}", issue.code, issue.message);
        }
        return Err(format!(
            "refusing before mutation: candidate {candidate} fails native manifest validation ({} issue(s))",
            issues.len()
        )
        .into());
    }

    // Candidate analysis (same pipeline as scan --include-analysis).
    let ingest = omasafe_analyzer::ingest_filesystem(
        &checkout.0,
        omasafe_analyzer::Limits::default(),
        omasafe_core::bounds::TimeBudget::default(),
    );
    let mut candidate_inventory =
        ingest.map_err(|error| format!("candidate analysis failed: {error}"))?;
    let reader = pinned_filesystem_reader(checkout.0.clone());
    let budget = omasafe_core::bounds::TimeBudget::default();
    let artifacts = omasafe_analyzer::analyze_inventory(&mut candidate_inventory, &reader, &budget);
    let finding_rule_ids: Vec<String> = artifacts
        .rendered_findings()
        .into_iter()
        .map(|finding| finding.rule_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let capability_kinds: Vec<String> = artifacts
        .capabilities
        .iter()
        .map(|capability| capability.capability.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let candidate_fingerprint =
        omasafe_analyzer::fingerprint_analysis(&artifacts.results, &artifacts.capabilities);
    let candidate_policy: String =
        serde_json::to_string(&serde_json::to_value(omasafe_analyzer::policy_identity())?)?;
    let mut candidate_coverage: Vec<String> = candidate_inventory
        .limitations
        .iter()
        .chain(artifacts.limitations.iter())
        .cloned()
        .collect();
    candidate_coverage.sort();
    candidate_coverage.dedup();

    let tree = bounded_git(
        Some(&bare),
        &["rev-parse", &format!("{candidate}^{{tree}}")],
    )
    .ok();
    let candidate_identity = source_identity(
        id,
        &checkout.0,
        Some(url.clone()),
        Some(candidate.clone()),
        tree.clone(),
    );

    interruption_checkpoint("after candidate evaluation")?;

    // --- Delta versus the trusted baseline ---
    let previous_event = ScanState::load(&paths.state.join("scan-state.json"))
        .ok()
        .and_then(|state| state.analysis_events.get(id).cloned());
    let set_delta = |candidate_set: &[String], previous_set: &[String]| {
        (
            candidate_set
                .iter()
                .filter(|item| !previous_set.contains(item))
                .cloned()
                .collect::<Vec<_>>(),
            previous_set
                .iter()
                .filter(|item| !candidate_set.contains(item))
                .cloned()
                .collect::<Vec<_>>(),
        )
    };
    let empty: Vec<String> = Vec::new();
    let (previous_rules, previous_caps) = match &previous_event {
        Some(event) => (&event.finding_rule_ids, &event.capability_kinds),
        None => (&empty, &empty),
    };
    let (added_rules, removed_rules) = set_delta(&finding_rule_ids, previous_rules);
    let (added_capabilities, removed_capabilities) = set_delta(&capability_kinds, previous_caps);

    let diff = if baseline_head_available {
        let head = baseline.head.clone().unwrap_or_default();
        git_diff(&checkout.0, &head, &candidate)
    } else {
        DiffResult {
            available: false,
            text: None,
            truncated: false,
            limitation: Some("trusted HEAD could not be fetched into the cache".to_owned()),
        }
    };

    // --- Preview ---
    println!("Reviewed update preview for {id}");
    println!("  {registry_note}");
    println!(
        "  trusted baseline: HEAD {}",
        baseline.head.as_deref().unwrap_or("(unknown)")
    );
    println!("  candidate:        HEAD {candidate}");
    match (&baseline.content_digest, &candidate_identity.content_digest) {
        (Some(old), Some(new)) if old != new => {
            println!("  content digest changes: {old} -> {new}");
        }
        (Some(_), Some(_)) => println!("  content digest unchanged"),
        _ => {}
    }
    if added_rules.is_empty() && removed_rules.is_empty() {
        println!("  findings: no rule-id delta versus the last recorded analysis");
    } else {
        if !added_rules.is_empty() {
            println!("  NEW findings since last recorded analysis:");
            for rule in &added_rules {
                println!("    + {rule}");
            }
        }
        if !removed_rules.is_empty() {
            println!("  resolved findings:");
            for rule in &removed_rules {
                println!("    - {rule}");
            }
        }
    }
    if !added_capabilities.is_empty() {
        println!("  new capabilities: {}", added_capabilities.join(", "));
    }
    if !removed_capabilities.is_empty() {
        println!(
            "  capabilities no longer observed: {}",
            removed_capabilities.join(", ")
        );
    }
    if previous_event.is_none() {
        println!(
            "  note: no prior recorded analysis event for this plugin; deltas compare against an empty baseline"
        );
    }
    if diff.available {
        let text = diff.text.as_deref().unwrap_or("");
        println!(
            "  source diff (trusted..candidate): {} bytes{}",
            text.len(),
            if diff.truncated { ", TRUNCATED" } else { "" }
        );
        println!("{text}");
    } else {
        println!("  source diff unavailable: trusted HEAD could not be fetched into the cache");
    }
    for limitation in candidate_inventory
        .limitations
        .iter()
        .chain(artifacts.limitations.iter())
    {
        println!("  coverage limitation: {limitation}");
    }

    // --- Approval gate: unattended updates must pin the exact commit ---
    if yes {
        let expected = expected_commit.as_deref().ok_or(
            "--yes requires --expected-commit SHA: unattended updates must pin the exact reviewed commit",
        )?;
        if expected != candidate {
            return Err(format!(
                "--expected-commit {expected} does not match the evaluated candidate {candidate}"
            )
            .into());
        }
    } else {
        if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
            return Err(
                "interactive review-update requires a terminal; use --yes with --expected-commit"
                    .into(),
            );
        }
        eprint!("Type 'update' to apply exactly commit {candidate}: ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if omasafe_core::interrupt::raised() {
            return Err(interrupted("during confirmation"));
        }
        if answer.trim() != "update" {
            return Err("update rejected; nothing was modified".into());
        }
    }

    interruption_checkpoint("before approval was recorded")?;

    // --- Recovery record is durably stored BEFORE any quiescing action ---
    // From here until a terminal state, every exit keeps this file so an
    // operator always finds actionable state, even after a hard death.
    let mut flow = UpdateFlowRecord {
        schema_version: 1,
        plugin_id: id.to_owned(),
        candidate_commit: candidate.clone(),
        started_at: now(),
        phase: "quiescing".into(),
        quiesced: Vec::new(),
        config_backup: None,
        config_target: None,
        config_original_mode: None,
    };
    flow.store(&flow_path)?;

    // Quiesce: switch an active full-bar replacement back to the default bar,
    // disable ordinary enabled plugins, so native rollback can never leave
    // new code live without a completed review.
    if full_bar_active {
        let outcome = omarchy_bar_use_default();
        flow.quiesced.push("bar-switched".into());
        if !outcome.success {
            flow.phase = "failed".into();
            flow.store(&flow_path)?;
            eprintln!(
                "switching back to the default bar failed or was interrupted;\n\
                 the bar state is uncertain. Check 'omarchy plugin list --json'\n\
                 and restore your preferred bar manually before retrying."
            );
            return Err(interrupted(&format!(
                "while switching back to the default bar: {}",
                outcome.output
            )));
        }
        flow.store(&flow_path)?;
    } else if was_enabled {
        let outcome = omarchy_plugin_disable(id);
        flow.quiesced.push("disabled".into());
        if !outcome.success {
            flow.phase = "failed".into();
            flow.store(&flow_path)?;
            eprintln!(
                "disabling failed or was interrupted; the enabled state is uncertain.\n\
                 Check 'omarchy plugin list --json' before retrying."
            );
            return Err(interrupted(&format!(
                "while disabling the plugin: {}",
                outcome.output
            )));
        }
        flow.store(&flow_path)?;
    }
    flow.phase = "auditing".into();
    flow.store(&flow_path)?;
    // --- Pre-mutation audit: native Git must not be allowed to consume the
    // installed repository's hooks or config before OmaSafe audits them. A
    // pre-existing post-merge hook would otherwise EXECUTE during the
    // delegated fetch/merge and only be reported by the postcondition
    // afterwards. Refuse here instead; the postcondition below still repeats
    // the same audit to close the window for changes made during the update,
    // and the updater runs with inherited Git hardening (hooks disabled via
    // injected config; see run_omarchy) so even a hook planted mid-update
    // cannot execute.
    let installed_pre_dir = PathBuf::from(record.path.clone());
    if let Err(failure) = audit_installed_git_state(&installed_pre_dir, &url) {
        flow.phase = "failed".into();
        flow.store(&flow_path)?;
        eprintln!(
            "refused before mutation: the installed repository failed the hook/config audit;\
             \n{failure}\
             \nThe plugin stays disabled and the native updater was not invoked."
        );
        return Err("pre-mutation git state audit failed".into());
    }
    flow.phase = "delegating".into();
    flow.store(&flow_path)?;
    interruption_checkpoint(
        "after quiescing; the plugin stays disabled and the recovery record is kept",
    )?;
    // --- Delegate the mutation; never fork native lifecycle logic ---
    // Native Git consumes the repository-local config for the whole window
    // (fetch URL rewriting, credential helpers, fsmonitor, attribute-driven
    // filter drivers during the checkout); env-injected overrides cannot
    // enumerate subsection-keyed sinks (filter.<name>, url.<base>.insteadOf),
    // so the audited config is swapped for a hardened snapshot for the
    // duration and restored afterwards. See GitConfigGuard.
    let config_backup_path = flow_path.with_extension("config-backup");
    let config_guard = GitConfigGuard::swap_to_hardened(
        &installed_pre_dir,
        &url,
        &config_backup_path,
        &mut flow,
        &flow_path,
    )
    .map_err(|error| format!("update-window config hardening failed: {error}"))?;
    let outcome = omarchy_plugin_update(id);
    match config_guard.restore() {
        RestoreOutcome::Clean => {
            // Original positively reinstalled: drop the recovery pointer.
            // Persist the cleared record BEFORE deleting the backup, so a crash
            // in between never leaves the on-disk record pointing at a deleted
            // backup (which reconciliation would then treat as unresolved).
            flow.config_backup = None;
            flow.config_target = None;
            flow.config_original_mode = None;
            flow.store(&flow_path)?;
            let _ = fs::remove_file(&config_backup_path);
        }
        RestoreOutcome::Tampered => {
            // Original reinstalled, but the window was tampered with. Clear the
            // pointer (the target is restored), persist, then delete the backup
            // and refuse the update.
            flow.config_backup = None;
            flow.config_target = None;
            flow.config_original_mode = None;
            flow.phase = "failed".into();
            flow.store(&flow_path)?;
            let _ = fs::remove_file(&config_backup_path);
            eprintln!(
                "postcondition failed: git configuration was modified during the update window; \
                 the injected change was discarded and never trusted, but the environment must be \
                 treated as hostile. The plugin stays disabled; inspect .git/config and any \
                 running processes before re-running 'plugins review-update'."
            );
            return Err("git configuration modified during the update window".into());
        }
        RestoreOutcome::RestoreFailed(error) => {
            // The original could NOT be reinstalled. KEEP the recovery pointer
            // and backup so the next run reconciles the target; do not delete
            // anything. Persist the failed record with its backup reference
            // intact.
            flow.phase = "failed".into();
            flow.store(&flow_path)?;
            eprintln!(
                "postcondition failed: could not restore the original .git/config after the \
                 update window ({error}). A durable backup of the audited original is preserved \
                 at {backup} and referenced by the recovery record; the next 'plugins \
                 review-update' run will reconcile it. The plugin stays disabled — inspect \
                 .git/config manually before re-enabling.",
                backup = config_backup_path.display()
            );
            return Err("restoring the original .git/config failed after the update".into());
        }
    }
    if !outcome.success && omasafe_core::interrupt::raised() {
        flow.phase = "failed".into();
        flow.store(&flow_path)?;
        eprintln!(
            "interrupted during the native update; the updater was stopped and\n\
             the plugin stays disabled. Inspect manually:\n\
               git -C ~/.config/omarchy/plugins/{id} log --oneline -3\n\
               omarchy plugin validate ~/.config/omarchy/plugins/{id}"
        );
        return Err(interrupted("during the native update"));
    }
    if !outcome.success {
        flow.phase = "failed".into();
        flow.store(&flow_path)?;
        eprintln!("native updater failed:\n{}", outcome.output);
        eprintln!(
            "the plugin is left disabled on purpose; the native updater rolled back via\n\
             'git reset --hard ORIG_HEAD' if validation failed.\n\
             manual recovery:\n\
               git -C ~/.config/omarchy/plugins/{id} log --oneline -3\n\
               omarchy plugin validate ~/.config/omarchy/plugins/{id}\n\
             then re-enable once you have verified the content yourself:\n\
               omarchy plugin enable {id}"
        );
        return Err(format!("native update of {id} failed").into());
    }

    // --- Postconditions: exact HEAD + fresh rescan before anything goes live ---
    if omasafe_core::interrupt::raised() {
        flow.phase = "failed".into();
        flow.store(&flow_path)?;
        eprintln!(
            "interrupted after the native update ran but BEFORE verification;\n\
             the plugin stays disabled. Inspect HEAD manually:\n\
               git -C ~/.config/omarchy/plugins/{id} log --oneline -3\n\
             then re-enable only if it matches a reviewed commit."
        );
        return Err(interrupted("between mutation and verification"));
    }
    flow.phase = "verifying".into();
    flow.store(&flow_path)?;
    let (fresh_shell_json, fresh_shell_error) = query_shell();
    let fresh_json = match fresh_shell_json {
        Some(json) => json,
        None => {
            flow.phase = "failed".into();
            flow.store(&flow_path)?;
            eprintln!(
                "post-update rescan could not be read ({}); the plugin stays disabled",
                fresh_shell_error.unwrap_or_else(|| "unknown error".into())
            );
            return Err("rescan verification failed after update".into());
        }
    };
    let updated = collect_one(&plugin_root, id, Some(fresh_json.as_str()));
    let updated_record = updated.plugins.iter().find(|plugin| plugin.id == id);
    let Some(updated_record) = updated_record else {
        flow.phase = "failed".into();
        flow.store(&flow_path)?;
        eprintln!(
            "postcondition failed: plugin vanished from the inventory after update; \
             inspect 'omarchy plugin list --json' and the plugin folder manually"
        );
        return Err("rescan verification failed after update".into());
    };
    if updated_record.head.as_deref() != Some(candidate.as_str()) {
        flow.phase = "failed".into();
        flow.store(&flow_path)?;
        eprintln!(
            "raced candidate detected: installed HEAD is {:?}, not the reviewed commit {candidate}.\
             \nThe native updater has no expected-SHA guard yet, so another push won the race;\
             \nthe plugin stays disabled. Inspect the new HEAD manually and either re-run\n\
             'plugins review-update' against it or restore the reviewed state with\n\
             'git -C ~/.config/omarchy/plugins/{id} reset --hard {candidate}'",
            updated_record.head
        );
        return Err("installed HEAD does not match the reviewed commit".into());
    }
    if updated_record.dirty != Some(false) {
        flow.phase = "failed".into();
        flow.store(&flow_path)?;
        if updated_record.dirty.is_none() {
            eprintln!(
                "postcondition failed: installed worktree git status is unavailable after the\n\
                 update, so a safe re-enable cannot be guaranteed. The plugin stays disabled.\n\
                 Inspect and resolve it manually:\n\
                   git -C ~/.config/omarchy/plugins/{id} status\n\
                 then re-run 'plugins review-update' once 'git status' works again."
            );
        } else {
            eprintln!(
                "postcondition failed: local changes appeared in the worktree during the update;\n\
                 the plugin stays disabled. Inspect them manually:\n\
                   git -C ~/.config/omarchy/plugins/{id} status\n\
                   git -C ~/.config/omarchy/plugins/{id} diff\n\
                 either restore the reviewed tree ('git -C ~/.config/omarchy/plugins/{id}\n\
                 reset --hard {candidate}') or re-enable only after verifying the content yourself."
            );
        }
        return Err("installed worktree is not verified clean after the update".into());
    }

    // --- Verify the INSTALLED tree against the approved candidate ---
    // Trust may only advance from what is actually on disk under
    // ~/.config/omarchy/plugins, never from the temporary checkout. Layers:
    //   1. Byte equality via SourceIdentity's audited bounded collector over
    //      the WORKTREE (tracked, ignored, and hidden files alike). Git
    //      internals that legitimately differ between a detached review
    //      checkout and a branch-based installed clone (.git/HEAD,
    //      packed-refs, template hook samples, .git/config, the flow-owned
    //      .owner.lock) are exempt from BYTES and verified semantically
    //      below instead.
    //   2. Resolved git identity: installed HEAD (already pinned to the
    //      candidate) and installed HEAD^{tree} must equal the candidate's
    //      tree object, so HEAD/packed-refs divergence cannot hide content.
    //   3. Active-hook audit: every .git/hooks entry must be a regular
    //      `*.sample` template file; anything else is a live hook and fails.
    //   4. Config allowlist: .git/config parsed by Git itself under bounded
    //      hardened settings; only known-benign repository-local keys pass.
    //   5. Exhaustive-collection gate: ANY SourceIdentity limitation on
    //      either side (file_limit, unreadable*, oversize, aggregate,
    //      depth/entry caps, hooks unreadable, budget, interruption) fails
    //      closed — a partial digest map can never prove byte equality.
    let installed_dir = PathBuf::from(updated_record.path.clone());
    let installed_tree = bounded_git(Some(&installed_dir), &["rev-parse", "HEAD^{tree}"]).ok();
    let installed_identity = source_identity(
        id,
        &installed_dir,
        updated_record.repository.clone(),
        updated_record.head.clone(),
        installed_tree.clone(),
    );
    if !candidate_identity.limitations.is_empty() || !installed_identity.limitations.is_empty() {
        flow.phase = "failed".into();
        flow.store(&flow_path)?;
        eprintln!(
            "postcondition failed: identity collection lost coverage (candidate: {:?},\
             installed: {:?}). A partial digest map cannot prove byte equality with the\
             reviewed candidate {candidate}; the plugin stays disabled and trust does not\
             advance. Resolve the collection limitation and re-run 'plugins review-update'.",
            candidate_identity.limitations, installed_identity.limitations
        );
        return Err("identity collection lost coverage during update verification".into());
    }
    let exempt_from_byte_compare = |key: &str, installed_digest: Option<&String>| -> bool {
        // Byte-different-but-benign git internals; each is verified another way.
        key == ".git/config"
            || key == ".git/HEAD"
            || key == ".git/packed-refs"
            || key.starts_with(".git/hooks/")
            || (key == ".owner.lock" && installed_digest.is_none())
    };
    let mut mismatched_files = Vec::new();
    for key in candidate_identity
        .file_digests
        .keys()
        .chain(installed_identity.file_digests.keys())
    {
        if candidate_identity.file_digests.get(key) != installed_identity.file_digests.get(key)
            && !exempt_from_byte_compare(key, installed_identity.file_digests.get(key))
        {
            mismatched_files.push(key.clone());
        }
    }
    mismatched_files.sort();
    mismatched_files.dedup();
    if !mismatched_files.is_empty() {
        flow.phase = "failed".into();
        flow.store(&flow_path)?;
        eprintln!(
            "postcondition failed: installed bytes differ from the reviewed candidate {candidate}\
             (HEAD matches but {} entr(ies) do not). The plugin stays disabled and trust does not\
             advance. Inspect manually:\
               git -C ~/.config/omarchy/plugins/{id} status --ignored\
               find ~/.config/omarchy/plugins/{id} -type f -o -type l",
            mismatched_files.len()
        );
        for key in mismatched_files.iter().take(10) {
            eprintln!("  differing: {key}");
        }
        return Err("installed bytes differ from the reviewed candidate".into());
    }
    if installed_tree.as_deref() != tree.as_deref() {
        flow.phase = "failed".into();
        flow.store(&flow_path)?;
        eprintln!(
            "postcondition failed: installed tree object is {:?}, not the reviewed tree {:?}.\\
             The plugin stays disabled and trust does not advance. Inspect manually:\\
               git -C ~/.config/omarchy/plugins/{id} rev-parse HEAD^{{tree}}",
            installed_tree, tree
        );
        return Err("installed tree does not match the reviewed candidate tree".into());
    }
    if let Err(failure) = audit_installed_git_state(&installed_dir, &url) {
        flow.phase = "failed".into();
        flow.store(&flow_path)?;
        eprintln!(
            "postcondition failed: the installed repository failed the hook/config audit.\
             \n{failure}\
             \nThe plugin stays disabled and trust does not advance."
        );
        return Err("installed-tree git state failed the post-update audit".into());
    }
    let installed_policy: String =
        serde_json::to_string(&serde_json::to_value(omasafe_analyzer::policy_identity())?)?;
    if installed_policy != candidate_policy {
        flow.phase = "failed".into();
        flow.store(&flow_path)?;
        eprintln!(
            "postcondition failed: analyzer policy identity changed while the update was in\n\
             flight; the approved analysis no longer describes this CLI's policy. The plugin\n\
             stays disabled and trust does not advance. Re-run 'plugins review-update'."
        );
        return Err("analyzer policy identity changed during the update".into());
    }
    let installed_ingest = omasafe_analyzer::ingest_filesystem(
        &installed_dir,
        omasafe_analyzer::Limits::default(),
        omasafe_core::bounds::TimeBudget::default(),
    );
    let mut installed_inventory = match installed_ingest {
        Ok(inventory) => inventory,
        Err(error) => {
            flow.phase = "failed".into();
            flow.store(&flow_path)?;
            eprintln!(
                "postcondition failed: the installed tree could not be analyzed ({error});\n\
                 trust will not advance and the plugin stays disabled."
            );
            return Err("installed-tree analysis failed after update".into());
        }
    };
    let installed_reader = pinned_filesystem_reader(installed_dir.clone());
    let budget = omasafe_core::bounds::TimeBudget::default();
    let installed_artifacts =
        omasafe_analyzer::analyze_inventory(&mut installed_inventory, &installed_reader, &budget);
    let installed_fingerprint = omasafe_analyzer::fingerprint_analysis(
        &installed_artifacts.results,
        &installed_artifacts.capabilities,
    );
    let mut installed_coverage: Vec<String> = installed_inventory
        .limitations
        .iter()
        .chain(installed_artifacts.limitations.iter())
        .cloned()
        .collect();
    installed_coverage.sort();
    installed_coverage.dedup();
    if installed_coverage != candidate_coverage {
        flow.phase = "failed".into();
        flow.store(&flow_path)?;
        eprintln!(
            "postcondition failed: coverage state of the installed tree differs from the\n\
             approved candidate analysis (candidate: {:?}, installed: {:?}). The plugin stays\n\
             disabled and trust does not advance.",
            candidate_coverage, installed_coverage
        );
        return Err("installed-tree coverage state differs from the approved candidate".into());
    }
    if installed_fingerprint != candidate_fingerprint {
        flow.phase = "failed".into();
        flow.store(&flow_path)?;
        eprintln!(
            "postcondition failed: analysis fingerprint of the installed tree differs from the\n\
             approved candidate despite identical bytes; nondeterminism or tampering is\n\
             suspected. The plugin stays disabled and trust does not advance."
        );
        return Err(
            "installed-tree analysis fingerprint differs from the approved candidate".into(),
        );
    }

    if omasafe_core::interrupt::raised() {
        // Verified content is installed, but service restore and the trust
        // advance are deliberate operator actions when the flow stops here.
        flow.phase = "verifying".into();
        flow.store(&flow_path)?;
        eprintln!(
            "interrupted after verification passed and before re-enable/trust.\n\
             The reviewed commit {candidate} IS installed and verified.\n\
             Manual completion:\n\
               omarchy plugin enable {id}\n\
               omasafe-cli plugins review {id} --action rebaseline --yes \\\n\
                 --expected-head {candidate} --reason 'complete interrupted review'"
        );
        return Err(interrupted("between verification and re-enable"));
    }

    // --- Restore availability, then trust the verified identity ---
    if full_bar_active || was_enabled {
        let enable_outcome = omarchy_plugin_enable(id);
        if !enable_outcome.success {
            if omasafe_core::interrupt::raised() {
                flow.phase = "verifying".into();
                flow.store(&flow_path)?;
                eprintln!(
                    "interrupted while re-enabling; the reviewed commit {candidate} IS\n\
                     installed and verified, but service restore did not complete.\n\
                     Manual completion:\n\
                       omarchy plugin enable {id}"
                );
                return Err(interrupted("during re-enable"));
            }
            eprintln!(
                "warning: re-enabling failed ({}); the reviewed commit is installed but the plugin stays disabled.\nmanual step: omarchy plugin enable {id}",
                enable_outcome.output
            );
        }
    }

    history.accept(TrustRecord {
        plugin_id: id.to_owned(),
        accepted: installed_identity,
        accepted_at: now(),
        note: format!("reviewed update to {candidate}"),
    });
    history.write_atomic_locked(&history_path)?;

    let _ = std::fs::remove_file(&flow_path);
    let _ = std::fs::remove_file(&config_backup_path);
    println!(
        "Reviewed update complete: {id} is at reviewed commit {candidate}; trust baseline advanced."
    );
    Ok(())
}

/// Bounded argv-only local git invocation with scrubbed config, returning
/// trimmed stdout on success.
fn bounded_git(dir: Option<&Path>, args: &[&str]) -> Result<String, String> {
    let mut command = omasafe_core::git::command();
    command.args(args.to_vec());
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    match omasafe_core::bounds::run_bounded_capped(
        &mut command,
        omasafe_core::bounds::GIT_PROCESS_BUDGET,
        omasafe_core::bounds::MAX_PROCESS_OUTPUT_BYTES_PER_STREAM,
    ) {
        Ok(Some(captured)) if captured.status.success() && !captured.truncated => {
            Ok(String::from_utf8_lossy(&captured.stdout).trim().to_owned())
        }
        Ok(Some(captured)) => Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&captured.stderr).trim()
        )),
        _ => Err(format!("git {} did not complete", args.join(" "))),
    }
}

#[derive(Clone, serde::Serialize)]
struct ScanAlert {
    plugin_id: String,
    kind: String,
    /// The confidence/impact level of the signal, not a claim that a plugin is safe.
    /// v0.1 emits review-needed warnings; later analysis can emit critical findings.
    severity: String,
    message: String,
    post_change: bool,
}

#[derive(serde::Serialize)]
struct ScanResult {
    alerts: Vec<ScanAlert>,
    quiet: bool,
    outstanding: usize,
    new: usize,
    highest_severity: String,
    post_change_detection: bool,
}

fn scan(args: &[String]) -> Result<bool, Box<dyn std::error::Error>> {
    let mut format = "text";
    let mut notify = false;
    let mut only_new = false;
    let mut include_analysis = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--notify" => {
                notify = true;
                index += 1;
            }
            "--only-new" => {
                only_new = true;
                index += 1;
            }
            "--include-analysis" => {
                include_analysis = true;
                index += 1;
            }
            "--format" => {
                format = next_value(args, index, "format")?;
                index += 2;
            }
            value => return Err(format!("unknown scan argument: {value}").into()),
        }
    }
    if !matches!(format, "text" | "json") {
        return Err(format!("unsupported format: {format}").into());
    }
    let paths = XdgPaths::discover()?;
    paths.ensure()?;
    let plugin_root = plugin_root()?;
    let (shell_json, shell_error) = query_shell();
    let mut inventory = collect(&plugin_root, shell_json.as_deref());
    if let Some(error) = shell_error {
        inventory.coverage.limitations.push(error);
    }
    let history_path = paths.state.join("trust-history.json");
    let _history_lock = lock_state(&history_path)?;
    let mut history_recovered = false;
    let history = match TrustHistory::load(&history_path) {
        Ok(history) => history,
        Err(error) => {
            let corrupt = history_path.with_extension(format!("corrupt-{}", now_nanos()));
            std::fs::rename(&history_path, &corrupt)?;
            eprintln!(
                "omasafe: trust history was corrupt and moved to {}; scanning without baselines: {error}",
                corrupt.display()
            );
            history_recovered = true;
            TrustHistory::default()
        }
    };
    let state_path = paths.state.join("scan-state.json");
    let _state_lock = lock_state(&state_path)?;
    let mut state = match ScanState::load(&state_path) {
        Ok(state) => state,
        Err(error) => {
            let corrupt = state_path.with_extension(format!("corrupt-{}", now_nanos()));
            let _ = std::fs::rename(&state_path, corrupt);
            eprintln!("omasafe: scan state was corrupt and has been reset: {error}");
            ScanState::default()
        }
    };
    let mut alerts = Vec::new();
    let mut new_alerts = Vec::new();
    let mut live_keys = BTreeSet::new();
    let mut highest_severity = "none".to_owned();
    if history_recovered {
        let key = "coverage:trust-history".to_owned();
        live_keys.insert(key.clone());
        let alert = ScanAlert {
            plugin_id: "trust-history".into(),
            kind: "lost-coverage".into(),
            severity: "warning".into(),
            message: "trust history was corrupt and quarantined; baselines require recovery".into(),
            post_change: false,
        };
        track_highest_severity(&mut highest_severity, &alert);
        let is_new = state.is_new(&key);
        if is_new {
            new_alerts.push(alert.clone());
        }
        if is_new && notify {
            notify_user(&alert);
            state.record(key, now());
        }
        if !only_new || is_new {
            alerts.push(alert);
        }
    }
    for plugin in &inventory.plugins {
        // Backups are retained in inventory for audit visibility but are not
        // installed targets. Scanning them would duplicate live-plugin IDs
        // when their copied manifests match an active shell plugin.
        if plugin.classification == "backup" {
            continue;
        }
        if plugin.classification == "unscannable"
            && !is_excluded(&history, &plugin.id, "lost-coverage")
        {
            let key = format!("coverage:{}", plugin.id);
            live_keys.insert(key.clone());
            let alert = ScanAlert {
                plugin_id: plugin.id.clone(),
                kind: "lost-coverage".into(),
                severity: "warning".into(),
                message: "plugin can no longer be scanned".into(),
                post_change: false,
            };
            track_highest_severity(&mut highest_severity, &alert);
            let is_new = state.is_new(&key);
            if is_new {
                new_alerts.push(alert.clone());
            }
            if is_new && notify {
                {
                    notify_user(&alert);
                    state.record(key, now());
                }
            }
            if !only_new || is_new {
                alerts.push(alert);
            }
            continue;
        }
        if !plugin.limitations.is_empty() && !is_excluded(&history, &plugin.id, "lost-coverage") {
            let key = format!("partial:{}", plugin.id);
            live_keys.insert(key.clone());
            let alert = ScanAlert {
                plugin_id: plugin.id.clone(),
                kind: "lost-coverage".into(),
                severity: "warning".into(),
                message: format!(
                    "plugin coverage is partial: {}",
                    plugin.limitations.join(", ")
                ),
                post_change: false,
            };
            track_highest_severity(&mut highest_severity, &alert);
            let is_new = state.is_new(&key);
            if is_new {
                new_alerts.push(alert.clone());
            }
            if is_new && notify {
                notify_user(&alert);
                state.record(key, now());
            }
            if !only_new || is_new {
                alerts.push(alert);
            }
        }
        let trusted = history.latest(&plugin.id).map(|record| &record.accepted);
        let current = SourceIdentity {
            plugin_id: plugin.id.clone(),
            repository: plugin.repository.clone(),
            head: plugin.head.clone(),
            tree: plugin.tree.clone(),
            content_digest: plugin.content_digest.clone(),
            file_count: plugin.content_file_count.unwrap_or_default(),
            limitations: plugin.limitations.clone(),
            file_digests: plugin.file_digests.clone(),
        };
        if let Some(trusted) = trusted
            && current != *trusted
            && !is_excluded(&history, &plugin.id, "source-drift")
        {
            let key = drift_key(&plugin.id, trusted, &current);
            live_keys.insert(key.clone());
            let alert = ScanAlert {
                plugin_id: plugin.id.clone(),
                kind: "source-drift".into(),
                severity: "warning".into(),
                message: if is_acknowledged(&history, &plugin.id, "source-drift") {
                    "installed source differs from the trusted baseline; previously acknowledged, review remains available"
                } else {
                    "installed source differs from the trusted baseline; review is required"
                }.into(),
                post_change: true,
            };
            track_highest_severity(&mut highest_severity, &alert);
            let is_new = state.is_new(&key);
            if is_new {
                new_alerts.push(alert.clone());
            }
            if is_new && notify {
                notify_user(&alert);
                state.record(key, now());
            }
            if !only_new || is_new {
                alerts.push(alert);
            }
        }
    }
    for trusted in history
        .records
        .iter()
        .filter(|record| !record.plugin_id.is_empty() && !history.is_revoked(&record.plugin_id))
    {
        if !inventory
            .plugins
            .iter()
            .any(|plugin| plugin.id == trusted.plugin_id)
            && !is_excluded(&history, &trusted.plugin_id, "missing-plugin")
        {
            let key = format!("missing:{}", trusted.plugin_id);
            if !live_keys.insert(key.clone()) {
                continue;
            }
            let alert = ScanAlert {
                plugin_id: trusted.plugin_id.clone(),
                kind: "missing-plugin".into(),
                severity: "warning".into(),
                message: "trusted plugin is missing or unavailable".into(),
                post_change: true,
            };
            track_highest_severity(&mut highest_severity, &alert);
            let is_new = state.is_new(&key);
            if is_new {
                new_alerts.push(alert.clone());
            }
            if is_new && notify {
                notify_user(&alert);
                state.record(key, now());
            }
            if !only_new || is_new {
                alerts.push(alert);
            }
        }
    }
    if inventory
        .coverage
        .limitations
        .iter()
        .any(|limitation| !limitation.starts_with("shell reports plugin "))
    {
        let key = "coverage:inventory".to_owned();
        live_keys.insert(key.clone());
        let is_new = state.is_new(&key);
        let alert = ScanAlert {
            plugin_id: "inventory".into(),
            kind: "lost-coverage".into(),
            severity: "warning".into(),
            message: "inventory coverage is limited; review the scan report".into(),
            post_change: false,
        };
        track_highest_severity(&mut highest_severity, &alert);
        if is_new {
            new_alerts.push(alert.clone());
        }
        if is_new && notify {
            notify_user(&alert);
            state.record(key, now());
        }
        if !only_new || is_new {
            alerts.push(alert);
        }
    }
    for (key, plugin_id, kind, message) in [(
        "bar:replacement",
        inventory.active_full_bar.as_deref().unwrap_or("bar"),
        "bar-replacement",
        "a non-built-in full-bar plugin replaces the OmaSafe bar widget",
    )] {
        if inventory.non_builtin_bar_replaces_bar {
            let key = key.to_owned();
            live_keys.insert(key.clone());
            let alert = ScanAlert {
                plugin_id: plugin_id.to_owned(),
                kind: kind.to_owned(),
                severity: "warning".into(),
                message: message.to_owned(),
                post_change: false,
            };
            track_highest_severity(&mut highest_severity, &alert);
            let is_new = state.is_new(&key);
            if is_new {
                new_alerts.push(alert.clone());
            }
            if is_new && notify {
                notify_user(&alert);
                state.record(key, now());
            }
            if !only_new || is_new {
                alerts.push(alert);
            }
        }
    }
    if inventory.bar_conflict {
        let key = "bar:conflict".to_owned();
        live_keys.insert(key.clone());
        let alert = ScanAlert {
            plugin_id: inventory
                .active_full_bars
                .first()
                .cloned()
                .unwrap_or_else(|| "bar".into()),
            kind: "provenance-conflict".into(),
            severity: "warning".into(),
            message: format!(
                "multiple active full-bar plugins are present: {}",
                inventory.active_full_bars.join(", ")
            ),
            post_change: false,
        };
        track_highest_severity(&mut highest_severity, &alert);
        let is_new = state.is_new(&key);
        if is_new {
            new_alerts.push(alert.clone());
        }
        if is_new && notify {
            notify_user(&alert);
            state.record(key, now());
        }
        if !only_new || is_new {
            alerts.push(alert);
        }
    }
    if let Some(snapshot) = load_cached_catalog(&paths.cache)? {
        let stale = timestamp_age_seconds(&snapshot.retrieved_at)
            .is_some_and(|age| age > 30 * 24 * 60 * 60);
        if !snapshot.verified || stale {
            let key = "coverage:marketplace-cache".to_owned();
            live_keys.insert(key.clone());
            let alert = ScanAlert {
                plugin_id: "marketplace".into(),
                kind: "lost-coverage".into(),
                severity: "warning".into(),
                message: if !snapshot.verified {
                    "cached marketplace snapshot could not be re-verified".into()
                } else {
                    "cached marketplace snapshot is older than 30 days".into()
                },
                post_change: false,
            };
            track_highest_severity(&mut highest_severity, &alert);
            let is_new = state.is_new(&key);
            if is_new {
                new_alerts.push(alert.clone());
            }
            if is_new && notify {
                notify_user(&alert);
                state.record(key, now());
            }
            if !only_new || is_new {
                alerts.push(alert);
            }
        }
        for plugin in &inventory.plugins {
            let correlation = correlate(
                &plugin.id,
                plugin.repository.as_deref(),
                plugin.head.as_deref(),
                &snapshot,
            );
            if correlation.status == "conflict" {
                let key = format!("provenance:{}", plugin.id);
                live_keys.insert(key.clone());
                let alert = ScanAlert {
                    plugin_id: plugin.id.clone(),
                    kind: "provenance-conflict".into(),
                    severity: "warning".into(),
                    message: "installed repository conflicts with the marketplace claim".into(),
                    post_change: false,
                };
                track_highest_severity(&mut highest_severity, &alert);
                let is_new = state.is_new(&key);
                if is_new {
                    new_alerts.push(alert.clone());
                }
                if is_new && notify {
                    notify_user(&alert);
                    state.record(key, now());
                }
                if !only_new || is_new {
                    alerts.push(alert);
                }
            }
        }
    }
    // Opt-in analysis events (S5): source drift, analyzer-policy updates,
    // and fingerprint instability are DISTINCT signals with distinct
    // wording. Default scans never touch this path. Registry/correlation
    // claims cannot clear any of them: classification reads only local
    // identities and locally computed fingerprints. Suppressions do not
    // participate — event classification uses the full stored reality.
    let mut analysis_events_dirty = false;
    if include_analysis {
        // Canonical JSON form (alphabetical object keys via Value) so stored
        // identities compare stably regardless of struct field order.
        let policy_string =
            serde_json::to_string(&serde_json::to_value(omasafe_analyzer::policy_identity())?)?;
        let mut classified_ids: BTreeSet<String> = BTreeSet::new();
        for plugin in &inventory.plugins {
            if !classified_ids.insert(plugin.id.clone()) {
                // Duplicate manifests claiming one id would alias each
                // other's event snapshot and make classification depend on
                // walk order; disclose instead of guessing.
                emit_scan_alert(
                    format!("analysis:{}:duplicate-id", plugin.id),
                    plugin.id.clone(),
                    "lost-coverage",
                    "warning",
                    format!(
                        "multiple installed directories claim plugin id {}; \
                         analysis events are tracked for the first only",
                        plugin.id
                    ),
                    false,
                    notify,
                    only_new,
                    &mut live_keys,
                    &mut alerts,
                    &mut new_alerts,
                    &mut state,
                    &mut highest_severity,
                );
                continue;
            }
            let source_identity = plugin
                .content_digest
                .clone()
                .or_else(|| plugin.tree.clone())
                .unwrap_or_default();
            let ingest = omasafe_analyzer::ingest_filesystem(
                Path::new(&plugin.path),
                omasafe_analyzer::Limits::default(),
                omasafe_core::bounds::TimeBudget::default(),
            );
            let mut plugin_inventory = match ingest {
                Ok(plugin_inventory) => plugin_inventory,
                Err(error) => {
                    emit_scan_alert(
                        format!("analysis:{}:unavailable", plugin.id),
                        plugin.id.clone(),
                        "lost-coverage",
                        "warning",
                        format!("installed plugin could not be analyzed: {error}"),
                        false,
                        notify,
                        only_new,
                        &mut live_keys,
                        &mut alerts,
                        &mut new_alerts,
                        &mut state,
                        &mut highest_severity,
                    );
                    continue;
                }
            };
            let reader = pinned_filesystem_reader(PathBuf::from(&plugin.path));
            let budget = omasafe_core::bounds::TimeBudget::default();
            let artifacts =
                omasafe_analyzer::analyze_inventory(&mut plugin_inventory, &reader, &budget);
            let fingerprint =
                omasafe_analyzer::fingerprint_analysis(&artifacts.results, &artifacts.capabilities);
            let finding_rule_ids: Vec<String> = artifacts
                .rendered_findings()
                .into_iter()
                .map(|finding| finding.rule_id)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let capability_kinds: Vec<String> = artifacts
                .capabilities
                .iter()
                .map(|capability| capability.capability.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();

            let previous = state.analysis_events.get(&plugin.id).cloned();
            // Explicit classification: drift rounds refresh silently and are
            // NEVER eligible for growth alerts (the baseline they would
            // compare against describes pre-drift content).
            enum EventClass {
                Baseline,
                DriftRefresh,
                PolicyUpdate,
                Instability,
                Clean,
            }
            let class = match &previous {
                None => EventClass::Baseline,
                Some(previous) if previous.source_identity != source_identity => {
                    EventClass::DriftRefresh
                }
                Some(previous) if previous.policy_identity != policy_string => {
                    EventClass::PolicyUpdate
                }
                Some(previous) if previous.fingerprint != fingerprint => EventClass::Instability,
                Some(_) => EventClass::Clean,
            };

            // Growth comparison runs whenever a previous snapshot exists for
            // unchanged source — INCLUDING policy-update and instability
            // rounds, where analyzer improvement or nondeterminism most often
            // manifests. First transitions from empty sets alert like any
            // other growth.
            if let Some(previous) = &previous
                && matches!(
                    class,
                    EventClass::PolicyUpdate | EventClass::Instability | EventClass::Clean
                )
            {
                let added_capabilities: Vec<String> = capability_kinds
                    .iter()
                    .filter(|kind| !previous.capability_kinds.contains(kind))
                    .cloned()
                    .collect();
                if !added_capabilities.is_empty() {
                    emit_scan_alert(
                        format!(
                            "analysis:{}:new-capability:{}",
                            plugin.id,
                            added_capabilities.join(",")
                        ),
                        plugin.id.clone(),
                        "new-capability",
                        "warning",
                        format!(
                            "analysis observed new capabilities since the last \
                                 evaluation: {}",
                            added_capabilities.join(", ")
                        ),
                        false,
                        notify,
                        only_new,
                        &mut live_keys,
                        &mut alerts,
                        &mut new_alerts,
                        &mut state,
                        &mut highest_severity,
                    );
                }
                let added_rules: Vec<String> = finding_rule_ids
                    .iter()
                    .filter(|rule| !previous.finding_rule_ids.contains(rule))
                    .cloned()
                    .collect();
                // One alert per added rule with its catalog severity: a High
                // finding must not reach reports and notifications as a
                // generic warning.
                for rule_id in added_rules {
                    let definition = omasafe_analyzer::rule(&rule_id);
                    let (severity, title) = match definition {
                        Some(definition) => (
                            definition.default_severity.to_string(),
                            definition.title.to_owned(),
                        ),
                        None => ("warning".to_owned(), rule_id.clone()),
                    };
                    emit_scan_alert(
                        format!("analysis:{}:finding-regression:{}", plugin.id, rule_id),
                        plugin.id.clone(),
                        "finding-regression",
                        &severity,
                        format!(
                            "analysis produced a new finding ({severity}): {rule_id} - {title}"
                        ),
                        false,
                        notify,
                        only_new,
                        &mut live_keys,
                        &mut alerts,
                        &mut new_alerts,
                        &mut state,
                        &mut highest_severity,
                    );
                }
            }
            match class {
                EventClass::PolicyUpdate => emit_scan_alert(
                    format!("analysis:{}:analyzer-policy-update", plugin.id),
                    plugin.id.clone(),
                    "analyzer-policy-update",
                    "warning",
                    "analyzer policy changed since the last evaluation; findings \
                     and capabilities were re-evaluated under the new policy"
                        .to_owned(),
                    false,
                    notify,
                    only_new,
                    &mut live_keys,
                    &mut alerts,
                    &mut new_alerts,
                    &mut state,
                    &mut highest_severity,
                ),
                EventClass::Instability => emit_scan_alert(
                    format!("analysis:{}:fingerprint-instability", plugin.id),
                    plugin.id.clone(),
                    "fingerprint-instability",
                    "error",
                    "analysis fingerprint changed while source identity and policy \
                     identity stayed identical; nondeterminism is suspected and \
                     review is required"
                        .to_owned(),
                    false,
                    notify,
                    only_new,
                    &mut live_keys,
                    &mut alerts,
                    &mut new_alerts,
                    &mut state,
                    &mut highest_severity,
                ),
                _ => {}
            }

            state.analysis_events.insert(
                plugin.id.clone(),
                omasafe_plugin_trust::baseline::AnalysisEventRecord {
                    source_identity,
                    policy_identity: policy_string.clone(),
                    fingerprint,
                    finding_rule_ids,
                    capability_kinds,
                },
            );
            analysis_events_dirty = true;
        }
    }
    // Retention is namespace-aware: default scans never hold `analysis:*`
    // keys in live_keys, so a plain retain would silently clear analysis-event
    // dedup state (and --notify would persist that clearing). Analysis keys
    // survive any scan that did not run the opted-in pass.
    state.alerts.retain(|key, _| {
        if key.starts_with("analysis:") {
            // Only a run that actually performed the opted-in classification
            // may retire its own stale keys; default scans leave them be.
            return if include_analysis {
                live_keys.contains(key)
            } else {
                true
            };
        }
        live_keys.contains(key)
    });
    if notify || analysis_events_dirty {
        state.write_atomic_locked(&state_path)?;
    }
    let result = ScanResult {
        quiet: live_keys.is_empty(),
        outstanding: live_keys.len(),
        new: new_alerts.len(),
        highest_severity: highest_severity.clone(),
        post_change_detection: true,
        alerts,
    };
    let has_findings = if only_new {
        result.new > 0
    } else {
        result.outstanding > 0
    };
    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&Report::new(TOOL_VERSION, now(), result))?
        );
    } else if result.quiet || (only_new && result.alerts.is_empty()) {
        println!("No new actionable changes detected.");
    } else {
        for alert in result.alerts {
            println!("{}: {}", safe_text(&alert.kind), safe_text(&alert.message));
        }
    }
    Ok(has_findings)
}

/// Single ladder over both severity vocabularies OmaSafe emits: legacy alert
/// levels (`warning`, `error`, `critical`) and analyzer catalog severities
/// (`info`, `low`, `medium`, `high`, `critical`). An unrecognized value keeps
/// the old fail-safe behavior of ranking at warning level.
fn alert_severity_rank(value: &str) -> u8 {
    match value {
        "none" => 0,
        "info" => 1,
        "low" => 2,
        "warning" => 3,
        "medium" => 4,
        "error" => 5,
        "high" => 6,
        "critical" => 7,
        _ => 3,
    }
}

fn track_highest_severity(current: &mut String, alert: &ScanAlert) {
    if alert_severity_rank(&alert.severity) > alert_severity_rank(current) {
        *current = alert.severity.clone();
    }
}

/// One scan-alert emission with the standard dedup/notify/only-new flow.
#[allow(clippy::too_many_arguments)]
fn emit_scan_alert(
    key: String,
    plugin_id: String,
    kind: &str,
    severity: &str,
    message: String,
    post_change: bool,
    notify: bool,
    only_new: bool,
    live_keys: &mut BTreeSet<String>,
    alerts: &mut Vec<ScanAlert>,
    new_alerts: &mut Vec<ScanAlert>,
    state: &mut ScanState,
    highest_severity: &mut String,
) {
    live_keys.insert(key.clone());
    let alert = ScanAlert {
        plugin_id,
        kind: kind.to_owned(),
        severity: severity.to_owned(),
        message,
        post_change,
    };
    track_highest_severity(highest_severity, &alert);
    let is_new = state.is_new(&key);
    if is_new {
        new_alerts.push(alert.clone());
    }
    if is_new && notify {
        notify_user(&alert);
        state.record(key, now());
    }
    if !only_new || is_new {
        alerts.push(alert);
    }
}

fn notify_user(alert: &ScanAlert) {
    let body = format!(
        "{}: [{}] {}",
        safe_text(&alert.plugin_id),
        safe_text(&alert.severity),
        safe_text(&alert.message)
    );
    let result = std::process::Command::new("notify-send")
        .args(["--urgency=critical", "OmaSafe", &body])
        .status();
    if result.is_err() {
        eprintln!("OmaSafe notification unavailable: {body}");
    }
}

fn write_if_changed(
    path: &std::path::Path,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if std::fs::read(path).ok().as_deref() != Some(bytes) {
        std::fs::write(path, bytes)?;
    }
    Ok(())
}

fn safe_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if matches!(character, '\n' | '\t') {
                character.to_string()
            } else if character.is_control() {
                format!("\\u{{{:x}}}", character as u32)
            } else {
                character.to_string()
            }
        })
        .collect()
}

fn schedule_install(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if !args.is_empty() {
        return Err("schedule install takes no arguments".into());
    }
    let home = home()?;
    let xdg = XdgPaths::discover()?;
    xdg.ensure()?;
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let unit_dir = config_home.join("systemd/user");
    std::fs::create_dir_all(&unit_dir)?;
    let executable = std::env::current_exe()?;
    let executable = executable
        .to_str()
        .ok_or("omasafe executable path is not UTF-8")?
        .replace('%', "%%")
        .replace('"', "\\\"");
    let state_path = xdg
        .state
        .display()
        .to_string()
        .replace('%', "%%")
        .replace('"', "\\\"");
    let cache_path = xdg
        .cache
        .display()
        .to_string()
        .replace('%', "%%")
        .replace('"', "\\\"");
    let service = format!(
        "[Unit]\nDescription=OmaSafe plugin drift scan\n\n[Service]\nType=oneshot\nSuccessExitStatus=3\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=\"{}\" \"{}\"\nExecStart=\"{}\" scan --notify --only-new\n",
        state_path, cache_path, executable
    );
    write_if_changed(&unit_dir.join("omasafe-scan.service"), service.as_bytes())?;
    write_if_changed(
        &unit_dir.join("omasafe-scan.timer"),
        b"[Unit]\nDescription=Daily OmaSafe plugin drift scan\n\n[Timer]\nOnCalendar=daily\nRandomizedDelaySec=15m\nPersistent=true\nUnit=omasafe-scan.service\n\n[Install]\nWantedBy=timers.target\n",
    )?;
    for args in [
        vec!["--user", "daemon-reload"],
        vec!["--user", "enable", "--now", "omasafe-scan.timer"],
    ] {
        let status = std::process::Command::new("systemctl")
            .args(args)
            .status()?;
        if !status.success() {
            return Err("systemd user timer installation failed".into());
        }
    }
    println!("Installed and enabled daily OmaSafe scan timer.");
    Ok(())
}

#[derive(serde::Serialize)]
struct StatusResult {
    plugin_id: String,
    state: String,
    current: SourceIdentity,
    trusted: Option<SourceIdentity>,
    reason: Option<String>,
}

fn review(id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut action = None;
    let mut reason = None;
    let mut scope = None;
    let mut yes = false;
    let mut expected_head = None;
    let mut expected_tree = None;
    let mut expected_digest = None;
    let mut restore_to = None;
    let mut rule = None;
    let mut suppression_path = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--action" => {
                action = Some(next_value(args, index, "review action")?.to_owned());
                index += 2;
            }
            "--reason" => {
                reason = Some(next_value(args, index, "review reason")?.to_owned());
                index += 2;
            }
            "--scope" => {
                scope = Some(next_value(args, index, "review scope")?.to_owned());
                index += 2;
            }
            "--yes" => {
                yes = true;
                index += 1;
            }
            "--expected-head" => {
                expected_head = Some(next_value(args, index, "expected HEAD")?.to_owned());
                index += 2;
            }
            "--expected-tree" => {
                expected_tree = Some(next_value(args, index, "expected tree")?.to_owned());
                index += 2;
            }
            "--expected-digest" => {
                expected_digest = Some(next_value(args, index, "expected digest")?.to_owned());
                index += 2;
            }
            "--to" => {
                restore_to = Some(next_value(args, index, "restore target")?.to_owned());
                index += 2;
            }
            "--rule" => {
                rule = Some(next_value(args, index, "suppression rule id")?.to_owned());
                index += 2;
            }
            "--path" => {
                suppression_path =
                    Some(next_value(args, index, "suppression path scope")?.to_owned());
                index += 2;
            }
            value => return Err(format!("unknown review argument: {value}").into()),
        }
    }
    if !yes {
        return Err("review actions require --yes after explicit preview".into());
    }
    let action = match action.ok_or("--action is required")?.as_str() {
        "revoke" => "untrust".to_owned(),
        value => value.to_owned(),
    };
    let reason = reason.ok_or("--reason is required")?;
    // Suppression decisions live outside the trust-history flow entirely:
    // they are scoped analysis-acceptance records in XDG config, never
    // overloads of the source-drift/missing-plugin/lost-coverage enum.
    if matches!(action.as_str(), "suppress" | "reinstate") {
        return suppression_review(
            id,
            &action,
            rule.as_deref(),
            suppression_path.as_deref(),
            &reason,
        );
    }
    let scope = scope.unwrap_or_else(|| {
        if action == "acknowledge" {
            "source-drift".into()
        } else if action == "untrust" {
            "trust-baseline".into()
        } else {
            "plugin".into()
        }
    });
    if matches!(action.as_str(), "acknowledge" | "exclude")
        && !matches!(
            scope.as_str(),
            "source-drift" | "missing-plugin" | "lost-coverage"
        )
    {
        return Err("review scope must be source-drift, missing-plugin, or lost-coverage".into());
    }
    if action == "untrust" && scope != "trust-baseline" {
        return Err("untrust scope must be trust-baseline".into());
    }
    let paths = XdgPaths::discover()?;
    paths.ensure()?;
    let path = paths.state.join("trust-history.json");
    let _history_lock = lock_state(&path)?;
    let mut history = TrustHistory::load(&path)?;
    if action == "restore" && restore_to.is_none() {
        return Err("restore requires --to INDEX or --to DIGEST".into());
    }
    if action == "untrust" {
        history.revoke(id);
        history.decisions.push(ReviewDecision {
            plugin_id: id.into(),
            action,
            scope,
            reason,
            created_at: now(),
        });
    } else if action == "rebaseline" || action == "restore" {
        let accepted = if action == "restore" {
            let target = restore_to.as_deref().unwrap();
            let records: Vec<&TrustRecord> = history
                .records
                .iter()
                .filter(|record| record.plugin_id == id)
                .collect();
            let record = if let Ok(index) = target.parse::<usize>() {
                records.get(index).copied()
            } else {
                records
                    .iter()
                    .rev()
                    .find(|record| record.accepted.content_digest.as_deref() == Some(target))
                    .copied()
            }
            .ok_or("restore target was not found")?;
            record.accepted.clone()
        } else {
            let (_, current) = current_identity(id)?;
            if !expected_component(current.head.as_deref(), expected_head.as_deref())
                || !expected_component(current.tree.as_deref(), expected_tree.as_deref())
                || !expected_component(
                    current.content_digest.as_deref(),
                    expected_digest.as_deref(),
                )
            {
                return Err("current identity does not exactly match the expected identity".into());
            }
            current
        };
        history.accept(TrustRecord {
            plugin_id: id.into(),
            accepted,
            accepted_at: now(),
            note: reason,
        });
    } else if matches!(action.as_str(), "acknowledge" | "exclude") {
        history.decisions.push(ReviewDecision {
            plugin_id: id.into(),
            action,
            scope,
            reason,
            created_at: now(),
        });
    } else {
        return Err("action must be acknowledge, rebaseline, restore, untrust, or exclude".into());
    }
    history.write_atomic_locked(&path)?;
    println!("Review decision recorded in {}", path.display());
    Ok(())
}

/// `plugins review ID --action suppress|reinstate`: scoped analysis
/// suppressions in XDG config. Records are plugin-targeted (created here)
/// with an optional path scope inside the plugin; the store itself also
/// supports global path-only records for plugin-less contexts.
fn suppression_review(
    plugin_id: &str,
    action: &str,
    rule_id: Option<&str>,
    path_scope: Option<&str>,
    reason: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let rule_id = rule_id.ok_or("suppress/reinstate requires --rule RULE_ID")?;
    if action == "suppress"
        && !omasafe_analyzer::catalog()
            .iter()
            .any(|definition| definition.id == rule_id)
    {
        return Err(format!(
            "unknown rule id: {rule_id}; see `omasafe-cli rules list` for the catalog"
        )
        .into());
    }
    omasafe_core::suppress::validate_new(rule_id, reason, path_scope)?;
    // Store and compare canonical scope forms so `assets` and `assets/`
    // are the same suppression everywhere.
    let canonical_path_scope = path_scope.map(omasafe_core::suppress::canonical_scope);
    let paths = XdgPaths::discover()?;
    paths.ensure()?;
    let path = paths.config.join("suppressions.json");
    let _lock = omasafe_core::suppress::acquire_lock(&path)?;
    let mut state = omasafe_core::suppress::SuppressionState::load(&path)?;
    match action {
        "suppress" => {
            state.add(omasafe_core::suppress::SuppressionRecord {
                rule_id: rule_id.to_owned(),
                plugin_id: Some(plugin_id.to_owned()),
                path_scope: canonical_path_scope,
                reason: reason.to_owned(),
                created_at: now(),
                active: true,
                reinstated_at: None,
            });
            state.write_atomic_locked(&path)?;
            println!("Suppression recorded in {}", path.display());
        }
        "reinstate" => {
            let flipped =
                state.reinstate(rule_id, Some(plugin_id), canonical_path_scope.as_deref());
            if flipped == 0 {
                return Err(format!(
                    "no active suppression matches rule {rule_id} for {plugin_id} at that scope"
                )
                .into());
            }
            state.write_atomic_locked(&path)?;
            println!(
                "Reinstated {flipped} suppression record(s) in {}; audit trail preserved",
                path.display()
            );
        }
        _ => unreachable!("action filtered by caller"),
    }
    Ok(())
}

fn status(id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let format = format_arg(args)?;
    let (_record, current) = current_identity(id)?;
    let history = TrustHistory::load(&XdgPaths::discover()?.state.join("trust-history.json"))?;
    let trusted = history.latest(id).map(|record| record.accepted.clone());
    let state = match trusted.as_ref() {
        None => "untrusted",
        Some(identity) if identity == &current && current.limitations.is_empty() => "unchanged",
        Some(identity) if identity == &current => "partial",
        Some(_) => "changed",
    };
    let result = StatusResult {
        plugin_id: id.into(),
        state: state.into(),
        current,
        trusted,
        reason: if state == "untrusted" {
            Some(if history.is_revoked(id) {
                "trust baseline was revoked; restore or re-trust to recover it".into()
            } else {
                "no trust baseline exists".into()
            })
        } else if state == "partial" {
            Some("source identity has disclosed coverage limitations".into())
        } else {
            None
        },
    };
    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&Report::new(TOOL_VERSION, now(), result))?
        );
    } else {
        println!("{}: {}", safe_text(&result.plugin_id), result.state);
        if let Some(reason) = result.reason {
            println!("Reason: {reason}");
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct DiffReport {
    plugin_id: String,
    from: Option<String>,
    to: Option<String>,
    source_changed: bool,
    diff: DiffResult,
    limitation: Option<String>,
    changed_files: Vec<String>,
}

fn diff(id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (format, range_arg) = parse_diff_args(args)?;
    let (record, current) = current_identity(id)?;
    let history = TrustHistory::load(&XdgPaths::discover()?.state.join("trust-history.json"))?;
    let trusted = history.latest(id).map(|record| record.accepted.clone());
    let Some(trusted) = trusted else {
        return Err(format!("no trust baseline exists for {id}").into());
    };
    let refs = if let Some(range) = range_arg.as_deref() {
        Some(
            range
                .split_once("..")
                .ok_or("diff range must be REF_A..REF_B")?,
        )
    } else if trusted.head.is_some() && (record.dirty == Some(true) || current.head.is_some()) {
        Some((
            trusted.head.as_deref().unwrap(),
            if record.dirty == Some(true) {
                "WORKTREE"
            } else {
                current.head.as_deref().unwrap()
            },
        ))
    } else {
        None
    };
    let git = refs.map_or_else(
        || DiffResult {
            available: false,
            text: None,
            truncated: false,
            limitation: None,
        },
        |(ref_a, ref_b)| git_diff(PathBuf::from(&record.path).as_path(), ref_a, ref_b),
    );
    let mut changed_files: Vec<String> = trusted
        .file_digests
        .keys()
        .chain(current.file_digests.keys())
        .filter(|path| trusted.file_digests.get(*path) != current.file_digests.get(*path))
        .cloned()
        .collect();
    changed_files.sort();
    changed_files.dedup();
    let diff = if git.available {
        let mut git = git;
        if !changed_files.is_empty() {
            let paths = changed_files
                .iter()
                .map(|path| format!("changed: {path}\n"))
                .collect::<String>();
            git.text = Some(format!("{}{}", git.text.unwrap_or_default(), paths));
        }
        git
    } else {
        DiffResult {
            available: true,
            text: Some(
                changed_files
                    .iter()
                    .map(|path| format!("changed: {path}\n"))
                    .collect(),
            ),
            truncated: false,
            limitation: Some("Git hunks unavailable; showing digest-level file changes".into()),
        }
    };
    let report = DiffReport {
        plugin_id: id.into(),
        from: refs.map(|(a, _)| a.into()),
        to: refs.map(|(_, b)| b.into()),
        source_changed: current != trusted,
        limitation: diff.limitation.clone(),
        diff,
        changed_files,
    };
    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&Report::new(TOOL_VERSION, now(), report))?
        );
    } else {
        println!(
            "{}: source_changed={}",
            safe_text(&report.plugin_id),
            report.source_changed
        );
        if let Some(text) = report.diff.text {
            print!("{}", safe_text(&text));
        }
        if let Some(limitation) = report.limitation {
            println!("\nLimitation: {}", safe_text(&limitation));
        }
    }
    Ok(())
}

fn parse_diff_args(args: &[String]) -> Result<(&str, Option<String>), Box<dyn std::error::Error>> {
    let mut format = "text";
    let mut range = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--format" => {
                format = next_value(args, index, "format")?;
                index += 2;
            }
            value if value.starts_with("--format=") => {
                format = &value["--format=".len()..];
                index += 1;
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown diff argument: {value}").into());
            }
            value => {
                if range.replace(value.to_owned()).is_some() {
                    return Err("diff accepts at most one REF_A..REF_B range".into());
                }
                index += 1;
            }
        }
    }
    if !matches!(format, "text" | "json") {
        return Err(format!("unsupported format: {format}").into());
    }
    Ok((format, range))
}

fn format_arg(args: &[String]) -> Result<&str, Box<dyn std::error::Error>> {
    match args {
        [] => Ok("text"),
        [flag, format] if flag == "--format" && matches!(format.as_str(), "text" | "json") => {
            Ok(format)
        }
        _ => Err("expected optional --format text|json".into()),
    }
}

fn next_value<'a>(
    args: &'a [String],
    index: usize,
    name: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    let value = args
        .get(index + 1)
        .ok_or_else(|| format!("missing {name}"))?;
    if value.starts_with("--") {
        return Err(format!("missing {name} value").into());
    }
    Ok(value)
}

fn current_identity(
    id: &str,
) -> Result<(omasafe_plugin_trust::PluginRecord, SourceIdentity), Box<dyn std::error::Error>> {
    let plugin_root = plugin_root()?;
    let (shell_json, _shell_error) = query_shell();
    let inventory = collect_one(&plugin_root, id, shell_json.as_deref());
    let record = inventory
        .plugins
        .into_iter()
        .find(|plugin| plugin.id == id)
        .ok_or_else(|| format!("plugin not found: {id}"))?;
    let identity = SourceIdentity {
        plugin_id: record.id.clone(),
        repository: record.repository.clone(),
        head: record.head.clone(),
        tree: record.tree.clone(),
        content_digest: record.content_digest.clone(),
        file_count: record.content_file_count.unwrap_or_default(),
        limitations: record.limitations.clone(),
        file_digests: record.file_digests.clone(),
    };
    Ok((record, identity))
}

fn inventory(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut format = "text";
    let mut catalog_path = None;
    let mut catalog_commit = None;
    let mut catalog_repository = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--format" => {
                format = args
                    .get(index + 1)
                    .map(String::as_str)
                    .ok_or("missing format")?;
                index += 2;
            }
            "--catalog" => {
                catalog_path = Some(PathBuf::from(next_value(args, index, "catalog path")?));
                index += 2;
            }
            "--catalog-commit" => {
                catalog_commit = Some(next_value(args, index, "catalog commit")?.to_owned());
                index += 2;
            }
            "--catalog-repository" => {
                catalog_repository =
                    Some(next_value(args, index, "catalog repository")?.to_owned());
                index += 2;
            }
            value => return Err(format!("unknown inventory argument: {value}").into()),
        }
    }
    if !matches!(format, "text" | "json") {
        return Err(format!("unsupported format: {format}").into());
    }
    if catalog_path.is_some() && catalog_commit.is_none() {
        return Err("--catalog requires --catalog-commit".into());
    }
    if catalog_path.is_some() && catalog_repository.is_none() {
        return Err("--catalog requires --catalog-repository".into());
    }

    let plugin_root = plugin_root()?;
    let (shell_json, shell_error) = query_shell();
    let mut result = collect(&plugin_root, shell_json.as_deref());
    if let Some(error) = shell_error {
        result.coverage.limitations.push(error);
    }
    let mut marketplace_source = None;
    let snapshot = match (catalog_path, catalog_commit, catalog_repository) {
        (Some(path), Some(commit), Some(repository)) => {
            if !valid_commit(&commit) || !repository.starts_with("https://") {
                return Err("local catalog requires an HTTPS repository and a 40- or 64-character hexadecimal commit".into());
            }
            marketplace_source = Some("local-file");
            Some(load_catalog(&path, repository, commit, now())?)
        }
        (None, None, None) => {
            let snapshot = load_cached_catalog(&XdgPaths::discover()?.cache)?;
            if snapshot.is_some() {
                marketplace_source =
                    Some(if snapshot.as_ref().is_some_and(|value| value.verified) {
                        "pinned-fetch"
                    } else {
                        "unverified-cache"
                    });
            }
            snapshot
        }
        _ => return Err("catalog options must be supplied together".into()),
    };
    let marketplace_snapshot_verified = snapshot.as_ref().map(|value| value.verified);
    let marketplace_repository = snapshot.as_ref().map(|value| value.repository.clone());
    let marketplace_repository_commit = snapshot
        .as_ref()
        .map(|value| value.repository_commit.clone());
    let marketplace_file_digest = snapshot.as_ref().map(|value| value.file_digest.clone());
    let correlations = snapshot.as_ref().map(|snapshot| {
        result
            .plugins
            .iter()
            .map(|plugin| {
                correlate(
                    &plugin.id,
                    plugin.repository.as_deref(),
                    plugin.head.as_deref(),
                    snapshot,
                )
            })
            .collect::<Vec<Correlation>>()
    });
    let marketplace_retrieved_at = snapshot.as_ref().map(|value| value.retrieved_at.clone());
    let marketplace_generation_time = snapshot
        .as_ref()
        .and_then(|value| value.generation_time.clone());
    let marketplace_age_seconds = marketplace_retrieved_at
        .as_deref()
        .and_then(timestamp_age_seconds);
    let marketplace_stale = marketplace_age_seconds.is_some_and(|age| age > 30 * 24 * 60 * 60);

    if format == "json" {
        let output = if let Some(correlations) = correlations {
            let mut value = serde_json::to_value(&result)?;
            value
                .as_object_mut()
                .unwrap()
                .insert("marketplace".into(), serde_json::to_value(correlations)?);
            if let Some(source) = marketplace_source {
                value.as_object_mut().unwrap().insert(
                    "marketplace_source".into(),
                    serde_json::Value::String(source.into()),
                );
            }
            if let Some(verified) = marketplace_snapshot_verified {
                value.as_object_mut().unwrap().insert(
                    "marketplace_snapshot_verified".into(),
                    serde_json::Value::Bool(verified),
                );
            }
            if let Some(repository) = marketplace_repository {
                value.as_object_mut().unwrap().insert(
                    "marketplace_repository".into(),
                    serde_json::Value::String(repository),
                );
            }
            if let Some(commit) = marketplace_repository_commit {
                value.as_object_mut().unwrap().insert(
                    "marketplace_repository_commit".into(),
                    serde_json::Value::String(commit),
                );
            }
            if let Some(digest) = marketplace_file_digest {
                value.as_object_mut().unwrap().insert(
                    "marketplace_file_digest".into(),
                    serde_json::Value::String(digest),
                );
            }
            if let Some(retrieved_at) = &marketplace_retrieved_at {
                value.as_object_mut().unwrap().insert(
                    "marketplace_retrieved_at".into(),
                    serde_json::Value::String(retrieved_at.clone()),
                );
            }
            if let Some(age) = marketplace_age_seconds {
                value.as_object_mut().unwrap().insert(
                    "marketplace_age_seconds".into(),
                    serde_json::Value::Number(age.into()),
                );
            }
            if let Some(generation_time) = marketplace_generation_time {
                value.as_object_mut().unwrap().insert(
                    "marketplace_generation_time".into(),
                    serde_json::Value::String(generation_time),
                );
            }
            value.as_object_mut().unwrap().insert(
                "marketplace_stale".into(),
                serde_json::Value::Bool(marketplace_stale),
            );
            value
        } else {
            serde_json::to_value(&result)?
        };
        let report = Report::new(TOOL_VERSION, now(), output);
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let backup_count = result
            .plugins
            .iter()
            .filter(|plugin| plugin.classification == "backup")
            .count();
        println!(
            "{} installed plugin(s) collected.",
            result.plugins.len().saturating_sub(backup_count)
        );
        if backup_count > 0 {
            println!("{backup_count} backup folder(s) retained separately for audit visibility.");
        }
        if let Some(source) = marketplace_source {
            println!("Marketplace source: {source}");
        }
        if let Some(verified) = marketplace_snapshot_verified {
            println!(
                "Marketplace snapshot integrity: {}",
                if verified { "verified" } else { "unverified" }
            );
        }
        if let Some(commit) = marketplace_repository_commit {
            println!("Marketplace catalog commit: {}", safe_text(&commit));
        }
        if let Some(retrieved_at) = marketplace_retrieved_at {
            println!("Marketplace retrieved at: {}", safe_text(&retrieved_at));
        }
        if marketplace_stale {
            println!("Marketplace limitation: cached snapshot is older than 30 days");
        }
        for limitation in result.coverage.limitations {
            println!("Coverage limitation: {}", safe_text(&limitation));
        }
        if let Some(correlations) = correlations {
            for correlation in correlations {
                println!(
                    "Marketplace {}: {}",
                    safe_text(&correlation.plugin_id),
                    correlation.status
                );
            }
        }
    }
    Ok(())
}

fn marketplace_refresh(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut commit = None;
    let mut latest = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--commit" => {
                commit = Some(next_value(args, index, "marketplace commit")?.to_owned());
                index += 2;
            }
            "--latest" => {
                latest = true;
                index += 1;
            }
            value => return Err(format!("unknown marketplace argument: {value}").into()),
        }
    }
    if latest && commit.is_some() {
        return Err("marketplace refresh accepts either --commit or --latest, not both".into());
    }
    let commit = match (commit, latest) {
        (Some(commit), false) => commit,
        (None, true) => resolve_latest_commit(OFFICIAL_REPOSITORY)?,
        (None, false) => {
            return Err("marketplace refresh requires --commit COMMIT or --latest".into());
        }
        (Some(_), true) => unreachable!(),
    };
    if !valid_commit(&commit) {
        return Err("marketplace commit must be 40 or 64 hexadecimal characters".into());
    }
    let paths = XdgPaths::discover()?;
    paths.ensure()?;
    let snapshot = fetch_pinned_catalog(&paths.cache, OFFICIAL_REPOSITORY, &commit, now())?;
    println!(
        "Fetched {} catalog entries at {}",
        snapshot.entries.len(),
        snapshot.repository_commit
    );
    Ok(())
}

fn rules_list(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut format = "text";
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--format" => {
                format = next_value(args, index, "rules format")?;
                index += 2;
            }
            value => return Err(format!("unknown rules list argument: {value}").into()),
        }
    }
    if !matches!(format, "text" | "json") {
        return Err("rules format must be text or json".into());
    }

    let policy_identity = omasafe_analyzer::policy_identity();
    let catalog = omasafe_analyzer::catalog();
    if format == "json" {
        let result = serde_json::json!({
            "policy_identity": policy_identity,
            "rule_catalog_version": omasafe_analyzer::RULE_CATALOG_VERSION,
            "severity_table_version": omasafe_analyzer::SEVERITY_TABLE_VERSION,
            "supported_surface_version": omasafe_analyzer::SUPPORTED_SURFACE_VERSION,
            "equivalence_map_version": omasafe_analyzer::EQUIVALENCE_MAP_VERSION,
            "rules": catalog,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&Report::new(TOOL_VERSION, now(), result))?
        );
    } else {
        println!(
            "OmaSafe rule catalog v{} (severity table v{}, surface {}, analyzer {})",
            omasafe_analyzer::RULE_CATALOG_VERSION,
            omasafe_analyzer::SEVERITY_TABLE_VERSION,
            policy_identity.supported_surface_version,
            policy_identity.analyzer_version
        );
        for definition in catalog {
            println!(
                "{}  [{}] {}  severity:{}  capability:{}",
                definition.id,
                definition.language,
                definition.title,
                definition.default_severity,
                definition.capability
            );
            println!("    {}", definition.summary);
            println!("    Guidance: {}", definition.review_guidance);
        }
    }
    Ok(())
}

fn rules_explain(id: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut format = "text";
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--format" => {
                format = next_value(args, index, "explain format")?;
                index += 2;
            }
            value => return Err(format!("unknown rules explain argument: {value}").into()),
        }
    }
    if !matches!(format, "text" | "json") {
        return Err("rules explain format must be text or json".into());
    }
    let definition = omasafe_analyzer::catalog()
        .iter()
        .find(|definition| definition.id == id)
        .ok_or_else(|| {
            format!("unknown rule id: {id}; see `omasafe-cli rules list` for the catalog")
        })?;
    let map = omasafe_analyzer::EquivalenceMap::embedded();
    let external_ids = map.external_ids_for_rule(definition.id);
    if format == "json" {
        let result = serde_json::json!({
            "policy_identity": omasafe_analyzer::policy_identity(),
            "rule": definition,
            "external_equivalences": external_ids
                .iter()
                .map(|external_id| {
                    map.entries
                        .iter()
                        .find(|entry| {
                            entry.oma_rule_id.as_deref() == Some(definition.id)
                                && entry.external_id == *external_id
                        })
                        .expect("listed external id comes from a map entry")
                })
                .collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&Report::new(TOOL_VERSION, now(), result))?
        );
    } else {
        println!(
            "{}  [{}] {}",
            definition.id, definition.language, definition.title
        );
        println!(
            "severity:{}  capability:{}",
            definition.default_severity, definition.capability
        );
        println!("{}", definition.summary);
        println!("Surface anchor: {}", definition.surface_anchor);
        println!("Guidance: {}", definition.review_guidance);
        if external_ids.is_empty() {
            println!("Marketplace baseline: no direct equivalence recorded");
        } else {
            println!("Marketplace baseline coverage:");
            for entry in map
                .entries
                .iter()
                .filter(|entry| entry.oma_rule_id.as_deref() == Some(definition.id))
            {
                println!(
                    "  {} {} — {}",
                    entry.relation, entry.external_id, entry.note
                );
            }
        }
    }
    Ok(())
}

fn plugins_analyze(id: &str, args: &[String]) -> Result<i32, Box<dyn std::error::Error>> {
    let mut format = "text";
    let mut fail_on = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--format" => {
                format = next_value(args, index, "analyze format")?;
                index += 2;
            }
            "--fail-on" => {
                let value = next_value(args, index, "--fail-on severity")?;
                fail_on = Some(value.to_owned());
                index += 2;
            }
            value => return Err(format!("unknown analyze argument: {value}").into()),
        }
    }
    if !matches!(format, "text" | "json") {
        return Err("analyze format must be text or json".into());
    }
    interruption_checkpoint("before analysis started")?;
    let fail_on = parse_fail_on(fail_on)?;
    let plugin_root = plugin_root()?;
    let (shell_json, _shell_error) = query_shell();
    let inventory = collect_one(&plugin_root, id, shell_json.as_deref());
    let record = inventory
        .plugins
        .iter()
        .find(|plugin| plugin.id == id)
        .ok_or_else(|| format!("plugin not found: {id}"))?;

    let target = serde_json::json!({
        "source": "installed-plugin",
        "id": id,
        "path": record.path,
        "classification": record.classification,
    });
    let ingest_result = omasafe_analyzer::ingest_filesystem(
        Path::new(&record.path),
        omasafe_analyzer::Limits::default(),
        omasafe_core::bounds::TimeBudget::default(),
    );
    interruption_checkpoint("before report emission")?;
    emit_analysis_report(
        target,
        ingest_result.map_err(Into::into),
        format,
        fail_on,
        ContentSource::Filesystem(PathBuf::from(&record.path)),
        Some(id),
    )
}

fn scan_plugin(args: &[String]) -> Result<i32, Box<dyn std::error::Error>> {
    interruption_checkpoint("before analysis started")?;
    let mut format = "text";
    let mut fail_on = None;
    let mut path_target = None;
    let mut git_url = None;
    let mut revision = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--format" => {
                format = next_value(args, index, "scan-plugin format")?;
                index += 2;
            }
            "--fail-on" => {
                let value = next_value(args, index, "--fail-on severity")?;
                fail_on = Some(value.to_owned());
                index += 2;
            }
            "--path" => {
                path_target = Some(next_value(args, index, "--path")?.to_owned());
                index += 2;
            }
            "--git" => {
                git_url = Some(next_value(args, index, "--git")?.to_owned());
                index += 2;
            }
            "--revision" => {
                revision = Some(next_value(args, index, "--revision")?.to_owned());
                index += 2;
            }
            value => return Err(format!("unknown scan-plugin argument: {value}").into()),
        }
    }
    if !matches!(format, "text" | "json") {
        return Err("scan-plugin format must be text or json".into());
    }
    let fail_on = parse_fail_on(fail_on)?;

    match (path_target, git_url, revision) {
        (Some(path), None, None) => {
            let target = serde_json::json!({ "source": "local-directory", "path": path });
            let result = omasafe_analyzer::ingest_filesystem(
                Path::new(&path),
                omasafe_analyzer::Limits::default(),
                omasafe_core::bounds::TimeBudget::default(),
            );
            match result {
                Ok(inventory) => emit_analysis_report(
                    target,
                    Ok(inventory),
                    format,
                    fail_on,
                    ContentSource::Filesystem(PathBuf::from(&path)),
                    None,
                ),
                Err(omasafe_analyzer::IngestError::NotADirectory) => {
                    Err("scan-plugin target is not a directory".into())
                }
                Err(error) => Err(Box::new(error)),
            }
        }
        (None, Some(url), Some(revision)) => {
            let paths = XdgPaths::discover()?;
            paths.ensure()?;
            let cache_root = paths.cache.join("analysis");
            match omasafe_analyzer::ensure_pinned_repository(&cache_root, &url, &revision) {
                Ok(repository_dir) => {
                    let target = serde_json::json!({
                        "source": "pinned-revision", "url": url, "revision": revision
                    });
                    let result = omasafe_analyzer::ingest_pinned_tree(
                        &repository_dir,
                        &revision,
                        omasafe_analyzer::Limits::default(),
                        omasafe_core::bounds::TimeBudget::default(),
                    );
                    emit_analysis_report(
                        target,
                        result.map_err(Into::into),
                        format,
                        fail_on,
                        ContentSource::GitRepository(repository_dir.clone()),
                        None,
                    )
                }
                Err(omasafe_analyzer::IngestError::InvalidRevision) => {
                    Err("scan-plugin --revision must be 40 or 64 hexadecimal characters".into())
                }
                Err(error) => Err(error.into()),
            }
        }
        (None, Some(_), None) => Err("scan-plugin --git requires --revision".into()),
        (None, None, Some(_)) => Err("scan-plugin --revision requires --git".into()),
        (None, None, None) => {
            Err("scan-plugin requires --path DIR or --git URL with --revision".into())
        }
        _ => Err(
            "scan-plugin accepts either --path or the --git URL + --revision pair, not both".into(),
        ),
    }
}

fn parse_fail_on(value: Option<String>) -> Result<Option<omasafe_analyzer::Severity>, String> {
    match value.as_deref() {
        None => Ok(None),
        Some("info") => Ok(Some(omasafe_analyzer::Severity::Info)),
        Some("low") => Ok(Some(omasafe_analyzer::Severity::Low)),
        Some("medium") => Ok(Some(omasafe_analyzer::Severity::Medium)),
        Some("high") => Ok(Some(omasafe_analyzer::Severity::High)),
        Some("critical") => Ok(Some(omasafe_analyzer::Severity::Critical)),
        Some(_) => Err("--fail-on must be one of info|low|medium|high|critical".to_owned()),
    }
}

/// Where analyzed file contents come from during the detection pass.
enum ContentSource {
    Filesystem(PathBuf),
    GitRepository(PathBuf),
}

/// Digest-bound content readers, boxed per source at the emit boundary.
type ContentReader = Box<dyn Fn(&omasafe_analyzer::PayloadEntry) -> Option<Vec<u8>>>;

/// Most-common `verificationBaselineVersion` across the locally cached frozen
/// catalog snapshot, used only for equivalence staleness marking. `None` when
/// no snapshot is available or it carries no version information.
fn observed_marketplace_baseline() -> Option<String> {
    let cache_dir = XdgPaths::discover().ok()?.cache;
    let path = cache_dir.join("catalog.json");
    // The cached snapshot is untrusted input: honor the marketplace catalog
    // byte bound before allocating, matching the loader's own contract.
    let size = std::fs::metadata(&path).ok()?.len();
    if size > MAX_CATALOG_BYTES as u64 {
        return None;
    }
    let raw = std::fs::read_to_string(path).ok()?;
    let document: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let entries = match &document {
        // Both frozen-snapshot shapes: bare entry arrays and wrapped objects.
        serde_json::Value::Array(entries) => entries,
        wrapped => wrapped
            .get("entries")
            .or_else(|| wrapped.get("plugins"))
            .and_then(serde_json::Value::as_array)?,
    };
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for entry in entries {
        if let Some(version) = entry
            .get("verificationBaselineVersion")
            .and_then(serde_json::Value::as_str)
        {
            *counts.entry(version).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(version, _)| version.to_owned())
}

/// Read at most `expected`+1 bytes so an overgrown file is detectable.
fn read_capped(file: &std::fs::File, expected: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut buffer = Vec::new();
    file.take(expected.saturating_add(1))
        .read_to_end(&mut buffer)
        .ok()?;
    Some(buffer)
}

/// Digest-bound filesystem content reader: bounded by the recorded size,
/// never following symlinks, and verified against the ingested sample digest.
/// Sampled entries have no full digest to verify against and read as `None`.
fn pinned_filesystem_reader(
    root: PathBuf,
) -> impl Fn(&omasafe_analyzer::PayloadEntry) -> Option<Vec<u8>> {
    move |entry: &omasafe_analyzer::PayloadEntry| -> Option<Vec<u8>> {
        if entry.sampled_digest || entry.sha256_sampled.is_none() {
            return None;
        }
        let bytes = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                // O_NOFOLLOW rejects a swapped-in symlink; O_NONBLOCK stops a
                // swapped-in FIFO from blocking the open. The fstat afterwards
                // must confirm a regular file, closing the device/socket/FIFO
                // window; anything else fails into a disclosed limitation.
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(root.join(&entry.relative_path))
                    .ok()?;
                if !file.metadata().ok()?.is_file() {
                    return None;
                }
                read_capped(&file, entry.size)
            }
            #[cfg(not(unix))]
            {
                let file = std::fs::File::open(root.join(&entry.relative_path)).ok()?;
                if !file.metadata().ok()?.is_file() {
                    return None;
                }
                read_capped(&file, entry.size)
            }
        }?;
        verify_entry_bytes(entry, bytes)
    }
}

/// Digest-bound git content reader: bounded cat-file by object id with
/// truncation/status checks against the ingested inventory record.
fn pinned_git_reader(
    repository_dir: PathBuf,
) -> impl Fn(&omasafe_analyzer::PayloadEntry) -> Option<Vec<u8>> {
    move |entry: &omasafe_analyzer::PayloadEntry| -> Option<Vec<u8>> {
        if entry.sampled_digest || entry.object_id.is_none() || entry.sha256_sampled.is_none() {
            return None;
        }
        let oid = entry.object_id.as_deref()?;
        let mut command = std::process::Command::new("git");
        command.current_dir(&repository_dir);
        command.args(["cat-file", "blob", oid]);
        command.env("GIT_CONFIG_GLOBAL", "/dev/null");
        command.env("GIT_CONFIG_SYSTEM", "/dev/null");
        let captured = omasafe_core::bounds::run_bounded_capped(
            &mut command,
            omasafe_core::bounds::GIT_PROCESS_BUDGET,
            entry.size as usize + 1,
        )
        .ok()??;
        if captured.truncated || !captured.status.success() {
            return None;
        }
        verify_entry_bytes(entry, captured.stdout)
    }
}

fn verify_entry_bytes(entry: &omasafe_analyzer::PayloadEntry, bytes: Vec<u8>) -> Option<Vec<u8>> {
    if bytes.len() as u64 != entry.size {
        return None;
    }
    use sha2::Digest as _;
    let expected_digest = entry.sha256_sampled.as_deref()?;
    let digest = sha2::Sha256::digest(&bytes);
    let hex_digest: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    (hex_digest == expected_digest).then_some(bytes)
}

fn emit_analysis_report(
    target: serde_json::Value,
    ingest_result: Result<omasafe_analyzer::PayloadInventory, Box<dyn std::error::Error>>,
    format: &str,
    fail_on: Option<omasafe_analyzer::Severity>,
    source: ContentSource,
    plugin_context: Option<&str>,
) -> Result<i32, Box<dyn std::error::Error>> {
    // Ingestion failures are command failures; only per-file degradation is
    // reported inside a successful inventory.
    let mut inventory = ingest_result?;

    // Re-reads must return exactly the bytes that were inventoried: bounded
    // by the recorded size, never following symlinks (filesystem source), and
    // verified against the ingested digest so a race or drift degrades into a
    // disclosed limitation instead of analyzing different content.
    let read_content: ContentReader = match &source {
        ContentSource::Filesystem(root) => Box::new(pinned_filesystem_reader(root.clone())),
        ContentSource::GitRepository(repository_dir) => {
            Box::new(pinned_git_reader(repository_dir.clone()))
        }
    };

    let budget = omasafe_core::bounds::TimeBudget::default();
    let artifacts = omasafe_analyzer::analyze_inventory(&mut inventory, &read_content, &budget);
    // Output-commitment point for every analysis command: an interrupt that
    // landed during analysis stops here, before any report text or JSON is
    // emitted, and the caller unwinds to a 130 exit.
    interruption_checkpoint("analysis finished; report not yet emitted")?;
    let rendered = artifacts.rendered_findings();

    // Suppressions are presentation/enforcement filters over the RENDERED
    // findings only. Stored results, capabilities, invocation edges, and the
    // analysis fingerprint were computed before this point and never change;
    // a suppression hides and de-enforces a finding but leaves every stored
    // artifact byte-identical. An unreadable suppressions file fails open
    // toward MORE visibility and is disclosed as a limitation.
    let suppressions_path = XdgPaths::discover()
        .ok()
        .map(|paths| paths.config.join("suppressions.json"));
    let (suppressions, suppressions_limitation) = match suppressions_path
        .as_deref()
        .map(omasafe_core::suppress::SuppressionState::load)
    {
        Some(Ok(state)) => (state, None),
        Some(Err(error)) => (
            omasafe_core::suppress::SuppressionState::default(),
            Some(format!("suppressions-unreadable:{error}")),
        ),
        None => (omasafe_core::suppress::SuppressionState::default(), None),
    };
    let mut applied_suppressions: Vec<serde_json::Value> = Vec::new();
    let findings: Vec<_> = rendered
        .into_iter()
        .filter(|finding| {
            let hit =
                suppressions.matches(&finding.rule_id, plugin_context, &finding.relative_path);
            if hit {
                applied_suppressions.push(serde_json::json!({
                    "rule_id": finding.rule_id,
                    "relative_path": finding.relative_path,
                }));
            }
            !hit
        })
        .collect();

    let policy_identity = omasafe_analyzer::policy_identity();
    let fingerprint =
        omasafe_analyzer::fingerprint_analysis(&artifacts.results, &artifacts.capabilities);
    let mut coverage_limitations = inventory.limitations.clone();
    coverage_limitations.extend(artifacts.limitations.clone());
    if let Some(limitation) = suppressions_limitation {
        coverage_limitations.push(limitation);
    }

    // Equivalence summary + staleness against the locally cached snapshot's
    // recorded baseline version (most common value across entries).
    let equivalence_map = omasafe_analyzer::EquivalenceMap::embedded();
    let observed_baseline = observed_marketplace_baseline();
    if let Some(observed) = &observed_baseline
        && equivalence_map.is_stale_against(observed)
    {
        coverage_limitations.push(format!(
            "equivalence-map-stale:map-v{}-observed-v{observed}",
            equivalence_map.external_ruleset_version
        ));
    }
    let equivalence_summary = omasafe_report::analysis::EquivalenceSummary {
        map_version: equivalence_map.map_version.clone(),
        external_system: equivalence_map.external_system.clone(),
        external_ruleset_name: equivalence_map.external_ruleset_name.clone(),
        external_ruleset_version: equivalence_map.external_ruleset_version.clone(),
    };
    let analysis = omasafe_report::analysis::AnalysisSection::new(
        policy_identity.clone(),
        fingerprint,
        coverage_limitations.clone(),
        findings.clone(),
        artifacts.capabilities.clone(),
        artifacts.edges.clone(),
        omasafe_analyzer::parser_metadata(),
        Some(equivalence_summary),
    );

    // --fail-on: findings are success; CI opts into a failure threshold.
    // Suppressed findings are de-enforced, so the threshold only sees
    // visible findings. Exit code 4 (documented separately from scan's 3).
    let severity_of = |value: &str| match value {
        "info" => Some(omasafe_analyzer::Severity::Info),
        "low" => Some(omasafe_analyzer::Severity::Low),
        "medium" => Some(omasafe_analyzer::Severity::Medium),
        "high" => Some(omasafe_analyzer::Severity::High),
        "critical" => Some(omasafe_analyzer::Severity::Critical),
        _ => None,
    };
    let threshold_breached = fail_on.is_some_and(|threshold| {
        findings.iter().any(|finding| {
            severity_of(&finding.severity).is_some_and(|severity| severity >= threshold)
        })
    });

    let states = serde_json::json!({
        "analyzed": inventory.state_count(omasafe_analyzer::CoverageState::Analyzed),
        "partial": inventory.state_count(omasafe_analyzer::CoverageState::Partial),
        "skipped": inventory.state_count(omasafe_analyzer::CoverageState::Skipped),
        "truncated": inventory.state_count(omasafe_analyzer::CoverageState::Truncated),
        "unsupported": inventory.state_count(omasafe_analyzer::CoverageState::Unsupported),
        "unreferenced": inventory.state_count(omasafe_analyzer::CoverageState::Unreferenced),
    });

    if format == "json" {
        let result = serde_json::json!({
            "target": target,
            "analysis": analysis,
            "suppressions": {
                "applied": applied_suppressions,
                "active_records": suppressions.active().count(),
            },
            "payload_inventory": {
                "totals": {
                    "files_seen": inventory.total_files_seen,
                    "bytes_ingested": inventory.total_bytes_ingested,
                    "entries": inventory.entries.len(),
                },
                "coverage_states": states,
                "limitations": inventory.limitations,
                "entries": inventory.entries,
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&Report::new(TOOL_VERSION, now(), result))?
        );
    } else {
        println!(
            "Analysis of {} ({})",
            safe_text(
                target["id"]
                    .as_str()
                    .or_else(|| target["path"].as_str())
                    .unwrap_or("?")
            ),
            safe_text(target["source"].as_str().unwrap_or("?"))
        );
        println!(
            "Files seen: {}  Bytes ingested: {}  Entries: {}",
            inventory.total_files_seen,
            inventory.total_bytes_ingested,
            inventory.entries.len()
        );
        for (state, count) in states.as_object().unwrap() {
            if count.as_u64().unwrap_or(0) > 0 {
                println!("Coverage state {}: {}", state, count);
            }
        }
        const TEXT_ENTRY_CAP: usize = 200;
        let omitted = inventory.entries.len().saturating_sub(TEXT_ENTRY_CAP);
        for entry in inventory.entries.iter().take(TEXT_ENTRY_CAP) {
            println!(
                "{}\t{}\t{}\t{:o}\t{}B{}",
                safe_text(&entry.relative_path),
                entry.kind.as_str(),
                entry.coverage_state.as_str(),
                entry.mode,
                entry.size,
                if entry.sampled_digest { " sampled" } else { "" }
            );
        }
        if omitted > 0 {
            println!(
                "… {} more entries omitted from the text view; use --format json",
                omitted
            );
        }
        for limitation in &coverage_limitations {
            println!("Coverage limitation: {}", safe_text(limitation));
        }
        if !applied_suppressions.is_empty() {
            println!("Suppressions applied: {}", applied_suppressions.len());
            for applied in &applied_suppressions {
                println!(
                    "  suppressed\t{}\t{}",
                    applied["rule_id"].as_str().unwrap_or("?"),
                    applied["relative_path"].as_str().unwrap_or("?")
                );
            }
        }
        println!("Findings: {}", findings.len());
        const TEXT_FINDING_CAP: usize = 100;
        for finding in findings.iter().take(TEXT_FINDING_CAP) {
            let location = finding
                .line
                .map(|line| format!(":{line}"))
                .unwrap_or_default();
            let evidence: String = safe_text(&finding.evidence).chars().take(80).collect();
            println!(
                "{}\t{}\t{}{}\t{}",
                finding.severity,
                finding.rule_id,
                safe_text(&finding.relative_path),
                location,
                evidence
            );
        }
        if findings.len() > TEXT_FINDING_CAP {
            println!(
                "… {} more findings omitted from the text view; use --format json",
                findings.len() - TEXT_FINDING_CAP
            );
        }
        if !artifacts.capabilities.is_empty() {
            println!("Capabilities observed: {}", artifacts.capabilities.len());
            const TEXT_CAPABILITY_CAP: usize = 100;
            for capability in artifacts.capabilities.iter().take(TEXT_CAPABILITY_CAP) {
                let detail: String = safe_text(&capability.detail).chars().take(60).collect();
                println!(
                    "{}\t{}\t{}",
                    capability.capability,
                    safe_text(&capability.relative_path),
                    detail
                );
            }
        }
        if !artifacts.edges.is_empty() {
            println!("Invocation edges: {}", artifacts.edges.len());
            for edge in &artifacts.edges {
                println!(
                    "{} -> {}",
                    safe_text(&edge.from_path),
                    safe_text(&edge.target_path)
                );
            }
        }
    }

    // Findings are still success (the report printed above); the exit code
    // is the CI opt-in signal, distinct from scan's 3. Returned through the
    // normal path so stdout flushes like any other run.
    Ok(if threshold_breached { 4 } else { 0 })
}

fn print_paths() -> Result<(), Box<dyn std::error::Error>> {
    let paths = XdgPaths::discover()?;
    println!(
        "config={}\nstate={}\ncache={}",
        paths.config.display(),
        paths.state.display(),
        paths.cache.display()
    );
    Ok(())
}

fn home() -> Result<PathBuf, Box<dyn std::error::Error>> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".into())
}

fn is_excluded(history: &TrustHistory, plugin_id: &str, scope: &str) -> bool {
    history.decisions.iter().rev().any(|decision| {
        decision.plugin_id == plugin_id && decision.action == "exclude" && decision.scope == scope
    })
}

fn is_acknowledged(history: &TrustHistory, plugin_id: &str, scope: &str) -> bool {
    history.decisions.iter().rev().any(|decision| {
        decision.plugin_id == plugin_id
            && decision.action == "acknowledge"
            && decision.scope == scope
    })
}

fn drift_key(plugin_id: &str, trusted: &SourceIdentity, current: &SourceIdentity) -> String {
    let mut material = trusted.identity_material();
    material.extend(current.identity_material());
    format!("drift:{plugin_id}:{:x}", Sha256::digest(material))
}

fn plugin_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = home()?;
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".config"));
    Ok(config.join("omarchy/plugins"))
}

fn now() -> String {
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

fn timestamp_age_seconds(timestamp: &str) -> Option<i64> {
    let parsed = if let Ok(seconds) = timestamp.parse::<i64>() {
        seconds
    } else {
        let date = timestamp.get(0..19)?;
        let bytes = date.as_bytes();
        if bytes.get(4) != Some(&b'-')
            || bytes.get(7) != Some(&b'-')
            || bytes.get(10) != Some(&b'T')
            || bytes.get(13) != Some(&b':')
            || bytes.get(16) != Some(&b':')
        {
            return None;
        }
        let year = date[0..4].parse::<i64>().ok()?;
        let month = date[5..7].parse::<i64>().ok()?;
        let day = date[8..10].parse::<i64>().ok()?;
        let hour = date[11..13].parse::<i64>().ok()?;
        let minute = date[14..16].parse::<i64>().ok()?;
        let second = date[17..19].parse::<i64>().ok()?;
        days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second
    };
    Some((unix_now() - parsed).max(0))
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 {
        year / 400
    } else {
        (year - 399) / 400
    };
    let year_of_era = year - era * 400;
    let month_adjusted = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_adjusted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

#[cfg(test)]
mod git_config_audit_tests {
    use super::{active_hooks_in, benign_git_config_entry};
    use omasafe_core::bounds::MAX_FILES;
    use std::fs;

    const ORIGIN: &str = "https://plugins.test/cli.git";

    #[test]
    fn executable_and_redirecting_keys_are_refused() {
        // Git executes these through the shell or redirects dataflow with
        // them; every one must fail closed by absence from the allowlist.
        for key in [
            "gc.recentObjectsHook",
            "gc.recentobjectshook",
            "gc.logExpiry",
            "core.hooksPath",
            "core.sshCommand",
            "core.fsmonitor",
            "core.askPass",
            "credential.helper",
            "diff.external",
            "gpg.program",
            "alias.!sh",
            "filter.lfs.smudge",
            "include.path",
            "includeif.gitdir/.path",
            "remote.origin.insteadof",
            "remote.origin.partialclonefilter",
            "remote.origin.mirror",
            "submodule.foo.update",
            "protocol.ext.allow",
        ] {
            assert!(
                !benign_git_config_entry(key, "value", ORIGIN),
                "{key} must be refused"
            );
        }
    }

    #[test]
    fn origin_url_and_refspec_are_value_validated() {
        assert!(benign_git_config_entry(
            "remote.origin.url",
            "https://plugins.test/cli.git",
            ORIGIN
        ));
        // Trailing-slash spelling of the same origin is tolerated.
        assert!(benign_git_config_entry(
            "remote.origin.url",
            "https://plugins.test/cli.git/",
            ORIGIN
        ));
        for value in [
            "https://evil.example/steal.git",
            "ext::sh -c touch /tmp/x",
            "/tmp/local-repo",
            "git@plugins.test:cli.git",
        ] {
            assert!(
                !benign_git_config_entry("remote.origin.url", value, ORIGIN),
                "origin url {value} must be refused"
            );
        }
        assert!(benign_git_config_entry(
            "remote.origin.fetch",
            "+refs/heads/*:refs/remotes/origin/*",
            ORIGIN
        ));
        assert!(!benign_git_config_entry(
            "remote.origin.fetch",
            "+refs/*:refs/*",
            ORIGIN
        ));
    }

    #[test]
    fn benign_lifecycle_entries_pass() {
        for (key, value) in [
            ("core.repositoryformatversion", "0"),
            ("core.filemode", "true"),
            ("core.bare", "false"),
            ("core.logallrefupdates", "true"),
            ("user.name", "OmaSafe Operator"),
            ("user.email", "operator@example.invalid"),
            ("init.defaultbranch", "main"),
            ("remote.origin.url", ORIGIN),
            ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"),
            ("branch.main.remote", "origin"),
            ("branch.main.merge", "refs/heads/main"),
            ("pull.rebase", "merges"),
            ("fetch.prune", "false"),
            ("push.default", "simple"),
        ] {
            assert!(
                benign_git_config_entry(key, value, ORIGIN),
                "{key}={value} must be allowed"
            );
        }
        // Section/variable case-insensitivity; subsection case-sensitivity.
        assert!(benign_git_config_entry(
            "CORE.RepositoryFormatVersion",
            "0",
            ORIGIN
        ));
        assert!(benign_git_config_entry(
            "branch.MAIN.remote",
            "origin",
            ORIGIN
        ));
        // A tracking remote that is not a configured remote name is refused.
        assert!(!benign_git_config_entry(
            "branch.main.remote",
            "/tmp/local-repo",
            ORIGIN
        ));
    }

    #[test]
    #[cfg(unix)]
    fn active_hook_audit_bounds_entries() {
        let root = tempfile::tempdir().unwrap();
        let hooks = root.path().join(".git/hooks");
        fs::create_dir_all(&hooks).unwrap();
        for index in 0..=MAX_FILES {
            fs::write(hooks.join(format!("hook-{index:05}")), "#!/bin/sh\n").unwrap();
        }
        let error = active_hooks_in(root.path()).unwrap_err();
        assert!(error.contains("more than"), "{error}");
    }
}

#[cfg(test)]
mod s5_reader_tests {
    use super::*;
    use omasafe_analyzer::{CoverageState, PayloadEntry, PayloadKind};
    use std::fs;

    fn record(path: &str, size: u64, digest_hex: Option<&str>) -> PayloadEntry {
        PayloadEntry {
            relative_path: path.to_owned(),
            kind: PayloadKind::TextFile,
            mode: 0o644,
            size,
            sha256_sampled: digest_hex.map(str::to_owned),
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Analyzed,
            link_target: None,
            invocation_target: false,
            object_id: None,
        }
    }

    fn digest_hex(bytes: &[u8]) -> String {
        use sha2::Digest as _;
        let digest = sha2::Sha256::digest(bytes);
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn filesystem_reader_enforces_digest_size_and_file_type() {
        let temp = tempfile::tempdir().unwrap();
        let content = b"stable payload bytes\n".to_vec();
        fs::write(temp.path().join("data.txt"), &content).unwrap();
        let reader = pinned_filesystem_reader(temp.path().to_path_buf());
        let matching = record(
            "data.txt",
            content.len() as u64,
            Some(&digest_hex(&content)),
        );
        assert_eq!(reader(&matching).as_deref(), Some(content.as_slice()));

        // Size drift fails even with a matching digest.
        let short_entry = record(
            "data.txt",
            content.len() as u64 - 1,
            Some(&digest_hex(&content)),
        );
        assert!(reader(&short_entry).is_none());

        // Content drift under the recorded size fails the digest check.
        let tampered = b"tampered payload byte\n".to_vec();
        fs::write(temp.path().join("data.txt"), &tampered).unwrap();
        assert!(reader(&matching).is_none());

        // A swapped-in symlink is never followed.
        fs::write(temp.path().join("evil.txt"), b"evil\n").unwrap();
        fs::remove_file(temp.path().join("data.txt")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(temp.path().join("evil.txt"), temp.path().join("data.txt"))
            .unwrap();
        assert!(reader(&matching).is_none());

        // Sampled entries carry no full digest to verify against.
        let mut sampled = record("data.txt", 0, None);
        sampled.sampled_digest = true;
        assert!(reader(&sampled).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_reader_rejects_swapped_in_special_files() {
        use std::ffi::CString;

        let temp = tempfile::tempdir().unwrap();
        let content = b"expected\n";
        fs::write(temp.path().join("data.txt"), content).unwrap();
        let reader = pinned_filesystem_reader(temp.path().to_path_buf());
        let record = record("data.txt", content.len() as u64, Some(&digest_hex(content)));

        let fifo = CString::new(temp.path().join("data.txt").to_str().unwrap().as_bytes()).unwrap();
        fs::remove_file(temp.path().join("data.txt")).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        // O_NONBLOCK keeps the open from hanging; the fstat check rejects it.
        assert!(reader(&record).is_none());
    }

    #[test]
    fn git_reader_rejects_missing_objects_and_bad_digests() {
        let temp = tempfile::tempdir().unwrap();
        let reader = pinned_git_reader(temp.path().to_path_buf());
        let mut record = record("blob", 4, Some(&digest_hex(b"body")));
        record.object_id = Some("0000000000000000000000000000000000000000".to_owned());
        assert!(reader(&record).is_none());

        // Missing object id or missing sample digest read as None.
        record.object_id = None;
        assert!(reader(&record).is_none());
        record.object_id = Some("abc".to_owned());
        record.sha256_sampled = None;
        assert!(reader(&record).is_none());
    }
}

#[cfg(all(test, unix))]
mod config_guard_tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const ORIGIN: &str = "https://plugins.test/cli.git";

    fn empty_flow() -> (UpdateFlowRecord, tempfile::TempDir) {
        let state = tempfile::tempdir().unwrap();
        let record = UpdateFlowRecord {
            schema_version: 1,
            plugin_id: "io.example.cfg".into(),
            candidate_commit: "0".repeat(40),
            started_at: "now".into(),
            phase: "delegating".into(),
            quiesced: Vec::new(),
            config_backup: None,
            config_target: None,
            config_original_mode: None,
        };
        (record, state)
    }

    /// installed_dir with a `.git/config` of `original` bytes at `mode`.
    fn installed(original: &[u8], mode: u32) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let git = dir.path().join(".git");
        fs::create_dir_all(&git).unwrap();
        let config = git.join("config");
        fs::write(&config, original).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(mode)).unwrap();
        dir
    }

    #[test]
    fn clean_window_restores_original_bytes_and_mode() {
        let original = b"[core]\n\trepositoryformatversion = 0\n[custom]\n\tkeep = yes\n";
        let install = installed(original, 0o640);
        let config = install.path().join(".git").join("config");
        let (mut flow, state) = empty_flow();
        let flow_path = state.path().join("review-update.json");
        let backup = flow_path.with_extension("config-backup");

        let guard = GitConfigGuard::swap_to_hardened(
            install.path(),
            ORIGIN,
            &backup,
            &mut flow,
            &flow_path,
        )
        .unwrap();
        // During the window the config is the hardened minimal snapshot and a
        // durable backup of the original exists and is referenced.
        assert_ne!(fs::read(&config).unwrap(), original.to_vec());
        assert_eq!(fs::read(&backup).unwrap(), original.to_vec());
        assert!(flow.config_backup.is_some());

        assert!(
            matches!(guard.restore(), RestoreOutcome::Clean),
            "clean window restores cleanly"
        );
        assert_eq!(fs::read(&config).unwrap(), original.to_vec());
        assert_eq!(
            fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o640,
            "original mode is preserved"
        );
        // restore() no longer deletes the backup; the caller does that only
        // after positively clearing and persisting the recovery record.
        assert!(backup.exists(), "backup retained for the caller to clear");
    }

    #[test]
    fn write_and_revert_is_detected_by_the_witness() {
        // A racing writer injects a directive (atomic replace), lets Git
        // "consume" it, then restores the EXACT hardened bytes before restore
        // runs. Bytes match afterwards, but the inode changed — the witness
        // catches it and restore fails closed.
        let original = b"[core]\n\trepositoryformatversion = 0\n";
        let install = installed(original, 0o644);
        let config = install.path().join(".git").join("config");
        let (mut flow, state) = empty_flow();
        let flow_path = state.path().join("review-update.json");
        let backup = flow_path.with_extension("config-backup");

        let guard = GitConfigGuard::swap_to_hardened(
            install.path(),
            ORIGIN,
            &backup,
            &mut flow,
            &flow_path,
        )
        .unwrap();
        let hardened = fs::read(&config).unwrap();

        // Inject via atomic replace (new inode)...
        let injected = install.path().join(".git").join("config.attacker");
        fs::write(&injected, b"[core]\n[filter \"x\"]\n\tsmudge = payload\n").unwrap();
        fs::rename(&injected, &config).unwrap();
        // ...then restore the exact hardened bytes, also via atomic replace.
        let revert = install.path().join(".git").join("config.revert");
        fs::write(&revert, &hardened).unwrap();
        fs::rename(&revert, &config).unwrap();
        assert_eq!(fs::read(&config).unwrap(), hardened, "bytes match again");

        assert!(
            matches!(guard.restore(), RestoreOutcome::Tampered),
            "write-and-revert must be detected by the witness"
        );
        // The audited original is still restored despite the tamper verdict.
        assert_eq!(fs::read(&config).unwrap(), original.to_vec());
    }

    #[test]
    fn reconcile_restores_target_from_durable_backup() {
        // Simulate a mid-window death: the target holds the hardened snapshot,
        // a durable backup of the original exists, and the record points at
        // both. Reconciliation must put the original back with its mode and
        // clear the swap state.
        let original = b"[core]\n\trepositoryformatversion = 0\n[keep]\n\tx = 1\n";
        let install = installed(b"[core]\n\thardened = snapshot\n", 0o600);
        let config = install.path().join(".git").join("config");
        let (mut flow, state) = empty_flow();
        let flow_path = state.path().join("review-update.json");
        let backup = flow_path.with_extension("config-backup");
        fs::write(&backup, original).unwrap();
        flow.config_backup = Some(backup.to_string_lossy().into_owned());
        flow.config_target = Some(config.to_string_lossy().into_owned());
        flow.config_original_mode = Some(0o640);
        flow.store(&flow_path).unwrap();

        reconcile_config_backup(&mut flow, &flow_path).expect("reconcile succeeds");

        assert_eq!(fs::read(&config).unwrap(), original.to_vec());
        assert_eq!(
            fs::metadata(&config).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert!(!backup.exists(), "backup removed after reconcile");
        assert!(flow.config_backup.is_none(), "swap state cleared");
        // Idempotent: a second reconcile with cleared state is a no-op.
        reconcile_config_backup(&mut flow, &flow_path).expect("idempotent no-op");
        assert_eq!(fs::read(&config).unwrap(), original.to_vec());
    }

    #[test]
    fn restore_failure_preserves_backup_and_recovery_pointer() {
        // If the original cannot be reinstalled, RestoreFailed is reported and
        // the durable backup + recovery pointer are preserved (not orphaned),
        // so a later run can reconcile the target.
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores the directory write bit that forces failure
        }
        let original = b"[core]\n\trepositoryformatversion = 0\n";
        let install = installed(original, 0o644);
        let git = install.path().join(".git");
        let (mut flow, state) = empty_flow();
        let flow_path = state.path().join("review-update.json");
        let backup = flow_path.with_extension("config-backup");

        let guard = GitConfigGuard::swap_to_hardened(
            install.path(),
            ORIGIN,
            &backup,
            &mut flow,
            &flow_path,
        )
        .unwrap();
        // Make `.git` unwritable so restore's temp creation fails.
        fs::set_permissions(&git, fs::Permissions::from_mode(0o500)).unwrap();

        let outcome = guard.restore();
        // Re-permit writes so Drop's retry and cleanup can proceed.
        fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            matches!(outcome, RestoreOutcome::RestoreFailed(_)),
            "unrestorable window must report RestoreFailed"
        );
        // The durable backup and its pointer survive for recovery.
        assert!(backup.exists(), "backup preserved on restore failure");
        assert!(
            flow.config_backup.is_some(),
            "recovery pointer preserved on restore failure"
        );
        assert_eq!(fs::read(&backup).unwrap(), original.to_vec());
    }

    #[test]
    fn reconcile_blocks_when_referenced_backup_is_missing() {
        // A record still references a backup, but the file is gone: the target
        // cannot be verified back to the original, so reconcile must fail
        // closed rather than silently treat it as completed.
        let install = installed(b"[core]\n\thardened = snapshot\n", 0o600);
        let config = install.path().join(".git").join("config");
        let (mut flow, state) = empty_flow();
        let flow_path = state.path().join("review-update.json");
        let missing = flow_path.with_extension("config-backup");
        flow.config_backup = Some(missing.to_string_lossy().into_owned());
        flow.config_target = Some(config.to_string_lossy().into_owned());
        flow.config_original_mode = Some(0o644);

        let error =
            reconcile_config_backup(&mut flow, &flow_path).expect_err("missing backup must block");
        assert!(error.contains("unavailable"), "{error}");
        // The pointer is NOT cleared, so the caller keeps blocking.
        assert!(flow.config_backup.is_some());
    }

    #[test]
    fn hardened_config_neutralizes_a_smudge_filter() {
        use std::process::Command;
        // Under root, worktree filters and perms behave differently; skip.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let install = tempfile::tempdir().unwrap();
        let repo = install.path();
        let marker_dir = tempfile::tempdir().unwrap();
        let marker = marker_dir.path().join("smudge-ran");

        let git = |args: &[&str]| {
            let status = Command::new("git")
                .current_dir(repo)
                .args(args)
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?}");
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "t@t.invalid"]);
        git(&["config", "user.name", "t"]);
        fs::write(repo.join("file.txt"), "hello\n").unwrap();
        fs::write(repo.join(".gitattributes"), "file.txt filter=evil\n").unwrap();
        git(&["add", "file.txt", ".gitattributes"]);
        git(&["commit", "-q", "-m", "init"]);
        // Malicious smudge filter: create a marker when it runs.
        let smudge = format!("touch '{}'", marker.display());
        git(&["config", "filter.evil.smudge", &smudge]);

        // Positive control: with the filter defined, a forced checkout runs it.
        fs::remove_file(repo.join("file.txt")).unwrap();
        git(&["checkout", "--", "file.txt"]);
        assert!(
            marker.exists(),
            "positive control: the smudge payload runs without hardening"
        );
        fs::remove_file(&marker).unwrap();

        // Under the guard the hardened config defines no filter, so the same
        // forced checkout must NOT run the payload during the window.
        let (mut flow, state) = empty_flow();
        let flow_path = state.path().join("review-update.json");
        let backup = flow_path.with_extension("config-backup");
        let guard =
            GitConfigGuard::swap_to_hardened(repo, ORIGIN, &backup, &mut flow, &flow_path).unwrap();
        fs::remove_file(repo.join("file.txt")).unwrap();
        git(&["checkout", "--", "file.txt"]);
        assert!(
            !marker.exists(),
            "hardened config must neutralize the smudge filter during the window"
        );
        assert!(matches!(guard.restore(), RestoreOutcome::Clean));
    }

    #[test]
    fn swap_refuses_a_symlinked_config() {
        // .git/config is a symlink to an outside file: hardening must refuse
        // rather than follow it (which would expose/overwrite the target).
        let dir = tempfile::tempdir().unwrap();
        let git = dir.path().join(".git");
        fs::create_dir_all(&git).unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, b"victim\n").unwrap();
        std::os::unix::fs::symlink(&outside, git.join("config")).unwrap();
        let (mut flow, state) = empty_flow();
        let flow_path = state.path().join("review-update.json");
        let backup = flow_path.with_extension("config-backup");

        let error = match GitConfigGuard::swap_to_hardened(
            dir.path(),
            ORIGIN,
            &backup,
            &mut flow,
            &flow_path,
        ) {
            Ok(_) => panic!("symlinked config must be refused"),
            Err(error) => error,
        };
        assert!(error.contains("not a regular file"), "{error}");
        assert_eq!(fs::read(&outside).unwrap(), b"victim\n".to_vec());
    }
}
