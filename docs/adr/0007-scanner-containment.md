# ADR 0007: Containment of scanner processes

Status: proposed, feasibility-gated · 2026-09-11 · target v0.4

## Context

The v0.3.1 candidate route fetches bare Git objects and statically analyzes
them without checkout. The reviewed-update route materializes a temporary tree.
Neither has a dedicated OS sandbox. The v0.3.2 plan independently hardens the
runner, Git environment, temporary paths, and evidence projection.

Containment introduces a runtime backend, worker protocol, execution metadata,
hard storage limits, the first explicit object-cache format version, and a
persistent evidence store. These belong in a following minor release rather
than blocking the patch. Baseline source: commit
`97961acdedab8c72e94b33423c69d4d426300235`; use symbols for code references.

## Proposed decision

Prototype Bubblewrap namespaces with verified cgroup v2 limits, coordinated
through a transient systemd user service. Workers are a hidden subcommand of
the same CLI binary, with fixed typed supervisor channels and no lifecycle
operations. The runner denies the worker entrypoint. The supervisor verifies
setup and authors execution facts; hidden naming is not a security boundary.

Fetch has a private filesystem and hard writable-storage limit but initially
shares the host network namespace. Ordinary Git is HTTPS-only. Filesystem-path
host sockets are not mounted; abstract Unix sockets and network listeners can
remain reachable. Do not claim complete host-service isolation before a network
broker. The analyzer uses a separate network namespace and read-only captured
inputs. Reuse its local-path profile for installed per-plugin and timer analysis;
host inventory/posture and lifecycle coordination remain outside it.

Required mode fails visibly if setup cannot enforce the specified profile. The
backend matrix must include headless sessions without a systemd user manager,
where `systemd-run --user` is unavailable, missing/full runtime directories,
disabled user namespaces, and unavailable cgroup controllers. No silent fallback.
Prefer `$XDG_RUNTIME_DIR/omasafe/`; a validated private cache fallback does not
replace a missing manager or supply a hard quota.

Seccomp is separately sized stretch work: a dangerous-syscall denylist compiled
to BPF, not a broad syscall allowlist fragile across Git/curl upgrades. Candidate
crate `seccompiler` requires review before any manifest change. Existing `libc`
and v0.3.2's reviewed `libc`-backed path hardening are the baseline; `tempfile`
remains dev-only after dependency review. `nix` and `cap-std` are not selected.
Declare whether seccomp was actually applied.

## Consequences and acceptance

The backend remains provisional until real kernel denial, whole-process-tree,
storage, resource, and unsupported-environment tests pass. Include hostile-server
ref floods, slow-loris transfers, and high-ratio pack expansion. Exact versions
and capabilities become release evidence. Installed per-plugin analysis must
preserve identity and timer/error semantics when reusing the worker.

Persistent report/evidence IDs contain at least 128 bits of CSPRNG randomness and
are scope/identity/expiry bound; randomness does not replace access checks.
The object-cache format/version is newly introduced, not a bump of an existing
constant. `MAX_CACHE_BYTES` is defined in `crates/omasafe-core/src/bounds.rs`.

This contains OmaSafe's own scanner processes, not running third-party Omarchy
plugins. It is not a VM, same-user-compromise defense, or benign-content verdict.

## References

- [Detailed v0.4 plan](../../../docs-vault/omasafe-Cli/plans/v0.4.md)
- [ADR 0006](0006-review-only-runner.md)
- [Bubblewrap](https://github.com/containers/bubblewrap)
- [Linux network namespaces](https://www.man7.org/linux/man-pages/man7/network_namespaces.7.html)

This ADR records a proposal, not implemented behavior or an accepted dependency.
