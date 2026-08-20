# OmaSafe — Trust & Security for Omarchy (Brainstorm)

Status: product and implementation reviews incorporated 2026-08-20 · Author: Hung Vo

This document is the frozen product context, thesis, and decision record. Version scope,
sequencing, sizing, and acceptance criteria live under [`docs/plans/`](plans/README.md).

## Context

- Omarchy (Quattro) plugins are QML + JavaScript loaded **unsandboxed, with full user
  permissions, inside the shared Omarchy shell process**. Plugin kinds: `bar-widget`,
  `panel`, `overlay`, `menu`, `service`, `bar`. Manifest = `manifest.json`, IDs use
  reverse-domain notation, installed via `omarchy plugin add {git-url} --enable`.
- The independent community marketplace has a real listing-time security program, not
  merely schema validation. Its deterministic Automated Security Baseline scans an exact
  approved commit, publishes rule/capability IDs, fails incomplete scans closed, and
  selectively blocks serious findings. It still explicitly disclaims a security audit or
  guarantee, and later upstream commits are outside the stored listing result.
- The 2026-08-20 catalog snapshot contains **689 listings**: 653 community and 36 built-in.
  Of the community listings, 297 are unverified and 274 have an upstream-observed commit
  different from the listing-validated commit. The catalog already exposes the commit and
  verification metadata OmaSafe needs for local correlation.
- Omarchy is Arch-based. Official installs use Arch and Omarchy repositories by default;
  AUR packages are optional but common among advanced users. AUR has had real malware
  incidents (e.g., the July 2025 CHAOS RAT packages), and plugins-as-git-repos have a
  similar supply-chain shape: community code that can change between revisions.

That combination — unsandboxed plugins, commit-bound listing checks, mutable Git installs,
and no local trust/drift view — is the gap this product fills. Working name: **OmaSafe**
(`io.github.<user>.omasafe`).

## Product Focus

**OmaSafe is the local trust layer for Omarchy community code.** Its primary job is to
answer after installation:

1. What exact plugin revision is installed on this machine?
2. Is that revision listed, verified, or the commit the marketplace validated?
3. What changed since I trusted or last reviewed it?
4. What shipped payloads and security-relevant capabilities should a human review?

Inventory, registry correlation, commit/tree identity, update diffs, and drift alerts are
the differentiator. Static rules are reviewer aids: a motivated attacker can evade a rule,
but a correctly pinned tree still reveals that code changed. General Linux posture checks
are useful supporting context, but they must not turn OmaSafe into an unfocused security-
tool installer or imply that a single score proves a machine is secure.

## Feature Areas

These are product concepts, not release scope. The version plans are authoritative.

### 1. Security Posture & Regression Dashboard

Read-only checks shown in the bar widget and panel. The first release uses severity and
change state (`critical regression`, `needs attention`, `informational`, `unchanged`),
not a universal letter grade. A score can be considered later after the checks have been
validated on real Omarchy installations.

Checks (all doable without root, or via polkit for the few that need it):

- **Disk encryption**: walk the block-device stack backing `/` and confirm LUKS is present.
  Omarchy enables LUKS by default, so loss of encryption is a regression, not a novel
  hardening recommendation.
- **Secure Boot**: report status as informational by default. Omarchy currently expects
  Secure Boot to be disabled for installation, so disabled must not produce a warning.
- **Firewall**: inspect the effective nftables/ufw rules, not merely whether a frontend
  service is active. Show listening addresses and ports. Process ownership from
  `ss -tlnp` may be incomplete without elevated permissions, and the UI must say so.
- **SSH hardening** (if sshd enabled): PermitRootLogin, PasswordAuthentication, port.
- **Updates**: run `checkupdates` once and distinguish updates (exit 0), successful empty
  result (exit 2), and operational failure (exit 1). It syncs only a temporary database
  under `fakeroot`; OmaSafe never syncs the system pacman database. Filter that successful
  result for `omarchy`/`omarchy-dev` instead of trusting `omarchy update available`, which
  can conflate an underlying error with “up to date.” The only supported full-update action
  is `omarchy update`. A verified `post-update` hook may record an OmaSafe-observed success
  time; a missing/unverified stamp means unknown.
- **Known vulnerabilities**: use `arch-audit`/Arch Security Tracker for matching official
  packages, while clearly stating its coverage limits; it is not an AUR vulnerability
  database.
- **Kernel staleness**: running kernel ≠ installed kernel → reboot needed.
- **Pacman trust**: keyring initialized/updated; scheduled (not frequent) `pacman -Qkk`
  metadata/integrity checks; foreign package inventory (`pacman -Qm`) shown as additional
  review surface, not automatically malicious.
- **Account hygiene**: passwordless accounts, `NOPASSWD` sudoers entries, users in
  unexpected privileged groups, and recent failed logins where permissions allow. Some
  authoritative checks require elevation and must be labelled incomplete without it.
- **Service hardening**: `systemd-analyze security` as informational sandbox-exposure
  analysis. A high exposure score is not proof of a vulnerability and should not be a
  critical finding by itself.
- **Persistence surfaces**: new/changed entries in `~/.config/autostart`, systemd user
  units, shell rc files, `~/.config/omarchy/plugins/` — baseline + diff (see §6).
- **Misc**: world-writable directories on `$PATH`, microcode availability, and logging
  configuration. Opinionated controls such as DNS-over-TLS or AppArmor belong in an
  optional profile, not the default score.

Bar widget = shield icon + alert count; it turns red only for a critical regression or a
new high-impact vulnerability affecting an installed package. The quiet state should be
calm rather than continuously grading the user.

### 2. AUR / Package Risk Scanner

Pre-install and on-demand review of AUR packages:

- **PKGBUILD static analysis**: flag `curl | bash`, `eval`, base64 blobs, `SKIP`
  checksums, sources fetched over plain HTTP, sources from non-canonical hosts, install
  scriptlets (`.install` files) doing network or writing outside $pkgdir, binary blobs in
  `-bin` packages without upstream signature verification.
- **Metadata heuristics** (AUR RPC): package age, current maintainer, votes/popularity,
  orphaned status, and out-of-date flag age. Do not claim maintainer tenure or ownership
  changes from the RPC response. Git authorship is not authoritative ownership history;
  takeover detection stays deferred unless a reliable data source is identified.
- **Update diffing**: show the PKGBUILD diff since last install before an AUR helper
  upgrade (what `paru --review` does, surfaced in the UI).
- **Installed-package audit**: periodic `arch-audit` sweep + list of foreign packages with
  their risk notes.
- Integration point: could ship a pacman hook + AUR-helper wrapper so scans happen at
  install time, not just in the panel.

### 3. Plugin Capability Analyzer

The marketplace already performs a deterministic listing-time baseline on an exact commit.
OmaSafe adds local analysis for an installed tree, a candidate update, an unlisted Git URL,
or a commit that moved beyond the marketplace result:

The analyzer is an **evidence-backed heuristic capability analyzer**, not a malware
detector and not a proof that a plugin is safe. QML is not plain JavaScript, so a
JavaScript parser alone is insufficient. Start with a QML-aware parser/tokenizer, analyze
embedded JavaScript where it can be parsed safely, and retain a lower-confidence lexical
fallback for unsupported syntax. Every result records the rule, capability, severity or
confidence, file, line, explanation, and a safe excerpt. Suppressions must be explicit,
local, reviewable, and never hide findings silently.

- **Manifest checks**: ID not `omarchy.*`, no symlinks, declared kinds match shipped files.
- **Shipped-payload inventory**: enumerate every relevant QML, JavaScript, shell, Python,
  executable, binary, and extensionless file with type, mode, size, and coverage status.
  Detect QML references/invocation edges to bundled payloads even when the payload language
  is not yet parsed.
- **QML/JS static analysis**: flag `Process`/process spawning, network calls
  (XMLHttpRequest/fetch), filesystem writes outside the plugin dir, `eval`/`Function`,
  obfuscated or base64-packed strings, reading `~/.ssh`, browser profiles, keyrings,
  crypto-wallet paths, clipboard monitoring in a `service` kind.
- **Repo heuristics**: repo age, commit history shape (force-pushes, single squash commit
  of a large codebase), author identity.
- **Shared-shell sensitive APIs**: flag third-party access to polkit, PAM/session-lock,
  lock-surface, and related authentication UI APIs. Omarchy's polkit agent and lock screen
  share the same unsandboxed shell process as community plugins; this is an architectural
  exposure a scanner can disclose but not fix.
- **Capability summary**: present a human-readable "this plugin appears able to: run
  processes, access network, read files" report. Do not call it a permission prompt:
  OmaSafe can describe capabilities but Omarchy does not currently enforce them.
- **VirusTotal (optional, off by default)**: hash-lookup shipped binaries/blobs and scan
  the repo URL via VT API. Caveats: needs user's API key; free tier is 4 req/min, 500/day;
  **uploading a file to VT makes it available to other researchers** — hash-lookup by
  default, upload only with explicit confirmation. Prefer local heuristics as the primary
  signal; VT is a secondary reputation check.
- **Post-install pinning**: record the installed commit hash; on plugin update, show the
  diff and re-scan it (TOFU model — the biggest real threat is a previously trusted plugin
  changing later). Blocking new code *before it loads* requires OmaSafe's CLI/wrapper to
  control the update path or an upstream Omarchy integration; a plugin cannot guarantee
  this merely by watching its own directory.

### 4. Optional Hardening Installers (one-click, via polkit)

Curated "install & configure sensibly" actions, each with a plain-English tradeoff note:

- **OpenSnitch**: per-application outbound firewall — higher value than AV on a desktop;
  catches exfiltration from a malicious plugin/AUR package. First installer we ship.
- **USBGuard**: block unknown USB devices when locked.
- **fail2ban**: only offered if sshd is enabled and exposed.
- **AIDE or paccheck-based integrity baseline** (advanced).
- **ClamAV** *(deferred — later optional add-on)*: install, enable `freshclam`, optional
  on-access scanning (`clamonacc`) on ~/Downloads only. Honest framing in the UI: high RAM
  (~1 GB+), most value for scanning downloads/mail and files passed to others, not a Linux
  rootkit defense.
- Each installer is idempotent, shows exactly the commands it will run, and requires
  explicit confirmation — never auto-install.

### 5. Separate Future Experiment: Agent Supply-Chain Integrations

This remains deliberately outside the core roadmap. If validated later, begin with explicit
inventory/baseline/diff of selected agent hooks, MCP definitions, and installed skills.
Automatic installation of dependency-guard or other agent tooling is a separate decision.
See [`plans/later.md`](plans/later.md); do not promote this into the local-plugin trust MVP.

### 6. Supporting Capabilities

- **Baseline & drift detection ("what changed?")**: snapshot autostarts, user services,
  shell rc, sudoers, pacman hook dirs, installed plugins; service kind diffs daily and
  notifies on change. Every alert needs `review`, `acknowledge & rebaseline`, and scoped
  exclusion actions so normal dotfile work does not create permanent alert fatigue.
- **Plugin update sentinel**: watch installed plugin revisions and alert on diffs. Enforce
  review before activation only when installation/update is performed through OmaSafe or
  when Omarchy provides a supported pre-activation integration point.
- **Secrets hygiene sweep**: explicit opt-in, local-only checks for plaintext keys in
  selected dotfiles/env files (`AWS_SECRET`, private keys with loose permissions,
  `.npmrc` tokens). Never persist or display secret values; report only type and location.
- **Network snapshot**: current listening ports + established connections by process, with
  "expected on Omarchy" allowlist; one glance answers "is anything phoning home?"
- **Security news feed**: Arch security advisories (security.archlinux.org RSS) filtered
  to *installed* packages only — actionable, zero noise.
- **Panic workflow** (later, advanced): lock the session and capture a local diagnostic
  snapshot. Network isolation is a separate, explicitly confirmed action because it can
  terminate remote support and is not fully implemented by `rfkill` on wired interfaces.
- **Report export**: posture report as Markdown/JSON — useful for compliance evidence
  (for us: MAS TRM-style workstation hygiene attestation).

## Architecture Sketch

```
omasafe/
├── cli/                     # primary, independently testable engine
│   ├── checks/              # posture/regression checks
│   ├── scanners/            # plugin and PKGBUILD scanners
│   └── contracts/           # versioned JSON schemas
├── plugin/                  # thin Omarchy UI face
│   ├── manifest.json        # bar-widget; add service only if required
│   ├── BarWidget.qml        # shield + alert badge
│   ├── Panel.qml            # nested panel rendered by BarWidget
│   └── Service.qml          # optional scheduler/notification bridge
└── docs/
```

Principles:

- **CLI is the engine; plugin is the face.** Heavy scans never run inside the QML/JS
  process. The CLI or systemd user timers write atomic, versioned JSON results; QML only
  invokes bounded commands and renders those results.
- **Privilege model**: everything read-only runs as the user. Later privileged actions
  use a small root-owned helper exposed through **polkit/pkexec with per-action prompts**.
  The helper accepts fixed action IDs and strictly validated typed arguments; it never
  accepts a shell command, arbitrary executable, or caller-controlled environment. Show
  the exact effect before confirmation. No daemon, general-purpose proxy, or NOPASSWD.
- **Check module + JSON contract** → independently testable; contributors can add checks
  without touching QML. Treat all command output as untrusted input and use argv-style
  process invocation, never `sh -c` with interpolated values.
- **Deterministic decisions**: rules, outcomes, severity, and automated policy are code and
  versioned data, never an LLM judgment. AI may help a human understand evidence but cannot
  decide trust, enforcement, or approval.
- **The plugin must be its own best advertisement**: zero external JS deps, pinned/signed
  releases, no hidden or unnecessary network traffic, and a published self-scan whose
  expected capabilities are explained and whose high-severity findings are all resolved.

## Decisions (agreed 2026-08-20)

1. **Engine/face split**: ship `omasafe-cli` as the scanning engine (installable via AUR,
   usable on plain Arch) with the Omarchy plugin as a thin UI face. The CLI owns scanning,
   state, schemas, and enforcement; QML owns presentation.
2. **VirusTotal: deferred.** Local static analysis + AUR heuristics are the primary
   signal; VT lands later as opt-in hash-lookup only (no uploads without confirmation).
3. **ClamAV: deferred to a later optional add-on.** Not in the initial installer set;
   OpenSnitch ships first (better value-per-MB on a desktop).
4. **Notification cadence**: daily quiet sweep; notify only on regressions and new CVEs;
   weekly digest otherwise. Start with severity/change state, not a universal grade.
5. **Naming/branding**: OmaSafe, ID `io.github.<user>.omasafe`; never imply official
   Omarchy affiliation (registry forbids `omarchy.*` IDs) — say "for Omarchy".
6. **Analyzer contract**: report evidence and confidence, not a safe/malicious verdict.
   Use QML-aware analysis plus parsed embedded JavaScript where feasible; clearly label
   lexical fallbacks and limitations.
7. **Privileged-action contract**: QML can request only fixed action IDs with validated
   arguments. It can never send an arbitrary command string through `pkexec`.
8. **Local trust first**: ship inventory, catalog correlation, revision identity, and diff
   before parser-heavy capability analysis.
9. **Marketplace interoperability without delegated trust**: consume a catalog file pinned
   to its repository commit as untrusted, time-bound claims. Registry data can add context
   but never suppress local signals. Keep OmaSafe-owned rule IDs and version mappings to
   equivalent marketplace rules so upstream changes cannot silently redefine findings.

## Phasing (agreed)

| Phase | Scope |
|-------|-------|
| [v0.1](plans/v0.1.md) | Local plugin trust: installed inventory, catalog correlation, commit/tree identity, diff, baseline, and drift alerts |
| [v0.2](plans/v0.2.md) | Payload-aware capability analyzer, QML-to-payload edges, shared-shell sensitive APIs, and reviewed update workflow |
| [v0.3](plans/v0.3.md) | AUR/PKGBUILD static analyzer and update review without executing build files |
| [v0.4](plans/v0.4.md) | Posture regressions, reliable `checkupdates` states, optional arch-audit, and actionable notifications |
| [v0.5](plans/v0.5.md) | Narrow polkit remediation helper, first hardening installer, report export, and advanced drift detection |
| [Later](plans/later.md) | Secrets sweep, panic workflow, ClamAV, VirusTotal hash lookups, AIDE, and experimental integrations |

The implementation sequence, shared engineering rules, and release dependencies live in
[`docs/plans/README.md`](plans/README.md).

## Omarchy Update Integration

| Need | Supported mechanism |
|------|---------------------|
| List pending Arch/Omarchy-repository packages without changing the system | `checkupdates --nocolor`; it syncs only a temporary database under `fakeroot`, never the system database |
| Check whether packaged Omarchy has an update | Filter the successfully completed `checkupdates` result for the installed `omarchy`/`omarchy-dev` package |
| Check whether a development checkout has an update | Independently fetch its configured Git upstream and compare `HEAD..<upstream>`, preserving every failure state |
| Apply a complete supported update | `omarchy update` (interactive) |
| Record an OmaSafe-observed successful-update time | Install and self-test a minimal `post-update` timestamp hook; missing/unverified state means `unknown` |

`checkupdates` exits 0 when updates exist, 2 when the check succeeded with no updates, and
1 on operational failure. `omarchy update available` suppresses the underlying
`checkupdates` error and can conflate failure with "up to date," so it is not authoritative
enough for OmaSafe's three-state check. OmaSafe still directs users to `omarchy update` for
the supported full update workflow and never syncs the system pacman database directly.

## References

- Plugin dev docs: https://omarchyplugins.com/develop.html
- Plugin publishing/security-validation scope: https://omarchyplugins.com/publish.html
- Registry: https://omarchyplugins.com/index.html
- Marketplace catalog source repository (runtime snapshots pin a repository commit):
  https://github.com/HANCORE-linux/omarchy-plugin-marketplace/blob/main/site/catalog.json
- Marketplace security baseline: https://github.com/HANCORE-linux/omarchy-plugin-marketplace/blob/main/SECURITY.md
- Omarchy security defaults: https://learn.omacom.io/2/the-omarchy-manual/93/security
- Omarchy update workflow: https://learn.omacom.io/2/the-omarchy-manual/68/updates
- Versioned Omarchy sink/threat inventory: [reference/omarchy-security-surface.md](reference/omarchy-security-surface.md)
- Arch Security Tracker: https://security.archlinux.org (arch-audit)
- Tools referenced: arch-audit, checkupdates, sbctl, ufw, ss, systemd-analyze security,
  pacman -Qkk/-Qm, ClamAV, OpenSnitch, USBGuard, fail2ban, AIDE, VirusTotal API
