# Review — OmaSafe brainstorm + implementation plans

Reviewer: Claude (Opus 5) · Date: 2026-08-20
Scope: `docs/brainstorm.md`, `docs/plans/{README,v0.1..v0.5,later}.md`
Verification: Omarchy 4.0.0-1, Quickshell 0.3.0, checked on this machine + primary sources

## Verdict

The security engineering is strong and unusually disciplined for a v0 plan. The non-verdict
analyzer contract, the untrusted-input rules, the "quiet ≠ secure" UX stance, and the
privileged-boundary design in v0.5 are better than most shipped security tools. Keep all of
that.

Two verified facts change the roadmap:

**1. A QML-only analyzer misses the payload.** Real third-party plugins ship and execute
non-QML code. On this machine, `lgse.sandman` ships `sandman.py` (19.5 KB) and
`sandman-configure-hibernate` (mode 755); `ilyazar.btop` ships `open-keybindings.sh`. Only
*entry points* must be QML — the repo can ship anything and the QML can exec it via
`Process` or `Quickshell.execDetached`. v0.1's analyzer, as scoped, would report a clean
QML surface for a plugin whose behavior lives entirely in a bundled Python file.

**2. The ecosystem is populated and already has listing-time scanning.** From the registry's
own `catalog.json` (generated 2026-08-20T07:04Z):

| Fact | Value |
|------|-------|
| Listed plugins | **689** (653 community, 36 built-in) |
| Community plugins marked `unverified` | **297 of 653 (45%)** |
| Plugins whose **upstream moved past the registry-validated commit** | **274 of 653 (42%)** |
| Registry security program | **Automated Security Baseline v4** — deterministic, listing-time, published rule IDs, non-bypassable blocking findings |
| Install path | 536/536 install commands are `omarchy plugin add` (uniform) |
| Plugin kinds | 590 bar-widget, 44 overlay, 33 service, 14 panel, 3 bar |
| Repository layouts | 648 root-plugin, 3 monorepo, 2 suite |

So the registry covers "was this repo acceptable at commit X." Nobody covers "what is
actually installed on this machine, was it ever validated, and what changed since I trusted
it" — and 42% of listings have already drifted past validation. That gap is the product.

**Headline recommendation: swap v0.1 and v0.2.** Ship the local trust layer first
(inventory, registry cross-reference, trusted commit, drift, diff). It needs no QML parser
at all, which defers the plan's biggest technical unknown behind a release that already
delivers value — and it is the half nobody else is building.

## Critical findings

### F1. A QML-only analyzer misses the payload — widen the scope or narrow the claim

Confirmed above. Consequences for the plan:

- v0.1's capability catalog must include a **shipped-payload inventory**: every non-QML
  file, its type, executable bit, size, and whether any QML references it. A 19 KB Python
  file plus a `Process` call is the finding, even when the Python is not parsed.
- Rule priority inverts. The interesting signal is *"QML invokes a bundled executable"*,
  not `eval` in QML. Detecting the invocation edge (QML → local file) matters more than
  understanding either side.
- Shell/Python analysis is currently planned for v0.3 (PKGBUILD). Either pull a minimal
  shell-script analyzer forward, or state explicitly in the report's coverage block that
  bundled scripts are inventoried but not analyzed. The second option is acceptable and
  honest; silently reporting "no findings" on such a plugin is not.
- The word **"sandbox" must not be borrowed from the Omarchy source**. `PluginRegistry.qml`
  uses it to mean path containment only (entry points cannot escape `sourceDir`; `..`,
  absolute paths, and symlinks are rejected). There is no runtime sandbox and no QML import
  allowlist. The brainstorm gets this right; keep it that way in user-facing copy.

### F2. Threat-model item the plan misses: the polkit agent shares the process

`omarchy plugin list --json` on this machine shows `omarchy.polkit` ("Polkit Agent", kind
`service`) as a plugin in the same registry, and the shell exposes
`Quickshell.Services.Polkit`, `WlSessionLock`, and the PAM services
`omarchy-lock-password` / `omarchy-lock-fingerprint`. **The polkit authentication agent and
the lock screen run in the same unsandboxed process as third-party community plugins.**

That reframes v0.5's privileged boundary. OmaSafe's own helper design is careful about what
QML can request — but any *other* installed plugin already shares a process with the
component that renders privilege-escalation prompts and handles lock-screen PAM. Actions:

- Add this to the threat model as a first-class item; it raises the severity of any
  third-party `service` plugin (33 in the registry) well above a bar widget.
- Add rules for plugins touching polkit, PAM, or session-lock APIs — for a third-party
  plugin these are near-zero-legitimacy capabilities.
- This is worth an upstream conversation with Omarchy independently of OmaSafe. It is a
  design-level exposure no scanner fixes.

### F3. Correct the premise, then reposition

`brainstorm.md` lines 11–14 understate the registry's program and call the ecosystem "very
new … an early ecosystem bet." Verified exact text from `publish.html`: *"The marketplace
validates listings, not plugin security. Plugins run unsandboxed."* and *"Automated
validation checks the current commit before a maintainer approves the listing."* Both doc
claims are literally accurate, but the doc omits Automated Security Baseline v4, which has
published rule IDs — `sudoers-dangerous-passwordless-command` and
`privileged-process-control-from-shared-temp` **block approval with no maintainer bypass** —
and a fixture corpus at `test/fixtures/security-baseline-v4/corpus.json`.

Actions:

- Rewrite Context with the real figures. The argument for OmaSafe gets *stronger*: 689
  plugins, 45% unverified, 42% drifted past validation, zero local tooling.
- Reposition Product Focus as explicitly **post-install and local** (see Verdict).
- **Align rule IDs and severity vocabulary with Baseline v4** where they overlap. Two tools
  describing the same plugin in different languages is a real UX cost and a free win.
- Adopt their norm, which matches yours: outcomes decided by deterministic code, not an
  LLM. Worth stating in the README to be credible in this ecosystem.
- Note the marketplace is an independent community project, not affiliated with Omarchy or
  37signals — relevant to how OmaSafe describes its relationship to both.

### F4. Consume the registry catalog — highest value-to-effort item in the plan

`catalog.json` is public and carries, per plugin: `listingValidatedCommit`,
`listingValidatedAt`, `upstreamObservedCommit`, `upstreamValidatedCommit`,
`upstreamCheckStatus`, `verificationStatus`, `repo`, `kind`, `installCommand`,
`repositoryLayout`. With one cached fetch and no static analysis, OmaSafe can say:

- This installed plugin is **unverified** by the registry (45% of community plugins are).
- Your installed commit **is not** the commit the registry validated.
- Upstream has **moved past** the validated commit (42% of listings have).
- This plugin **is not listed in the registry at all** — installed by direct Git URL, so it
  never passed even listing-time validation.

The last case is where malicious plugins will actually live, and nobody can see it today.
Make this its own v0.1 milestone, with graceful offline behavior, and treat the catalog as
untrusted input.

Note: `omarchy plugin list --json` (verified working) returns only
`id, name, kinds, enabled, active, canDisable, firstParty, clonedFrom` — **no path, source
URL, or commit**. Provenance must come from the filesystem plus Git, exactly as v0.2 M1
assumes. Also `omarchy plugin update [id]` already exists natively, so OmaSafe's staged
updater competes with a command users already have; plan to detect its use rather than
assume users route through OmaSafe.

### F5. Diff and drift is the differentiator; the rule engine is the garnish

An attacker who knows OmaSafe exists defeats the rule catalog cheaply: split strings,
`Qt.atob`, property-name indirection, fetch at runtime, or — per F1 — put the logic in a
bundled script. Revision pinning plus diff survives all of it, because it reports *change*
regardless of whether any rule understands the change, and it is cheaper to build.

Add `diff-plugin <ref-a>..<ref-b>` to the first release, and state the evasion posture in
Product Focus: *the value is disclosure and change-detection for a human reviewer, not
detection of malice.* That changes which rules are worth writing — the test becomes "does
this raise reviewer efficiency."

### F6. The sink inventory is now mostly answered — write it down and prioritize by kind

Verified: the shell is Quickshell 0.3.0 and plugins get the **full Quickshell + Qt Quick API,
unrestricted** — no import allowlist anywhere in `shell.qml` or `PluginRegistry.qml`.
Confirmed reachable sinks: `Process` (15 uses in `lgse.sandman` alone), `FileView`, `Timer`,
`Quickshell.execDetached` (the first-party menu uses it to run arbitrary bash from `action:`
strings), `Quickshell.Hyprland`, `Quickshell.Wayland`, `Quickshell.Services.Polkit`,
`WlSessionLock`, and the PAM lock services. 37 first-party plugin files import
`Quickshell.Io`.

So the research task is smaller than I first thought, but still required as a committed,
versioned document — re-verified per Omarchy release, since nothing gates these imports and
the surface will grow. Prioritize rules by the real distribution: the **33 `service`** and
**3 `bar`** plugins are the headless/whole-bar-replacing kinds and deserve far more rule
attention than 590 bar widgets.

### F7. The corpus problem is solved — use it, and set a false-positive budget

My earlier concern that rules would only be tuned on self-written fixtures is resolved:
**653 real community plugins** are a ready-made corpus, plus the marketplace's own baseline
fixture corpus for cross-checking rule agreement.

The release gate still needs teeth — "false-positive expectations are documented" fails
nothing. Make it **zero high-severity findings across the 653-plugin corpus**, enforced in
CI, with per-rule true/false-positive counts published. Any rule that cannot clear that bar
ships as informational or not at all. It is also the launch post: "we scanned all 689 listed
plugins."

Handle `repositoryLayout` explicitly: 3 monorepo and 2 suite layouts exist, and 114 entries
are "Manual setup" shell suites with their own installers rather than `omarchy plugin add`
targets. The plan assumes one plugin per repository root.

## Technical findings

### T1. v0.4 contains a self-contradiction: `checkupdates` runs `pacman -Sy`

v0.4's acceptance criteria say *"`pacman -Sy` is never executed or recommended"*, while M2
mandates `checkupdates`. Verified: `checkupdates` (from `pacman-contrib` 1.13.1) literally
runs `fakeroot -- pacman -Sy --dbpath "$CHECKUPDATES_DB" --logfile /dev/null` against a
throwaway database in `$TMPDIR`, with the real local DB symlinked in.

The tool choice is correct and safe; the wording is wrong. Restate as: *"never syncs the
system pacman database; `checkupdates` runs `pacman -Sy` against a temporary database copy
under `fakeroot`, never the system DB and never as root."*

**Related and more serious:** the plan implies Omarchy protects against partial upgrades.
Verified in `omarchy-update-pacman-guard`, the guard fires only when **both** sync and
sysupgrade flags are present — so it blocks `pacman -Syu` (the *correct* command) and
**permits bare `pacman -Sy`** (the dangerous one), as well as `pacman -S <pkg>`. Do not
claim protection that does not exist; if anything, "user ran a bare `pacman -Sy`" is a
legitimate posture check OmaSafe could add. Documented bypass for maintainers:
`OMARCHY_ALLOW_DIRECT_PACMAN=1`.

### T2. `omarchy update available` fails closed — exit 1 is ambiguous

Verified: the script ends `exit 0` when updates exist and `exit 1` on "Omarchy is up to
date", and it is `set -euo pipefail` depending on `checkupdates` — so **a network failure
also produces exit 1**, indistinguishable from up-to-date. Note the polarity is inverted
from shell convention.

v0.4 M2 says "handle its documented 'exit 1 means up to date' behavior," which is not
enough. Distinguish the three states using stdout content plus an independent connectivity
check, and never report "up to date" on an unverified failure — that is exactly the
"inability to observe" case the check contract already requires you to separate.

### T3. Hook-based update timestamp is less reliable than assumed

`omarchy hook install post-update <script>` is verified (copies to
`~/.config/omarchy/hooks/post-update.d/`, chmod 755), and `post-update` is genuinely invoked
from `omarchy-update:49`. Two gotchas: `omarchy-hook` **swallows hook failures**
(`|| echo "Hook failed: $hook"`), and `omarchy-hook-install` **does not validate the hook
type name** — a typo silently creates a dead directory. So verify the installed hook by
round-trip (install, trigger, confirm the timestamp file changed) rather than trusting a
successful install, and treat a missing timestamp as "unknown," never "never updated."

### T4. The trusted report digest will drift on every OmaSafe upgrade

The state model stores a "trusted report digest," and v0.1 only guarantees determinism
"after timestamps and temporary paths are normalized." If the digest covers tool/schema
version, rule wording, or ordering, upgrading OmaSafe invalidates every baseline and alerts
users about plugins that did not change — precisely the alert fatigue the UX contract exists
to prevent.

Define a canonical digest input — sorted, normalized findings limited to
`{rule_id, capability, path, severity}` — excluding tool version, timestamps, excerpts, and
message strings. Add a test that bumps the tool version and asserts the digest is unchanged.
Separately, define the event for *"a new rule fired on unchanged code"*: that is "analyzer
improved," not "plugin changed."

### T5. "Atomically replace the validated tree" is not achievable as written

v0.2 M4 says: disable plugin, "atomically replace/fast-forward the validated tree," ask the
shell to rescan, restore enabled state. Directory replacement is **not atomic** on Linux —
`rename()` over a non-empty directory fails, there is no portable atomic directory swap, and
the plugin directory is hot-reloaded, so a partially written tree can be loaded.
Symlink-flip is out: `PluginRegistry.qml` rejects symlinked entry points.

Preferred fix, which also matches how 648 of 653 repos are laid out: keep each plugin as a
normal Git checkout and `git fetch` + `git merge --ff-only` to the reviewed commit **while
the plugin is disabled** — no swap needed. Fallback: rename live tree out, rename staged tree
in, same filesystem, plus a startup recovery step. Also confirm what "ask the shell to
rescan" is; `omarchy plugin enable/disable` exist, but if no rescan trigger does, the
supported activation path is a shell restart and the UX must say so.

### T6. Reimplementing the manifest validator will silently diverge

`omarchy plugin validate <plugin-folder>` is verified — note **it requires the folder
argument**; the docs reference it bare in places. Authoritative facts for reimplementation:
`schemaVersion` must be the JSON number `1`; required fields are
`id, name, version, kinds, entryPoints`; the six kinds map to entry points as
`bar:bar`, `bar-widget:barWidget`, `menu:menu`, `overlay:overlay`, `panel:panel`,
`service:service`.

Add a CI canary that runs both validators over the corpus against the current Omarchy
release and **fails the build on disagreement**; record the verified Omarchy version and
surface it in report coverage, so a stale validator degrades coverage instead of passing
silently. The manual currently lags the release (the security page is still titled "The
Omarchy 3 Manual" while this box runs 4.0.0), so treat docs as secondary to the shipped
scripts.

### T7. Two release gates depend on test infrastructure nobody schedules

"Works from a clean Omarchy installation" (README gate 1) and "test clean install, upgrade,
uninstall in an Omarchy VM" (v0.1 M7, v0.5 M3) need a provisioned, snapshot-capable VM
harness. No milestone builds it, and manual VM testing will be skipped by release three. Add
an explicit infra milestone with an owner.

### T8. Name the parser candidates and a kill criterion

v0.1 M1 says "evaluate at least one QML-aware parser," which understates the options:

- **`tree-sitter-qmljs`** (v0.3.1, MIT, Rust bindings on crates.io) — grammar generated from
  Qt's own `qqmljs.g`, error-tolerant, byte/line spans, handles embedded JS. Obvious primary
  choice; it makes the Rust decision safe.
- **`qmllint --json`** — Qt's own analyzer with machine-readable output. Good second signal
  for correctness/imports, but it is a correctness linter, not a capability analyzer, and
  adds a Qt runtime dependency.
- **QQmlSA** — Qt's static-analysis framework with real type resolution; C++ plugin API,
  overkill now, worth knowing if type-aware analysis becomes necessary.

Add a kill criterion: below a stated parse-coverage threshold on the corpus, ship as an
explicitly labelled lexical analyzer with reduced claims rather than sliding there silently.
With the analyzer moved behind the trust release, this stops blocking the first ship.

### T9. Tool availability assumptions are wrong on a stock box

Verified on this machine: **`arch-audit` is not installed** (it is in official `[extra]`, not
AUR — `arch-audit 0.2.0-5`), and **`sbctl` is not installed**. So v0.4 must treat both as
optional, offer installation, and degrade to `incomplete` rather than `pass`. Use `bootctl`
for Secure Boot state instead of assuming `sbctl`.

`arch-audit`'s data source is `security.archlinux.org/all.json`, which covers official-repo
packages only — correct in effect, though not a quotable line from its man page. Given
Omarchy itself pulls AUR packages (`quickshell-git` on this box is from the AUR), the AUR
vulnerability blind spot is real and belongs in the doc as a stated limitation.

### T10. "Signed tags/artifacts where practical" is too weak for this tool

OmaSafe ships as an unsandboxed plugin plus an AUR package — through the exact unreviewed
channel it exists to warn about — and will be the highest-value tampering target in the
ecosystem precisely because users trust its output. Make signed tags, signed artifacts, and a
published self-scan **hard release gates**, with the verification procedure in the README.
Consider a project-controlled binary repo later so AUR is not the sole distribution path.

### T11. VirusTotal is a licensing problem, not just a rate-limit one

Verified: the Public API is **500 requests/day, 4/minute**, and — decisive here — *"must not
be used in commercial products or services"* and *"must not be used in business workflows
that do not contribute new files."* On disclosure, VirusTotal states submitted content is
shared with examining partners, the public community, **and premium customers**.

Deferring VT was already the right call. When it is revisited, note in `later.md` that the
free tier is contractually unavailable for a commercial/business context — so it is a
bring-your-own-paid-key feature or nothing. Hash-lookup only (`GET /files/{sha256}`), never
auto-upload: uploading a plugin containing a developer's config would disclose it to
VirusTotal's premium customer base.

## Coverage gaps worth adding

### G1. Agent/AI config drift belongs in the core roadmap, not "Later"

`~/.claude/settings.json` hooks, MCP server definitions, and installed agent skills are
community code installed by URL, executed unsandboxed, and updated silently — structurally
identical to the plugin threat OmaSafe is built for, already present on every developer
machine here, with nothing watching it. A malicious hook or MCP server entry is a live
persistence and exfiltration vector today.

`later.md` files this under "Agent supply-chain integrations," gated on demand and framed as
*installing* dependency-guard. That framing is backwards: the valuable half is **baselining
and diffing agent configuration**, which reuses the same machinery as plugin drift at near-zero
marginal cost. Promote it to a drift target in the trust release; keep dependency-guard
installation in Later.

### G2. Browser extension inventory

Same shape again: unsandboxed third-party code, auto-updating, high privilege over
credentials and sessions. Inventory plus drift over installed extension IDs and their
requested permissions is cheap and fits the thesis. Worth a line in `later.md` at minimum.

### G3. Firewall check: encode the real default

Verified: Omarchy ships **ufw** (plus `ufw-docker`), default-deny incoming, with **port 22
(ssh) and port 53317 (LocalSend) open by default**. v0.4 M3 says "inspect effective
nftables/ufw policy" — correct approach, but encode those two ports as the expected baseline
or the check will flag a stock install. Also verified: LUKS full-disk encryption is default
and effectively mandatory (opt-out only via Ctrl+C at the format prompt), and Secure Boot
**must be disabled to install** — so the plan's "informational, never a warning" treatment
is right.

### G4. Traceability

One loose end: the **security news feed** (advisories RSS) has no plan home. In substance
v0.4's arch-audit sweep covers it — say so explicitly or drop the bullet. Network snapshot is
partially covered by v0.4 M3's listener inspection; make that mapping explicit too.

## Doc hygiene

- `brainstorm.md` § 6 is still titled **"Additional Suggestions (my additions)"** — stale
  authorial voice from the first draft. Rename to "Supporting Capabilities."
- **Brainstorm and plans overlap substantially** (installers in brainstorm § 4, v0.5, and
  `later.md`; agent integrations in § 5 and `later.md`). Two sources of truth will drift.
  Freeze `brainstorm.md` as context + thesis + decisions; let `plans/` own scope and
  sequencing.
- **The project is not a Git repository.** For a plan whose thesis is provenance and change
  review, version-controlling the docs is table stakes — `git init` and commit before the
  first line of Rust.
- No **sizing, owner, or dates** across ~35 milestones. Coarse t-shirt sizes and one named
  owner per release would have exposed the v0.1 overload immediately.
- No **success metrics**. Suggest three: plugins scanned per week; high-severity FP rate on
  the 653-plugin corpus (target zero); median time from upstream plugin change to user
  review.

## Verified-fact appendix

Confirmed on this machine (Omarchy 4.0.0-1, Quickshell 0.3.0) or from primary sources:

- Plugin model, the six kinds and their entry-point keys, `manifest.json` required fields,
  `schemaVersion: 1`, `~/.config/omarchy/plugins/<id>/`, and unsandboxed execution — the
  latter stated twice in Omarchy's own words: *"Plugins run as unsandboxed code inside
  `omarchy-shell`"* (`shell/README.md:107`) and at install time by `omarchy-plugin-add`.
- Command surface: `omarchy plugin add|clone|disable|enable|list [--json]|remove|update|
  validate <folder>`. `list --json` works and omits path/URL/commit.
- `omarchy update available`: exit 0 = updates found, exit 1 = up to date **or failure**.
- `omarchy hook install post-update <script>` exists; `post-update` invoked from
  `omarchy-update:49`; failures swallowed; hook type unvalidated.
- Quickshell full unrestricted API; no import allowlist; polkit agent and PAM lock services
  in the same process as third-party plugins.
- Registry: 689 listed (653 community / 36 built-in), 356 verified / 297 unverified, 274
  drifted past validated commit; Baseline v4 with non-bypassable blocking rules; independent
  community project.
- Omarchy defaults: LUKS mandatory-by-default; Secure Boot must be disabled to install; ufw
  deny-incoming with 22 and 53317 open.
- `pacman` guard blocks `-Syu` but not bare `-Sy`; `checkupdates` (pacman-contrib) is safe
  but does run `pacman -Sy` under fakeroot against a temp dbpath.
- `arch-audit` in `[extra]`, not installed here; `sbctl` not installed; advisory feed covers
  official repos only.
- VirusTotal Public API: 500/day, 4/min, no commercial use, content shared with partners,
  the public community, and premium customers.
- `tree-sitter-qmljs` 0.3.1 (MIT, from Qt's `qqmljs.g`); `qmllint --json`; QQmlSA.

## Recommended changes, prioritized

| # | Change | Effort |
|---|--------|--------|
| 1 | Swap v0.1 ↔ v0.2: ship the local trust layer first, analyzer second | doc edit, big payoff |
| 2 | Widen analyzer scope to bundled non-QML payloads, or state the coverage limit (F1) | design decision |
| 3 | Add registry `catalog.json` cross-reference (validated vs installed vs upstream commit) | small, highest value/effort |
| 4 | Add the polkit/PAM shared-process threat-model item; rules for those APIs (F2) | doc + design |
| 5 | Correct the Context premise with the real figures; align rule IDs with Baseline v4 | doc edit |
| 6 | Fix the `pacman -Sy` / `checkupdates` contradiction and the guard claim (T1) | doc edit |
| 7 | Handle `omarchy update available` ambiguity and hook-verification round-trip (T2, T3) | small |
| 8 | Define canonical digest inputs + version-bump-stability test (T4) | small, prevents churn |
| 9 | Adopt the 653-plugin corpus with a zero-high-severity CI gate (F7) | 1–2 days |
| 10 | Pick the `--ff-only`-while-disabled update strategy (T5) | design decision |
| 11 | Treat `arch-audit`/`sbctl` as optional; use `bootctl`; encode ufw 22/53317 baseline | small |
| 12 | Promote agent-config drift into the trust release (G1) | doc edit |
| 13 | Signing + self-scan as hard gates; VM harness milestone; `git init`; sizing/owners | small |

Items 1, 2, 3, 4, and 9 change outcomes rather than wording.

---

# Round 2 — disputed items, resolved

Author response received 2026-08-20; ~85–90% accepted, seven partial disagreements. Verified
each against the shipped scripts. Outcome below.

## Conceded to the author

**Exit-code handling for update detection (author point 3).** My connectivity-probe
suggestion was inferior and is withdrawn. Verified: `checkupdates` exits **0** with updates
listed, **2** for successfully-checked-no-updates (`/usr/bin/checkupdates:181`), and **1** on
operational failure (`die 'Cannot fetch updates'`). That contract distinguishes all three
states natively, with no probe. Confirmed too that the native wrapper is the source of the
ambiguity: `omarchy-update-available` calls `checkupdates --nocolor 2>/dev/null … || true`
and `git fetch … || true`, so both paths fail silently into "Omarchy is up to date", exit 1.

**Refinement the author's version needs:** "call `checkupdates` and filter for
`omarchy`/`omarchy-dev`" loses the **dev-checkout branch**. When `$OMARCHY_PATH` is not
`/usr/share/omarchy`, `omarchy-update-available` measures `git rev-list --count HEAD..@{u}`
against the upstream of the active checkout — a signal `checkupdates` structurally cannot
see, because there is no package involved. OmaSafe must reimplement **both** branches
independently: `checkupdates` exit codes for the packaged case, `git rev-list` for the
`omarchy dev link` case, each with its own explicit failure state.

**Three identities instead of one digest (author point 4).** Accepted and better than my
proposal. Source identity (commit + tree digest), analysis fingerprint (normalized rule
results), and policy identity (analyzer + rule-set version) separate the three transitions
cleanly, and the author is right that folding severity into a supposedly stable digest still
churns when a rule's severity changes. Two additions: wire the third case — policy unchanged,
findings changed — into CI as a **determinism canary**, since it is exactly the
nondeterminism assertion the test suite wants anyway; and include the severity table's own
version inside policy identity, so a severity change reads as a policy transition rather
than as plugin drift.

**Release gate wording (author point 2).** Accepted; my formulation was wrong. "Zero
high-severity findings across 653 plugins" would let a genuinely malicious listed plugin
block OmaSafe's own release. Correct gate: zero known high-severity false positives, zero
*untriaged* high-severity findings, true positives allowed and documented. The pinned-corpus
/ PR-subset / nightly-live split is right. Addition: store dispositions as in-repo
expectation files keyed by `{plugin_id, commit, rule_id}` with an explicit
TP/FP/needs-triage verdict, so the gate is mechanically "no needs-triage" and the corpus
doubles as the regression fixture. Pin corpus entries by the SHA the catalog already
publishes in `upstreamObservedCommit`.

**Atomicity, stated correctly (author point 5).** "Not achievable" was too absolute;
"not portable, and unnecessary given a better strategy" is the accurate claim. `renameat2`
with `RENAME_EXCHANGE` does exist and btrfs supports it — relevant since Omarchy's root is
btrfs. The author's six-step sequence is the right one. Both of their additions are
confirmed and were gaps in my review: `omarchy-shell shell rescanPlugins` exists
(`shell.qml:890`, documented as "re-walk plugin dirs and hot-reload plugin code"), so a shell
restart is not normally required; and a `bar`-kind plugin cannot simply be disabled, so the
updater must temporarily fall back to the built-in bar.

**Sizing without dates (author point 7).** Accepted. Suggested substitute for calendar
dates: sequencing gates plus a fixed review cadence, and a stated hours-per-week capacity —
for a side project that number predicts delivery better than any date would.

## Held, with modification

**Plugin kind (author point 1).** Agreed on the main claim: severity belongs to reachable
capability plus evidence, and `kind` is a review-priority prior, not a severity input. A bar
widget is equally long-lived and gets the same unrestricted API.

But one kind does warrant structural treatment, for a reason neither of us raised: a
**`bar`-kind plugin replaces the entire bar**, which is where OmaSafe renders its own alert
badge. A malicious or merely buggy `bar` replacement can suppress OmaSafe's only ambient
signal — the product's core notification path depends on a component a third-party plugin can
displace. Three of the 653 listings are `bar` kind. Implications: OmaSafe must detect that a
non-built-in `bar` plugin is active and must not rely solely on the bar widget for critical
alerts (fall back to a desktop notification), and "replaces the bar" deserves disclosure in
the capability summary independently of severity.

**Agent-config drift (author point 6).** Agreed on sequencing — it does not belong in v0.1,
and my "promote to the trust release" recommendation became wrong the moment the trust
release became v0.1. Withdrawn on timing.

Held on architecture. The claim was not that agent configs are cheap to *collect*; it was
that the drift *machinery* is shared. Baseline storage, the three identities above,
acknowledge/rebaseline, scoped exclusion, and notification dedup are target-independent; what
differs per target is a collector that yields a path set plus a digest. So define the
**drift-target interface in v0.1** — `collect() -> {target_id, paths, digest, classification}` —
even while plugins are the only registered target. That is a design-time cost of near zero
and the difference between "add a collector" later and "retrofit a framework" later.

Two constraints worth fixing now while it is free: the interface contract should be
**digest-only, never store contents**, because agent configs hold API keys and that
requirement should be structural rather than remembered later; and when targets are added,
**MCP server definitions first** — they name executables that run with the agent's
privileges, making them the highest-risk member of that family, not a generic "agent config"
bucket.

## New findings from this round's verification

**The native updater already does fetch + diff + confirm.** `omarchy-plugin-update` runs
`git fetch origin HEAD`, compares `HEAD` against `FETCH_HEAD`, prints the diff (through
`delta` when present), and asks for confirmation. This is the same trap as duplicating the
marketplace's listing-time scanner, one layer down: **"staged update with diff review" is
not on its own a differentiator, because users already have it.** OmaSafe's update path is
only worth building where it adds what the native command cannot — comparison against the
*trusted baseline* rather than against current `HEAD`, registry correlation of the candidate
commit, capability-delta rather than text-delta, and a recorded trust decision. Scope v0.1's
updater to exactly that increment, and consider wrapping `omarchy-plugin-update` rather than
reimplementing the fetch/merge mechanics.

**`catalog.json` becomes a supply-chain dependency of OmaSafe.** Consuming the registry to
label plugins verified/unverified makes the registry an input to OmaSafe's own trust
decisions. Three rules follow: fetch from the GitHub repository at a recorded commit rather
than the rendered site, so the input is itself pinned and auditable; record
`verificationStatus` as a **sourced claim with provenance and retrieval time**, never as a
fact; and — most important — registry data may only ever *add* context, never **downgrade or
suppress** a local finding. Otherwise a compromised or merely mistaken registry entry
silently switches off OmaSafe's own signal.

**Baseline v4 alignment needs a versioned mapping table, not direct ID adoption.** If
OmaSafe emits marketplace rule IDs directly, an upstream rule-set change silently redefines
OmaSafe's findings. Keep OmaSafe-owned IDs, plus a `baseline_v4_equivalent` mapping carrying
the baseline version it was verified against — so divergence surfaces as a stale mapping
rather than as a quietly changed meaning.
