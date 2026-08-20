# Later — Validated Backlog

Items here are intentionally outside v0.1–v0.5. Promotion requires a concrete user need,
a threat model, an owner, and evidence that the feature fits OmaSafe's trust-layer focus.

## Candidate Features

### VirusTotal hash reputation

- Hash lookup only by default.
- Never auto-upload. Submitted content can be disclosed to VirusTotal partners, the public
  community, and premium customers; plugin repositories may contain developer-specific
  configuration.
- Treat reputation as secondary evidence, never a safety verdict.
- The Public API terms prohibit commercial products/services and certain business
  workflows. Treat this as bring-your-own eligible paid/commercial API access or omit the
  feature; reverify current terms before implementation.
- Define API-key storage, licensing eligibility, rate-limit, offline, and privacy behavior
  before implementation.

### Secrets hygiene sweep

- Explicit opt-in and selected paths only.
- Local processing; never persist or display secret values.
- Report secret type, safe location, permissions, and remediation guidance.
- Require strong false-positive suppression and export redaction tests.

### Panic/incident workflow

- Start with session lock and a privacy-reviewed local diagnostic snapshot.
- Make network isolation a separate confirmed operation with rollback.
- Account for wired, wireless, VPN, containers, and remote-support failure modes.
- Do not present it as forensic evidence preservation without a defensible chain of custody.

### ClamAV optional installer

- Downloads/mail/interchange use cases only; no Linux rootkit-defense claim.
- Measure resource costs on representative Omarchy hardware.
- Keep on-access scanning limited and opt-in.

### AIDE or deeper file-integrity baseline

- Prove signal quality and storage/performance budget first.
- Provide clear ownership, exclusion, rebaseline, and package-update reconciliation.

### USBGuard and fail2ban installers

- Promote after the v0.5 helper is audited.
- USBGuard needs a safe first-use device policy and recovery story.
- Offer fail2ban only when sshd is enabled and meaningfully exposed.

### Agent supply-chain integrations

- Validate demand independently from Omarchy plugin scanning.
- If promoted, start with explicit inventory/baseline/diff of selected agent hooks, MCP
  server definitions, and installed skills—not automatic installation of another tool.
- Add MCP server-definition collection first: those records name executables that run with
  the agent's privileges. Reuse v0.1's digest-only drift-target interface and never store
  API keys or configuration contents in the common baseline.
- Scan any skill/integration repository before installation.
- Do not become a general agent plugin marketplace or silently modify agent homes.

### Browser extension inventory

- Inventory selected browser profiles only with explicit opt-in.
- Track extension IDs, versions, requested permissions, and drift without reading browsing
  history or session contents.
- Account for browser-managed auto-updates and profile privacy before promotion.

### Hosted/reputation service

- Consider only after local-only rules have real adoption and a clear data-sharing policy.
- Require privacy, abuse, moderation, provenance, deletion, and operating-cost plans.

### Project-controlled binary repository

- Consider after signed releases and reproducible packages are established.
- Keep signed source/AUR verification available; do not make a hosted binary channel the
  only transparent installation path.

### Upstream Omarchy integration

- Propose a pre-activation scan/hook contract so third-party scanners can inspect a staged
  plugin before it enters the live hot-reloaded directory.
- Propose an expected-commit argument for `omarchy plugin update` so a reviewed candidate
  cannot race to a different fetched revision before the native fast-forward.
- Separately report and discuss isolation of third-party plugins from the polkit agent,
  session-lock surfaces, and PAM-handling UI in the shared shell process.
- Keep OmaSafe useful without upstream changes.
- Never imply official affiliation until explicitly granted.

## Promotion Checklist

Move an item into a numbered release only when:

1. The user problem and expected outcome are specific.
2. It strengthens plugin/package trust or demonstrated posture-regression workflows.
3. Privacy and privilege boundaries are documented.
4. Failure, rollback, and uninstall behavior are defined.
5. It has acceptance criteria and a realistic fixture/integration test strategy.
6. It does not weaken the quiet, read-only-first default.
