# ADR 0006: Review-only agent runner

Status: implemented · 2026-09-12 · v0.3.2 and its skill companion

## Context

At CLI commit `97961acdedab8c72e94b33423c69d4d426300235` and skill version
1.4.0, the Python runner has no argv authorization gate. Its report validator
explicitly accepts `plugins enable` output. Plugin text can reach an agent
through evidence, so behavioral instructions alone cannot enforce review-only
operation.

The original combined release plan proposed an operator flag and TTY route in
the runner. A shell-capable agent could imitate that route, while a human can
already invoke the CLI directly. Keep mutation authorization outside the runner.

## Decision

- Build an exact positive command/action/option allowlist before any requested
  CLI child starts. Unknown routes fail closed.
- Permit documented reads and observations with disclosed managed cache/state
  effects. Deny trust/review decisions, enable/update, overrides, executable
  review mutations, schedule/hook mutations, marketplace refresh, and optional
  notification effects in the restricted review route.
- Provide no operator flag, TTY confirmation, or mutation exception. Humans use
  the CLI's existing guarded workflows directly.
- Remove mutation-only output validators, including enable, while retaining
  enforcement-status and other read validators. Test denied mutations with zero
  child invocations.
- Default to a fixed minimal evidence projection. Explicit bounded source
  detail remains untrusted. Do not add a persistent evidence store in v0.3.2.

Initial host acceptance target: OpenCode 1.18.30, a dedicated primary review
agent in a trusted launcher directory, and one typed `omasafe_review` tool.
The effective permission policy denies all other tools, including shell and
delegation. Test interactive and headless use and configuration merging before
claiming enforcement. Other hosts remain unverified; a skill file cannot revoke
an agent's independent shell access. No host configuration is installed silently.

## Consequences and validation

This deliberately breaks the runner's former mutation convenience without
changing direct human CLI operation. Marketplace-ID reviews need a previously
operator-refreshed, reverified catalog. Denials are structured and occur before
process creation; `--yes` and source-derived approval text cannot override them.

v0.3.2 adds no OS containment and no hard fetch-storage guarantee. Scanner
containment is separately proposed in ADR 0007; its feasibility cannot block the
runner fix. Command effects, malformed-argument tests, evidence bounds, and
companion compatibility are frozen for this implementation; host effective
permissions remain a separate acceptance probe on a configured OpenCode host.

The implementation is present in the skill runner, the CLI Git/workspace paths,
and the typed OpenCode bundle. The runner and CLI tests cover zero-spawn mutation
denials, named Git environment canaries, cache and workspace poisoning, hostile
input bounds, and minimal projection. The skill integrity, structural, and
quick-validation checks pass; the plugin companion's floor and QML checks pass.
The adapter test verifies immutable argv and trusted-directory enforcement.

OpenCode 1.18.30 static configuration and agent loading are verified. A model-
level interactive/headless denial probe is not claimed here: this headless host
has no configured model for that test, and its 1.18.30 custom-tool loader hangs at
initialization when a project tool is present. Run those probes on a configured
trusted host before treating the host boundary as independently verified.

The native human updater retains its desktop environment for compatibility but
now removes Git selector/helper, loader, language-startup, and proxy variables
before applying its fixed policy. It is a separate direct-human path; the review
runner and remote scan builders use an allowlisted environment.

## References

- [Detailed v0.3.2 plan](../../../docs-vault/omasafe-Cli/plans/v0.3.2.md)
- [Source review](../../../docs-vault/omasafe-Cli/reviews/2026-09-11-prompt-injection-and-candidate-isolation.md)
- [OpenCode permissions](https://opencode.ai/docs/permissions/)
- [OpenCode custom tools](https://opencode.ai/docs/custom-tools/)

This ADR records the v0.3.2 implementation. It does not claim OS containment,
prompt-injection detection, or host-level model enforcement beyond the checks
listed above; those are separate release or host-verification concerns.
