# OpenCode 1.18.30 review host

This directory contains the named OpenCode integration for the v0.3.2
review-only runner. It is a configuration bundle, not a request to modify a
user's existing OpenCode installation. Install it only into a trusted global
configuration directory, outside any candidate repository, and keep the
launcher directory owner-private.

The `omasafe-review` primary agent denies every tool by default and allows only
`omasafe_review`. The custom tool accepts one typed selector and constructs the
complete `scan-plugin --report-profile review --format json` argv internally.
It starts the fixed Python runner with `shell: false`, a fixed trusted working
directory, an allowlisted environment, and no stderr transport. The runner's
default projection is minimal; `boundedEvidence` only opts into bounded,
untrusted detail.

From this source checkout, start the trusted bundle with:

```sh
./integrations/opencode/launch.sh
```

The launcher resolves the built CLI and the sibling skill runner, validates
that each is an owner-controlled regular file, and runs OpenCode from this
bundle directory. Build the CLI first with `cargo build -p omasafe-cli`, or
provide installed paths through `OMASAFE_REVIEW_CLI` and
`OMASAFE_REVIEW_RUNNER`. Run the script with `bash` if your shell has a `cd`
wrapper such as zoxide.

The launcher must set these host-controlled values before starting OpenCode:

```sh
export OMASAFE_REVIEW_CLI=/usr/bin/omasafe-cli
export OMASAFE_REVIEW_RUNNER=/usr/local/libexec/omasafe-plugin-review/run-omasafe.py
# Use the resolved regular interpreter path; /usr/bin/python3 may be a symlink.
export OMASAFE_REVIEW_PYTHON="$(readlink -f /usr/bin/python3)"
export OMASAFE_REVIEW_CWD=/usr/local/libexec/omasafe-plugin-review
cd "$OMASAFE_REVIEW_CWD"
exec opencode --agent omasafe-review "$@"
```

That example is for a package installation which has provisioned
`/usr/local/libexec/omasafe-plugin-review`; it will fail with “Directory not
found” until that directory and its runner are installed. Do not substitute a
candidate repository for the trusted working directory.

The values are never exposed as tool arguments. The launcher should be the
only way to start this agent; do not start it from a candidate checkout, and do
not allow the candidate's OpenCode config, plugins, skills, or `AGENTS.md` to
participate. Keep the existing OpenCode config unchanged unless an operator
explicitly installs this bundle.

For installation, copy this entire directory (including `.opencode/agent` and
`.opencode/tools`) into a new owner-private launcher directory outside all
candidate repositories, then run OpenCode from that directory. Do not merge
the files into a candidate's project configuration. The installed OpenCode
release must be exactly `1.18.30` for the v0.3.2 acceptance record; other
versions need a new host verification. Run `verify.sh`, then run
`opencode debug config` and `opencode debug agent omasafe-review` from the
trusted directory and record the merged permission snapshot. A configuration
dump alone is not evidence that a model cannot reach alternate tools: exercise
the interactive and `opencode run --agent omasafe-review` headless sessions
with actual attempts to use shell, read/edit, web, delegation, and arbitrary
skill tools, and confirm the host denies each one. Explicit `deny` rules must
remain effective with `--auto`.

The typed adapter can be exercised without a model or network access. From the
repository root, run `node --experimental-strip-types
integrations/opencode/test.mjs`; it uses temporary trusted binaries and checks
the generated immutable Git argv, bounded-evidence flag, URL validation, and
trusted-directory check.

The bundle's host verification has two parts. `verify.sh` checks the pinned
OpenCode version, trusted agent configuration, and static adapter invariants;
`test.mjs` exercises the adapter with fake binaries. A model-level interactive or
headless denial probe must still run on a configured host with the exact pinned
release. In the current headless container, OpenCode 1.18.30 recognizes the
agent but hangs during project custom-tool loading, so `verify.sh` intentionally
does not claim that probe. Do not treat the static permission snapshot or the
skill instructions as proof that an arbitrary shell-capable host cannot reach
other tools.
