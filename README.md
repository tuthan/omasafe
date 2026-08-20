# OmaSafe

OmaSafe is a local trust and drift-review tool for Omarchy community plugins.
It reports installed source identity, marketplace context, and changes since a
user-established baseline. It does not declare plugins safe or malicious.

## Status

Implementation follows the versioned plans in [`docs/plans/`](docs/plans/).
Milestone progress and verification results are recorded in
[`docs/progress.md`](docs/progress.md). Each milestone is committed before the
next milestone begins.

Current milestone: **v0.1 M2 complete**. The CLI collects filesystem inventory,
records Git provenance, and correlates plugins with a pinned marketplace
catalog.

## Development

Requirements: Rust and Cargo.

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo run -p omasafe-cli -- --version
cargo run -p omasafe-cli -- plugins inventory --format json
cargo run -p omasafe-cli -- plugins inventory --format json \
  --catalog fixtures/marketplace/catalog.json --catalog-commit FIXTURE_COMMIT
```

The CLI is the engine. The future Omarchy bar-widget is a thin QML interface
over bounded CLI commands. Runtime state uses XDG paths:

- Configuration: `${XDG_CONFIG_HOME:-~/.config}/omasafe`
- State: `${XDG_STATE_HOME:-~/.local/state}/omasafe`
- Cache: `${XDG_CACHE_HOME:-~/.cache}/omasafe`

## Scope

The v0.1 release delivers installed plugin inventory, marketplace correlation,
source identity, trust baselines, diffs, and drift notifications. Static
capability analysis is deliberately deferred to v0.2.

See [`docs/brainstorm.md`](docs/brainstorm.md) for the product thesis and
[`docs/plans/README.md`](docs/plans/README.md) for the release sequence.
