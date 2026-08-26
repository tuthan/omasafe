#!/usr/bin/env bash
# Release gate for every OmaSafe version. Implements the release checklist
# verbatim: both test configurations, lint/format gates, generated-asset
# consistency, the determinism canary, corpus-tooling self-tests, a bounded
# pinned-corpus sample run, native-validator parity, and the self-scan.
# Produces the three evidence reports under release-reports/.
#
# Usage:
#   scripts/release-gate.sh [--sample N] [--skip-network]
# Network steps (corpus sample + parity) are skipped with --skip-network;
# a real release MUST run them.
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root_dir"

sample=12
skip_network=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sample) sample="${2:?--sample requires a number}"; shift 2 ;;
    --skip-network) skip_network=true; shift ;;
    *) printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

step() { printf '\n=== %s ===\n' "$1"; }

mkdir -p release-reports

step "format"
cargo fmt --all -- --check

for features in "" "--no-default-features"; do
  step "clippy ${features:-[default]}"
  # shellcheck disable=SC2086
  cargo clippy --workspace --all-targets $features -- -D warnings

  step "tests ${features:-[default]}"
  # shellcheck disable=SC2086
  cargo test --workspace $features
done

step "generated assets are current"
./scripts/generate-cli-assets.sh --check

step "determinism canary"
./scripts/determinism-canary.sh

step "corpus tooling self-tests"
python3 scripts/test_corpus_tooling.py

if [[ $skip_network == false ]]; then
  cache="${OMASAFE_RELEASE_CACHE:-$root_dir/release-reports/corpus-cache}"
  mkdir -p "$cache"
  step "pinned-corpus sample (n=$sample)"
  python3 scripts/run-corpus.py \
    --manifest fixtures/corpus/manifest.json \
    --sample "$sample" \
    --cache "$cache" \
    --output release-reports/corpus-sample.json

  step "native validator parity (n=$sample)"
  python3 scripts/validator-parity.py \
    --manifest fixtures/corpus/manifest.json \
    --cache "$cache" \
    --sample "$sample" \
    --output release-reports/validator-parity.json
else
  printf '\nSKIPPED network steps (--skip-network): corpus sample and parity.\n'
  printf 'A real release must run them; see scripts/run-corpus.py and scripts/validator-parity.py.\n'
fi

step "self-scan of OmaSafe's own source"
cargo build --quiet -p omasafe-cli
./target/debug/omasafe-cli scan-plugin --path . --format json > release-reports/self-scan.json

step "provenance"
./target/debug/omasafe-cli provenance --format json > release-reports/provenance.json

printf '\nRelease gate passed. Evidence reports:\n'
ls -la release-reports/
printf '\nRemaining manual steps before tagging:\n'
printf '  1. Review release-reports/self-scan.json findings (no unreviewed high severity).\n'
printf '  2. Confirm corpus-sample.json has zero incomplete repositories or an explicit note.\n'
printf '  3. Confirm validator-parity.json shows zero disagreements on the recorded version.\n'
printf '  4. Sign the tag (git tag -s) and cut the tag; the workflow signs artifacts via Sigstore.\n'
