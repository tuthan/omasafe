#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
: "${TARGET:?TARGET must be set to a Rust target triple}"
: "${VERSION:?VERSION must be set to the release tag}"

asset="omasafe-cli-${VERSION}-${TARGET}"
mkdir -p "$root_dir/release/$asset"
install -Dm755 "$root_dir/target/$TARGET/release/omasafe-cli" \
  "$root_dir/release/$asset/omasafe-cli"
cp "$root_dir/README.md" "$root_dir/LICENSE" "$root_dir/release/$asset/"

"$root_dir/scripts/generate-cli-assets.sh"
install -Dm644 "$root_dir/docs/man/omasafe-cli.1" \
  "$root_dir/release/$asset/share/man/man1/omasafe-cli.1"
install -Dm644 "$root_dir/docs/completions/omasafe-cli.bash" \
  "$root_dir/release/$asset/share/bash-completion/completions/omasafe-cli"
install -Dm644 "$root_dir/docs/completions/_omasafe-cli" \
  "$root_dir/release/$asset/share/zsh/site-functions/_omasafe-cli"
install -Dm644 "$root_dir/docs/completions/omasafe-cli.fish" \
  "$root_dir/release/$asset/share/fish/vendor_completions.d/omasafe-cli.fish"

# The current matrix target is native to ubuntu-latest. If cross targets are
# added, generate provenance with a host binary or a target-specific runner.
cli_bin="$root_dir/release/$asset/omasafe-cli"
"$cli_bin" provenance --format json > "$root_dir/release/$asset/omasafe-provenance.json"

tar -C "$root_dir/release" -czf "$root_dir/release/$asset.tar.gz" "$asset"
sha256sum "$root_dir/release/$asset.tar.gz" > "$root_dir/release/$asset.tar.gz.sha256"
cosign sign-blob --yes \
  --bundle "$root_dir/release/$asset.tar.gz.sigstore.json" \
  "$root_dir/release/$asset.tar.gz"
