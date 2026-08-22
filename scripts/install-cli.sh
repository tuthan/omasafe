#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: install-cli.sh [OPTIONS]

Download, verify, and install the OmaSafe CLI release for x86_64 Linux.

Options:
  --version VERSION  Release tag to install (default: latest)
  --prefix DIR       Install under DIR/bin (default: ~/.local)
  --repo OWNER/REPO  GitHub repository (default: tuthan/omasafe)
  -h, --help         Show this help

The archive is verified with its Sigstore bundle and SHA-256 digest before it
is unpacked or installed. Cosign, curl, sha256sum, and tar are required.
EOF
}

repo="tuthan/omasafe"
version="latest"
prefix="${OMASAFE_INSTALL_PREFIX:-${HOME}/.local}"
cosign_bin="${COSIGN_BIN:-cosign}"

while (($# > 0)); do
  case "$1" in
    --version)
      (($# >= 2)) || { printf '%s\n' '--version requires a value' >&2; exit 2; }
      version=$2
      shift 2
      ;;
    --prefix)
      (($# >= 2)) || { printf '%s\n' '--prefix requires a value' >&2; exit 2; }
      prefix=$2
      shift 2
      ;;
    --repo)
      (($# >= 2)) || { printf '%s\n' '--repo requires a value' >&2; exit 2; }
      repo=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$(uname -s):$(uname -m)" in
  Linux:x86_64|Linux:amd64)
    platform='x86_64-linux'
    ;;
  *)
    printf 'unsupported host: %s %s (only x86_64 Linux is currently released)\n' \
      "$(uname -s)" "$(uname -m)" >&2
    exit 1
    ;;
esac

[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  printf 'invalid GitHub repository: %s\n' "$repo" >&2
  exit 2
}

command -v curl >/dev/null || { printf '%s\n' 'missing required command: curl' >&2; exit 1; }
if ! command -v "$cosign_bin" >/dev/null 2>&1; then
  printf 'missing required command: %s\n' "$cosign_bin" >&2
  if command -v pacman >/dev/null 2>&1; then
    printf '%s\n' 'On Arch Linux, install it with: sudo pacman -S --needed cosign' >&2
  else
    printf '%s\n' 'Install Cosign from https://docs.sigstore.dev/cosign/system_config/installation/' >&2
  fi
  exit 1
fi
command -v sha256sum >/dev/null || { printf '%s\n' 'missing required command: sha256sum' >&2; exit 1; }
command -v tar >/dev/null || { printf '%s\n' 'missing required command: tar' >&2; exit 1; }

if [[ "$version" == latest ]]; then
  version=$(curl -fsSL \
    -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/$repo/releases/latest" |
    sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
fi

[[ "$version" =~ ^v[0-9]+([.][0-9]+)*([.-][0-9A-Za-z.-]+)?$ ]] || {
  printf 'invalid release version: %s\n' "$version" >&2
  exit 2
}

asset="omasafe-cli-${version}-${platform}"
base_url="https://github.com/$repo/releases/download/$version/$asset"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

archive="$tmp_dir/$asset.tar.gz"
checksum="$tmp_dir/$asset.tar.gz.sha256"
bundle="$tmp_dir/$asset.tar.gz.sigstore.json"

printf 'Downloading %s from %s\n' "$asset" "$repo"
curl -fL --retry 3 --retry-delay 1 -o "$archive" "${base_url}.tar.gz"
curl -fL --retry 3 --retry-delay 1 -o "$checksum" "${base_url}.tar.gz.sha256"
curl -fL --retry 3 --retry-delay 1 -o "$bundle" "${base_url}.tar.gz.sigstore.json"

repo_identity_re=${repo//./\\.}
version_identity_re=${version//./\\.}
"$cosign_bin" verify-blob \
  --bundle "$bundle" \
  --certificate-identity-regexp "^https://github\\.com/${repo_identity_re}/\\.github/workflows/release\\.yml@refs/tags/${version_identity_re}$" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "$archive"

expected_digest=$(awk 'NF { print $1; exit }' "$checksum")
[[ "$expected_digest" =~ ^[[:xdigit:]]{64}$ ]] || {
  printf 'invalid SHA-256 sidecar: %s\n' "$checksum" >&2
  exit 1
}
actual_digest=$(sha256sum "$archive" | awk '{print $1}')
[[ "$actual_digest" == "$expected_digest" ]] || {
  printf 'SHA-256 mismatch for %s\n' "$archive" >&2
  exit 1
}

extract_dir="$tmp_dir/extract"
mkdir -p "$extract_dir"
tar -xzf "$archive" -C "$extract_dir"
binary="$extract_dir/$asset/omasafe-cli"
[[ -f "$binary" && ! -L "$binary" ]] || {
  printf '%s\n' 'release archive does not contain a regular omasafe-cli binary' >&2
  exit 1
}

install -Dm755 "$binary" "$prefix/bin/omasafe-cli"
printf 'Installed omasafe-cli to %s\n' "$prefix/bin/omasafe-cli"
