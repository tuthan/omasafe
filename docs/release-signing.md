# Release signing and verification

M7 uses two complementary signatures:

- The maintainer creates a signed Git source tag with GPG before pushing it.
- GitHub Actions uses Cosign keyless signing with the workflow's OIDC identity
  to produce a Sigstore bundle next to every release tarball.

The release workflow requires `id-token: write` only for the build job. It does
not store a long-lived signing key in GitHub secrets. The `.sigstore.json` file
is a detached verification bundle; the `.sha256` file is an additional
integrity check, not a signature.

## Maintainer release sequence

From the exact clean commit that is ready to release:

```sh
git tag -s v0.1.2 -m 'OmaSafe v0.1.2'
git tag -v v0.1.2
git push origin v0.1.2
```

The tag starts `.github/workflows/release.yml`. It publishes:

```text
omasafe-cli-v0.1.2-x86_64-linux.tar.gz
omasafe-cli-v0.1.2-x86_64-linux.tar.gz.sha256
omasafe-cli-v0.1.2-x86_64-linux.tar.gz.sigstore.json
```

The `x86_64-linux` label is the human-facing platform name. The binary is
built for the `x86_64-unknown-linux-gnu` Rust target (generic Linux GNU ABI);
the archive name drops the `unknown` vendor field for readability.

## End-user verification

Install Cosign, download the archive and its Sigstore bundle from the same
GitHub release, then verify the bundle before unpacking. On Arch Linux:

```sh
sudo pacman -S --needed cosign
```

```sh
cosign verify-blob \
  --bundle omasafe-cli-v0.1.2-x86_64-linux.tar.gz.sigstore.json \
  --certificate-identity-regexp \
    '^https://github.com/tuthan/omasafe/.github/workflows/release.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  omasafe-cli-v0.1.2-x86_64-linux.tar.gz
test "$(sha256sum omasafe-cli-v0.1.2-x86_64-linux.tar.gz | awk '{print $1}')" = \
  "$(awk 'NF { print $1; exit }' omasafe-cli-v0.1.2-x86_64-linux.tar.gz.sha256)"
tar -xzf omasafe-cli-v0.1.2-x86_64-linux.tar.gz
```

The repository also provides a user-level installer for x86_64 Linux. It
downloads the archive, bundle, and digest, verifies the Sigstore identity before
unpacking, then installs the binary under `~/.local/bin`:

```sh
# Install the latest signed release
curl --fail --proto '=https' --tlsv1.2 --location \
  https://raw.githubusercontent.com/tuthan/omasafe/d4fb76d/scripts/install-cli.sh \
  | bash -s -- --version latest

# Or install an exact release
curl --fail --proto '=https' --tlsv1.2 --location \
  https://raw.githubusercontent.com/tuthan/omasafe/d4fb76d/scripts/install-cli.sh \
  | bash -s -- --version v0.1.2
```

The raw-script URL is pinned to the commit that introduced the installer;
`--version latest` selects the current signed release, while `v0.1.2` selects an
exact signed archive. From a repository checkout, run
`./scripts/install-cli.sh --version latest` or
`./scripts/install-cli.sh --version v0.1.2` instead. Use `--prefix DIR` to
choose another installation root. The installer does not require root
privileges.

The identity and issuer restrictions are intentional: they require the
signature to originate from the OmaSafe release workflow in GitHub Actions.
The source tag remains separately verifiable with `git tag -v` using the
maintainer's published GPG key.
