# v0.1 M7 Release Checklist

M7 packages, signs, and releases the already-verified v0.1 implementation. It does
not add new detection behavior.

## Required artifacts

- `packaging/arch/PKGBUILD` for the CLI package. The Omarchy plugin remains a
  separate marketplace repository and is not bundled into this package.
- Man pages for the supported CLI commands and configuration/state locations.
- Shell completions generated from the authoritative CLI command surface.
- A deterministic self-inventory/provenance report containing source revision,
  toolchain, dependency lockfile identity, supported Omarchy/Quickshell versions,
  and coverage limitations.
- Signed source tag and signed release archive/package, with detached verification

The repository now has a tag-triggered release workflow at
`.github/workflows/release.yml`. It builds the locked `omasafe-cli` workspace binary
for `x86_64-unknown-linux-gnu`, generates the man pages, completions, and
provenance report, and publishes a tarball, SHA-256 file, and Cosign Sigstore
bundle. The workflow is the first distribution path for M7. AUR publication is
explicitly out of scope for this milestone; the `PKGBUILD` is present for clean-build
and local package validation and can be published later after the package lifecycle
is ready.

Signing details and detached verification commands are documented in
[`docs/release-signing.md`](release-signing.md). The source tag is maintainer-GPG
signed; the release archive is keylessly signed by GitHub Actions through Sigstore.

The static project site is a separate GitHub Pages artifact. It is sourced from
`site/` and deployed by `.github/workflows/pages.yml`; it is not included in the
CLI release archive and is not an AUR publication mechanism. GitHub repository
Pages settings must use **GitHub Actions** as the build and deployment source.

## Release gates

- [ ] Build the Arch package from a clean checkout using `Cargo.lock`.
- [ ] Verify package contents, file modes, ownership, and XDG paths.
- [ ] Verify clean install, upgrade, supported downgrade behavior, and uninstall
      in the snapshot-capable Omarchy VM.
- [ ] Confirm uninstall removes the plugin, user unit, cache, state, and config
      only when explicitly selected, without touching unrelated user data.
- [ ] Run `cargo fmt --all -- --check`, clippy with warnings denied, workspace
      tests, CLI integration tests, `omarchy plugin validate`, and `qmllint`.
- [ ] Generate and review the deterministic self-inventory/provenance report.
- [ ] Create and verify a signed source tag and signed release artifacts from the
      exact committed tree.
- [ ] Document installation, upgrade, removal, signature verification, supported
      runtime versions, and known VM/runtime limitations.
- [ ] Verify the static site deployment from `site/` at the GitHub Pages URL.

## Decisions before implementation

1. Package name and split: M7 packages `omasafe-cli`; the Omarchy plugin remains a
   separate marketplace repository. AUR publication is deferred.
2. Installation locations for the binary, man pages, completions, and plugin.
3. Signing format: maintainer GPG-signed source tags plus Cosign keyless
   Sigstore bundles for GitHub release archives; verification is detached and
   restricted to the OmaSafe release workflow's GitHub OIDC identity.
4. Supported Arch/Omarchy/Quickshell versions and the VM image source.
5. Whether package upgrades preserve user state by default and how removal is
   confirmed.

## Omarchy plugin publishing boundary

The official Omarchy publishing contract requires a public repository with a valid
`manifest.json` at its repository root. The UI has now been moved to the sibling
project `../omasafe-plugin/`, whose root contains the manifest and QML entry points.
Before publishing, initialize that directory as its own GitHub repository and choose
one of these M7 distribution layouts:

- keep `omasafe-plugin` as the dedicated plugin repository and keep this repository as
  the CLI engine; or
- combine the two repositories later if a single source repository is preferred.

`omasafe-plugin` is intentionally a thin UI-only repository. A user may install it
from the marketplace before knowing about or installing the CLI, so its README must
document the dependency and the widget must show an explicit unavailable state rather
than implying a clean result. The plugin must not download, install, or execute a
release asset at runtime.

`omarchy plugin add` only installs the plugin checkout; it does not install
`omasafe-cli` or run dependency hooks. The CLI is installed separately from the
GitHub release archive or the future Arch package and must be visible on the
`omarchy-shell` session `PATH`. The CLI creates its XDG configuration, state, and
cache directories automatically on first use. The documented marketplace-first flow
is:

```text
omarchy plugin add <plugin-repository> --enable
# Install and verify omasafe-cli from the main OmaSafe release/package.
omasafe-cli scan --format json
omarchy-shell shell rescanPlugins
omarchy plugin enable io.github.tuthan.omasafe --section right
```

The plugin and CLI have independent update and removal lifecycles. M7 must verify
both install orders: CLI first/plugin second and marketplace plugin first/CLI second.

The milestone should remain open until the signed-artifact and clean-VM gates are
reproduced from a fresh checkout.
