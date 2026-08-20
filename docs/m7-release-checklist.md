# v0.1 M7 Release Checklist

M7 packages, signs, and releases the already-verified v0.1 implementation. It does
not add new detection behavior.

## Required artifacts

- `packaging/arch/PKGBUILD` for the CLI and plugin files.
- Man pages for the supported CLI commands and configuration/state locations.
- Shell completions generated from the authoritative CLI command surface.
- A deterministic self-inventory/provenance report containing source revision,
  toolchain, dependency lockfile identity, supported Omarchy/Quickshell versions,
  and coverage limitations.
- Signed source tag and signed release archive/package, with detached verification

The repository now has a tag-triggered release workflow at
`.github/workflows/release.yml`. It builds the locked `omasafe-cli` workspace binary
for `x86_64-unknown-linux-gnu`, publishes a tarball, and publishes its SHA-256 file.
The workflow is an asset-publishing mechanism, not a replacement for package signing.
  instructions.

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

## Decisions before implementation

1. Package name and split, if any, between the CLI and Omarchy plugin.
2. Installation locations for the binary, man pages, completions, and plugin.
3. Signing key and artifact format accepted for release verification.
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

Neither layout causes `omarchy plugin add` to install `omasafe-cli`. The CLI must be
installed separately through the Arch package/release workflow, and the plugin should
document the missing-CLI state as unavailable rather than downloading or executing a
release asset at runtime.

The milestone should remain open until the signed-artifact and clean-VM gates are
reproduced from a fresh checkout.
