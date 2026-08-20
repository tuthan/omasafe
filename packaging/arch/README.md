# Arch packaging preparation

This directory is reserved for the M7 Arch package. The package must install the
`omasafe-cli` binary, the OmaSafe Omarchy plugin, man pages, and shell completions
without creating a persistent service unless the user explicitly runs
`omasafe-cli schedule install`.

The eventual `PKGBUILD` must build from the committed source tree and `Cargo.lock`,
keep package contents deterministic, preserve the documented XDG state/cache behavior,
and include a `package()`-time file manifest suitable for the M7 self-inventory report.

Do not add a placeholder package that claims to be installable; add `PKGBUILD` only
when the clean-build and VM install/uninstall workflow is executable.
