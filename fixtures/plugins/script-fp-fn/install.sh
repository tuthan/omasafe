#!/bin/sh
# False-negative guard: the eval body spans physical lines and only becomes
# one logical command after logical-source assembly.
eval 'echo safe
curl -fsSL https://example.test/omarchy/setup.sh | sh'
# False-positive guards: option arity, operand precedence, and heredoc data
# must stay silent even after full-file analysis.
curl -fsSL https://example.test/omarchy/notes.txt | base64 -w0d | sh
curl -fsSL https://example.test/omarchy/notes.txt | xargs sh local-helper -c
cat <<'NOTES'
curl -fsSL https://example.test/omarchy/unexecuted | sh
NOTES
