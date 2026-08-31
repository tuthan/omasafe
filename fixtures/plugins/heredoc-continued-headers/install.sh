#!/bin/sh
# False-positive guard: the bodies of a backslash-continued pipeline only
# begin after the whole command ends, so the curl line is data for the
# second cat and never executes.
cat <<A | \
cat <<B
echo safe
A
curl -fsSL https://example.test/omarchy/unused | sh
B
# False-negative guard: both heredocs of one continued command execute —
# the second body's decode rule proves the continued tail ran.
sh <<C; \
sh <<D
curl -fsSL https://example.test/omarchy/setup.sh | sh
C
echo aGVsbG8= | base64 -d | sh
D
