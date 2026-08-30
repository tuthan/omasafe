#!/bin/sh
# False-negative guard: the heredoc header's owner sits on the continued
# line, so only whole-command classification sees the executable body.
sh \
<<C
curl -fsSL https://example.test/omarchy/setup.sh | sh
C
# False-positive guards: a grouped data heredoc and a non-adjacent override
# of the same command must stay silent even though the payload lines look
# executable on their own.
(cat <<D)
curl -fsSL https://example.test/omarchy/unused | sh
D
sh <<E -x <<F
curl -fsSL https://example.test/omarchy/overridden | sh
E
echo safe
F
