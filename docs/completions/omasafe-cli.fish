# fish completion for omasafe-cli; generated from docs/cli-surface.txt
complete -c omasafe-cli -f -n "__fish_use_subcommand" -a "marketplace paths plugins provenance rules scan scan-cache scan-plugin schedule"
complete -c omasafe-cli -l format -r -a "text json"
complete -c omasafe-cli -l notify
complete -c omasafe-cli -l only-new
complete -c omasafe-cli -l include-analysis
complete -c omasafe-cli -l refresh
complete -c omasafe-cli -l cached
complete -c omasafe-cli -l yes
complete -c omasafe-cli -l policy -r -a "advisory hardened"
complete -c omasafe-cli -l expected-head -r
complete -c omasafe-cli -l expected-tree -r
complete -c omasafe-cli -l expected-digest -r
complete -c omasafe-cli -l note -r
complete -c omasafe-cli -l action -r -a "acknowledge exclude rebaseline restore untrust revoke suppress reinstate"
complete -c omasafe-cli -l scope -r
complete -c omasafe-cli -l to -r
complete -c omasafe-cli -l reason -r
complete -c omasafe-cli -l rule -r
complete -c omasafe-cli -l commit -r
complete -c omasafe-cli -l expires -r
complete -c omasafe-cli -l path -r
complete -c omasafe-cli -l git -r
complete -c omasafe-cli -l revision -r
complete -c omasafe-cli -l request -r
complete -c omasafe-cli -l marketplace -r
complete -c omasafe-cli -l plugin-id -r
complete -c omasafe-cli -l report-profile -r -a "full review"
complete -c omasafe-cli -l fail-on -r -a "info low medium high critical"
complete -c omasafe-cli -l method -r -a "local-malware-scan remote-hash-reputation manual-binary-review reproducible-build-review signature-review"
complete -c omasafe-cli -l assessment-outcome -r -a "no-known-issue issue-found inconclusive"
complete -c omasafe-cli -l decision -r -a "accepted rejected"
complete -c omasafe-cli -l performed-at -r
complete -c omasafe-cli -l provider -r
complete -c omasafe-cli -l provider-version -r
complete -c omasafe-cli -l report-ref -r
complete -c omasafe-cli -l report-digest -r
complete -c omasafe-cli -l limitation -r
