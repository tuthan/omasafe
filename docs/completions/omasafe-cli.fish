# fish completion for omasafe-cli; generated from docs/cli-surface.txt
complete -c omasafe-cli -f -n "__fish_use_subcommand" -a "marketplace paths plugins provenance rules scan scan-plugin schedule"
complete -c omasafe-cli -l format -r -a "text json"
complete -c omasafe-cli -l notify
complete -c omasafe-cli -l only-new
complete -c omasafe-cli -l include-analysis
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
complete -c omasafe-cli -l fail-on -r -a "info low medium high critical"
