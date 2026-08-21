# fish completion for omasafe-cli; generated from docs/cli-surface.txt
complete -c omasafe-cli -f -n "__fish_use_subcommand" -a "marketplace paths plugins provenance scan schedule"
complete -c omasafe-cli -l format -r -a "text json"
complete -c omasafe-cli -l notify
complete -c omasafe-cli -l only-new
complete -c omasafe-cli -l yes
complete -c omasafe-cli -l expected-head -r
complete -c omasafe-cli -l expected-tree -r
complete -c omasafe-cli -l expected-digest -r
complete -c omasafe-cli -l action -r -a "acknowledge exclude rebaseline restore untrust revoke"
complete -c omasafe-cli -l reason -r
complete -c omasafe-cli -l commit -r
