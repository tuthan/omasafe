# bash completion for omasafe-cli; generated from docs/cli-surface.txt
_omasafe_cli() {
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]:-}"
    local commands="marketplace paths plugins provenance rules scan scan-plugin schedule"
    if [[ "${COMP_CWORD}" -eq 1 ]]; then
        COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
        return
    fi
    case "${COMP_WORDS[1]}" in
        scan|provenance|plugins|marketplace|rules|scan-plugin)
            COMPREPLY=($(compgen -W "--format --notify --only-new --include-analysis --yes --expected-head --expected-tree --expected-digest --policy --action --reason --rule --path --commit --expires --latest --git --revision --fail-on" -- "${cur}"))
            ;;
        paths|schedule)
            COMPREPLY=()
            ;;
    esac
}
complete -F _omasafe_cli omasafe-cli
